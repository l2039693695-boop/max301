package router

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func mustCIDR(t *testing.T, s string) ipRange {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := toRange(n)
	if !ok {
		t.Fatalf("toRange(%s) failed", s)
	}
	return r
}

func TestMatch(t *testing.T) {
	m := NewCNIPMatcher([]ipRange{
		mustCIDR(t, "1.0.1.0/24"),
		mustCIDR(t, "14.0.0.0/8"),
		mustCIDR(t, "223.255.252.0/23"),
	})

	tests := []struct {
		ip   string
		want bool
	}{
		{"1.0.1.0", true},   // first address of a block
		{"1.0.1.255", true}, // last address
		{"1.0.0.255", false},
		{"1.0.2.0", false},
		{"14.0.0.1", true},
		{"14.255.255.255", true},
		{"15.0.0.0", false},
		{"223.255.253.255", true},
		{"223.255.254.0", false},
		{"8.8.8.8", false},
		{"0.0.0.0", false},
		{"255.255.255.255", false},
	}
	for _, tc := range tests {
		if got := m.Match(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("Match(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestMatchIPv6IsNeverChinese(t *testing.T) {
	m := NewCNIPMatcher([]ipRange{mustCIDR(t, "1.0.1.0/24")})
	if m.Match(net.ParseIP("2001:db8::1")) {
		t.Error("Match returned true for an IPv6 address")
	}
}

// Adjacent and overlapping prefixes should collapse, keeping lookups cheap.
func TestRangesAreMerged(t *testing.T) {
	m := NewCNIPMatcher([]ipRange{
		mustCIDR(t, "10.0.0.0/24"),
		mustCIDR(t, "10.0.1.0/24"), // adjacent to the one above
		mustCIDR(t, "10.0.2.0/24"), // and to that one
	})
	if m.Len() != 1 {
		t.Errorf("Len = %d, want 1 after merging three adjacent blocks", m.Len())
	}
	for _, ip := range []string{"10.0.0.0", "10.0.1.128", "10.0.2.255"} {
		if !m.Match(net.ParseIP(ip)) {
			t.Errorf("Match(%s) = false after merge", ip)
		}
	}
	if m.Match(net.ParseIP("10.0.3.0")) {
		t.Error("merge extended past the end of the last block")
	}
}

func TestOverlappingRangesMerge(t *testing.T) {
	m := NewCNIPMatcher([]ipRange{
		mustCIDR(t, "10.0.0.0/16"),
		mustCIDR(t, "10.0.5.0/24"), // fully inside the one above
	})
	if m.Len() != 1 {
		t.Errorf("Len = %d, want 1", m.Len())
	}
	if !m.Match(net.ParseIP("10.0.5.5")) {
		t.Error("Match = false for an address in the enclosed block")
	}
	if !m.Match(net.ParseIP("10.0.200.1")) {
		t.Error("Match = false for an address in the enclosing block")
	}
}

// CIDRs feeds the Windows route table, so every address in a range must be
// covered and nothing outside it may be.
func TestCIDRsCoverRangeExactly(t *testing.T) {
	cases := []ipRange{
		mustCIDR(t, "1.0.1.0/24"),
		mustCIDR(t, "14.0.0.0/8"),
		{lo: 0x0A000001, hi: 0x0A000005}, // 10.0.0.1 - 10.0.0.5, unaligned
		{lo: 0x0A0000FF, hi: 0x0A000101}, // crosses a /24 boundary
		{lo: 0x00000000, hi: 0x00000000}, // single address at zero
		{lo: 0xFFFFFFFF, hi: 0xFFFFFFFF}, // single address at the top
	}

	for _, r := range cases {
		m := &CNIPMatcher{ranges: []ipRange{r}}
		cidrs := m.CIDRs()
		if len(cidrs) == 0 {
			t.Fatalf("range %#x-%#x produced no CIDRs", r.lo, r.hi)
		}

		covered := map[uint32]bool{}
		for _, c := range cidrs {
			cr, ok := toRange(c)
			if !ok {
				t.Fatalf("CIDRs returned a non-IPv4 prefix %v", c)
			}
			if cr.lo < r.lo || cr.hi > r.hi {
				t.Errorf("prefix %v (%#x-%#x) escapes the range %#x-%#x",
					c, cr.lo, cr.hi, r.lo, r.hi)
			}
			for a := uint64(cr.lo); a <= uint64(cr.hi); a++ {
				covered[uint32(a)] = true
			}
		}
		for a := uint64(r.lo); a <= uint64(r.hi); a++ {
			if !covered[uint32(a)] {
				t.Fatalf("address %#x in range %#x-%#x was not covered", a, r.lo, r.hi)
			}
		}
	}
}

// An aligned block must come back as exactly one prefix, not many.
func TestCIDRsAreMinimalForAlignedBlocks(t *testing.T) {
	for _, cidr := range []string{"1.0.1.0/24", "14.0.0.0/8", "223.255.252.0/23"} {
		m := &CNIPMatcher{ranges: []ipRange{mustCIDR(t, cidr)}}
		if got := m.CIDRs(); len(got) != 1 {
			t.Errorf("%s produced %d prefixes, want 1", cidr, len(got))
		} else if got[0].String() != cidr {
			t.Errorf("%s came back as %s", cidr, got[0])
		}
	}
}

func TestLoadCNIPList(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chnroute.txt")
	content := `# comment
1.0.1.0/24

14.0.0.0/8
2001:db8::/32
223.255.252.0/23
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	m, err := LoadCNIPList(path)
	if err != nil {
		t.Fatalf("LoadCNIPList: %v", err)
	}
	if m.Len() != 3 { // the IPv6 line is skipped
		t.Errorf("Len = %d, want 3", m.Len())
	}
	if !m.Match(net.ParseIP("14.1.2.3")) {
		t.Error("Match = false for an address that should be listed")
	}
}

func TestLoadCNIPListErrors(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file", func(t *testing.T) {
		if _, err := LoadCNIPList(filepath.Join(dir, "absent.txt")); err == nil {
			t.Error("LoadCNIPList accepted a missing file")
		}
	})

	t.Run("malformed line", func(t *testing.T) {
		p := filepath.Join(dir, "bad.txt")
		os.WriteFile(p, []byte("not-a-cidr\n"), 0o600)
		if _, err := LoadCNIPList(p); err == nil {
			t.Error("LoadCNIPList accepted a malformed line")
		}
	})

	t.Run("no IPv4 entries", func(t *testing.T) {
		p := filepath.Join(dir, "v6only.txt")
		os.WriteFile(p, []byte("2001:db8::/32\n"), 0o600)
		if _, err := LoadCNIPList(p); err == nil {
			t.Error("LoadCNIPList accepted a file with no IPv4 prefixes")
		}
	})
}

func BenchmarkMatch(b *testing.B) {
	// Stand in for the real list: a few thousand /24s.
	var ranges []ipRange
	for i := uint32(0); i < 4000; i++ {
		lo := 0x01000000 + i*512 // gaps, so nothing merges
		ranges = append(ranges, ipRange{lo: lo, hi: lo + 255})
	}
	m := NewCNIPMatcher(ranges)
	ip := net.ParseIP("1.0.100.5")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Match(ip)
	}
}
