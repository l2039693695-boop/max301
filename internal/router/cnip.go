package router

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
)

// CNIPMatcher answers whether an address is inside mainland China.
//
// The list holds thousands of prefixes and is consulted for every new
// destination, so prefixes are stored as sorted uint32 ranges and looked up by
// binary search rather than walking a slice of net.IPNet.
type CNIPMatcher struct {
	ranges []ipRange
}

type ipRange struct {
	lo, hi uint32 // inclusive
}

// LoadCNIPList reads a file of CIDR blocks, one per line, as published by
// github.com/17mon/china_ip_list. Blank lines and # comments are ignored.
func LoadCNIPList(path string) (*CNIPMatcher, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("router: open %s: %w", path, err)
	}
	defer f.Close()
	return parseCNIPList(f, path)
}

// EmbeddedCNIPList returns the prefix list compiled into the binary.
//
// It exists because the client used to download the list at setup time, which
// fails outright on a machine whose hosts file or DNS blocks GitHub -- and that
// is exactly the kind of machine someone installs a tunnel on. 118 KB of text
// in the binary is cheaper than an install that cannot complete.
func EmbeddedCNIPList() (*CNIPMatcher, error) {
	return parseCNIPList(strings.NewReader(embeddedCNIP), "embedded list")
}

func parseCNIPList(r io.Reader, path string) (*CNIPMatcher, error) {
	var ranges []ipRange
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		_, n, err := net.ParseCIDR(text)
		if err != nil {
			return nil, fmt.Errorf("router: %s line %d: %w", path, line, err)
		}
		r, ok := toRange(n)
		if !ok {
			continue // skip IPv6 entries
		}
		ranges = append(ranges, r)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("router: read %s: %w", path, err)
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("router: %s contained no IPv4 prefixes", path)
	}
	return NewCNIPMatcher(ranges), nil
}

// NewCNIPMatcher builds a matcher from ranges, sorting and merging them.
func NewCNIPMatcher(ranges []ipRange) *CNIPMatcher {
	sort.Slice(ranges, func(i, j int) bool { return ranges[i].lo < ranges[j].lo })

	// Merge touching or overlapping ranges so the search space stays small and
	// a lookup cannot straddle two entries.
	merged := ranges[:0]
	for _, r := range ranges {
		if n := len(merged); n > 0 && r.lo <= merged[n-1].hi+1 && merged[n-1].hi != ^uint32(0) {
			if r.hi > merged[n-1].hi {
				merged[n-1].hi = r.hi
			}
			continue
		}
		merged = append(merged, r)
	}
	return &CNIPMatcher{ranges: merged}
}

// Match reports whether ip falls in the list. IPv6 always returns false, so
// IPv6 traffic takes the tunnel path.
func (m *CNIPMatcher) Match(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	addr := beUint32(v4)

	// Rightmost range whose start is at or below addr.
	i := sort.Search(len(m.ranges), func(i int) bool { return m.ranges[i].lo > addr })
	if i == 0 {
		return false
	}
	r := m.ranges[i-1]
	return addr >= r.lo && addr <= r.hi
}

// Len reports how many merged ranges are held.
func (m *CNIPMatcher) Len() int { return len(m.ranges) }

// CIDRs returns the matcher's ranges as CIDR-aligned prefixes, which is what
// the Windows route table needs. A merged range rarely lands on one prefix, so
// it is split into the fewest aligned blocks that cover it.
func (m *CNIPMatcher) CIDRs() []*net.IPNet {
	var out []*net.IPNet
	for _, r := range m.ranges {
		out = append(out, rangeToCIDRs(r)...)
	}
	return out
}

func toRange(n *net.IPNet) (ipRange, bool) {
	v4 := n.IP.To4()
	if v4 == nil {
		return ipRange{}, false
	}
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return ipRange{}, false
	}
	lo := beUint32(v4)
	size := uint32(1)<<(32-ones) - 1
	return ipRange{lo: lo, hi: lo + size}, true
}

// rangeToCIDRs covers [lo, hi] with the fewest aligned prefixes.
func rangeToCIDRs(r ipRange) []*net.IPNet {
	var out []*net.IPNet
	lo, hi := r.lo, r.hi
	for {
		// The block is limited by two things: the alignment of lo, and how much
		// of the range is left. Take the smaller.
		prefix := 32 - trailingZeros32(lo) // alignment allows at most this
		if lo == 0 {
			prefix = 0
		}
		for prefix < 32 && blockSize(prefix) > uint64(hi)-uint64(lo)+1 {
			prefix++
		}

		out = append(out, &net.IPNet{IP: uint32ToIP(lo), Mask: net.CIDRMask(prefix, 32)})

		end := uint64(lo) + blockSize(prefix) - 1
		if end >= uint64(hi) {
			break
		}
		lo = uint32(end + 1)
	}
	return out
}

func blockSize(prefix int) uint64 { return uint64(1) << (32 - prefix) }

func trailingZeros32(v uint32) int {
	if v == 0 {
		return 32
	}
	n := 0
	for v&1 == 0 {
		v >>= 1
		n++
	}
	return n
}

func beUint32(v4 net.IP) uint32 {
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
