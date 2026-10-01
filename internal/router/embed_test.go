package router

import (
	"net"
	"testing"
)

// The embedded list is what the client uses when it cannot reach GitHub, so a
// broken or truncated embed must not pass silently.
func TestEmbeddedCNIPList(t *testing.T) {
	m, err := EmbeddedCNIPList()
	if err != nil {
		t.Fatalf("EmbeddedCNIPList: %v", err)
	}

	// The real list has thousands of prefixes; a few hundred would mean a
	// truncated or wrong file got embedded.
	if n := m.Len(); n < 3000 {
		t.Errorf("only %d prefixes; the embedded list looks truncated", n)
	}

	domestic := []string{
		"1.0.1.1",         // first range in the list
		"114.114.114.114", // 114DNS
		"223.5.5.5",       // AliDNS
		"180.76.76.76",    // Baidu DNS
	}
	for _, s := range domestic {
		if !m.Match(net.ParseIP(s)) {
			t.Errorf("%s should be inside mainland China", s)
		}
	}

	foreign := []string{
		"8.8.8.8",        // Google
		"1.1.1.1",        // Cloudflare
		"208.67.222.222", // OpenDNS
	}
	for _, s := range foreign {
		if m.Match(net.ParseIP(s)) {
			t.Errorf("%s should be outside mainland China", s)
		}
	}
}

// The embedded and on-disk paths must agree, or behaviour would depend on how
// the list reached the program.
func TestEmbeddedMatchesFileLoad(t *testing.T) {
	embedded, err := EmbeddedCNIPList()
	if err != nil {
		t.Fatal(err)
	}
	fromFile, err := LoadCNIPList("data/chnroute.txt")
	if err != nil {
		t.Fatal(err)
	}
	if embedded.Len() != fromFile.Len() {
		t.Errorf("embedded has %d prefixes, the file has %d", embedded.Len(), fromFile.Len())
	}
}
