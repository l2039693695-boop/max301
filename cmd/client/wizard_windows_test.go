//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"max301/internal/config"
)

// The wizard writes client.yaml by hand, so the thing most likely to break is
// the loader rejecting its own generated file. Check both routing modes round
// trip, and that a password with YAML metacharacters survives quoting.
func TestWriteConfigLoads(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		cnip     string
		password string
	}{
		{"bypass_cn", "bypass_cn", "chnroute.txt", "0123456789abcdef0123"},
		{"global", "global", "", "0123456789abcdef0123"},
		{"awkward password", "global", "", `a: b #c "d" 'e' \f`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "client.yaml")

			if tc.mode == "bypass_cn" {
				// LoadClient does not read the prefix list, but the client does,
				// so write one to keep the fixture honest.
				if err := os.WriteFile(filepath.Join(dir, tc.cnip),
					[]byte("1.0.1.0/24\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			if err := writeConfig(path, "203.0.113.9", tc.password, tc.mode, tc.cnip, []int{20001, 20002}, 2); err != nil {
				t.Fatalf("writeConfig: %v", err)
			}

			cfg, err := config.LoadClient(path)
			if err != nil {
				data, _ := os.ReadFile(path)
				t.Fatalf("LoadClient rejected the generated file: %v\n---\n%s", err, data)
			}
			if cfg.Relay.Host != "203.0.113.9" {
				t.Errorf("host = %q, want 203.0.113.9", cfg.Relay.Host)
			}
			if cfg.Relay.Password != tc.password {
				t.Errorf("password = %q, want %q", cfg.Relay.Password, tc.password)
			}
			if cfg.Routing.Mode != tc.mode {
				t.Errorf("routing mode = %q, want %q", cfg.Routing.Mode, tc.mode)
			}
			if cfg.Relay.Redundancy != 2 {
				t.Errorf("redundancy = %d, want 2", cfg.Relay.Redundancy)
			}
			if cfg.Tun.MTU != 1400 {
				t.Errorf("mtu = %d, want 1400", cfg.Tun.MTU)
			}
		})
	}
}

// The config file holds the shared password. Windows ignores the Unix mode
// passed to WriteFile, so what matters is the ACL restrictACL applies: no
// entry for Users or Everyone.
func TestWriteConfigRestrictsACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := writeConfig(path, "203.0.113.9", "0123456789abcdef", "global", "", []int{20001, 20002}, 1); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command("icacls", path).CombinedOutput()
	if err != nil {
		t.Skipf("icacls unavailable: %v", err)
	}
	acl := string(out)
	for _, bad := range []string{"Everyone", "BUILTIN\\Users", "\\Users:"} {
		if strings.Contains(acl, bad) {
			t.Errorf("ACL still grants %s:\n%s", bad, acl)
		}
	}
	// Sanity check that the ACL was actually replaced rather than left empty.
	if !strings.Contains(acl, "NT AUTHORITY\\SYSTEM") {
		t.Errorf("expected a SYSTEM entry, got:\n%s", acl)
	}
}

// Redundancy above the port count is rejected by the loader, which is why
// askRedundancy caps its range at the number of ports the user entered. Check
// the cap matches what the loader will actually accept.
func TestRedundancyWithinPortCount(t *testing.T) {
	ports := []int{20001, 20002, 20003}
	for _, r := range []int{1, 2, 3} {
		path := filepath.Join(t.TempDir(), "client.yaml")
		if err := writeConfig(path, "203.0.113.9", "0123456789abcdef", "global", "", ports, r); err != nil {
			t.Fatal(err)
		}
		if _, err := config.LoadClient(path); err != nil {
			t.Errorf("redundancy %d with %d ports: %v", r, len(ports), err)
		}
	}

	// One past the port count must be refused, so the prompt's cap is not
	// merely cosmetic.
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := writeConfig(path, "203.0.113.9", "0123456789abcdef", "global", "", ports, 4); err != nil {
		t.Fatal(err)
	}
	_, err := config.LoadClient(path)
	if err == nil {
		t.Fatal("redundancy 4 with 3 ports: want an error, got none")
	}
	if !strings.Contains(err.Error(), "redundancy") {
		t.Errorf("unexpected error: %v", err)
	}
}

// A custom port set must survive into the config, since the whole point is
// matching a server that does not use the defaults.
func TestWriteConfigCustomPorts(t *testing.T) {
	ports := []int{30001, 30002, 30003, 30004}
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := writeConfig(path, "203.0.113.9", "0123456789abcdef", "global", "", ports, 3); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadClient(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Relay.Ports) != len(ports) {
		t.Fatalf("got %d ports, want %d", len(cfg.Relay.Ports), len(ports))
	}
	for i, p := range ports {
		if cfg.Relay.Ports[i] != p {
			t.Errorf("port %d = %d, want %d", i, cfg.Relay.Ports[i], p)
		}
	}
}

func TestParsePorts(t *testing.T) {
	ok := []struct {
		in   string
		want []int
	}{
		{"20001,20002", []int{20001, 20002}},
		{"30001, 30002, 30003", []int{30001, 30002, 30003}}, // spaces tolerated
		{"20001", []int{20001}},
		{"20001,20002,", []int{20001, 20002}}, // trailing comma
	}
	for _, tc := range ok {
		got, err := parsePorts(tc.in)
		if err != nil {
			t.Errorf("parsePorts(%q): %v", tc.in, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("parsePorts(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parsePorts(%q) = %v, want %v", tc.in, got, tc.want)
				break
			}
		}
	}

	bad := []string{
		"",                  // nothing
		"abc",               // not a number
		"80",                // privileged
		"70000",             // out of range
		"0",                 // out of range
		"20001,20001",       // duplicate, which would waste a path
		"1,2,3,4,5,6,7,8,9", // more than the cap
	}
	for _, in := range bad {
		if _, err := parsePorts(in); err == nil {
			t.Errorf("parsePorts(%q): want an error, got none", in)
		}
	}
}

// askRedundancy must never return a value the loader will reject, whatever the
// port count.
func TestRedundancyCapNeverExceedsPorts(t *testing.T) {
	for ports := 1; ports <= 8; ports++ {
		max := ports
		if max > 4 {
			max = 4
		}
		path := filepath.Join(t.TempDir(), "client.yaml")
		list := make([]int, ports)
		for i := range list {
			list[i] = 20001 + i
		}
		if err := writeConfig(path, "203.0.113.9", "0123456789abcdef", "global", "", list, max); err != nil {
			t.Fatal(err)
		}
		if _, err := config.LoadClient(path); err != nil {
			t.Errorf("%d ports, redundancy %d: %v", ports, max, err)
		}
	}
}

// bypass_cn with no cnip_file is the normal case now that the list is embedded.
// The loader must accept it, and the key must be absent rather than empty --
// an empty cnip_file would send the client looking for a file named "".
func TestWriteConfigOmitsCNIPFileWhenEmbedded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := writeConfig(path, "203.0.113.9", "0123456789abcdef", "bypass_cn", "", []int{20001, 20002}, 2); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "cnip_file") {
		t.Errorf("cnip_file should be absent:\n%s", data)
	}

	cfg, err := config.LoadClient(path)
	if err != nil {
		t.Fatalf("LoadClient: %v\n---\n%s", err, data)
	}
	if cfg.Routing.Mode != "bypass_cn" {
		t.Errorf("mode = %q, want bypass_cn", cfg.Routing.Mode)
	}
	if cfg.Routing.CNIPFile != "" {
		t.Errorf("cnip_file = %q, want empty", cfg.Routing.CNIPFile)
	}
}

func TestRandomTunAddressIsValid(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		addr := randomTunAddress()
		if !strings.HasPrefix(addr, "10.88.") || !strings.HasSuffix(addr, ".2/24") {
			t.Fatalf("unexpected address %q", addr)
		}
		seen[addr] = true
	}
	if len(seen) < 5 {
		t.Errorf("only %d distinct addresses in 50 draws; randomisation looks broken", len(seen))
	}
}
