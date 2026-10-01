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

			if err := writeConfig(path, "203.0.113.9", tc.password, tc.mode, tc.cnip, 2); err != nil {
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
	if err := writeConfig(path, "203.0.113.9", "0123456789abcdef", "global", "", 1); err != nil {
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

// Redundancy above the port count is rejected by the loader, so the wizard must
// not offer a value the generated file cannot use. It writes two ports.
func TestRedundancyWithinPortCount(t *testing.T) {
	for _, r := range []int{1, 2} {
		path := filepath.Join(t.TempDir(), "client.yaml")
		if err := writeConfig(path, "203.0.113.9", "0123456789abcdef", "global", "", r); err != nil {
			t.Fatal(err)
		}
		if _, err := config.LoadClient(path); err != nil {
			t.Errorf("redundancy %d: %v", r, err)
		}
	}

	// 3 exceeds the two ports the wizard writes; confirm the loader says so,
	// which is why askRedundancy's range is capped in the prompt text.
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := writeConfig(path, "203.0.113.9", "0123456789abcdef", "global", "", 3); err != nil {
		t.Fatal(err)
	}
	_, err := config.LoadClient(path)
	if err == nil {
		t.Fatal("redundancy 3 with 2 ports: want an error, got none")
	}
	if !strings.Contains(err.Error(), "redundancy") {
		t.Errorf("unexpected error: %v", err)
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
