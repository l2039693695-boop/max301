package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The shipped examples must load, or a new user's first run fails.
func TestExamplesLoad(t *testing.T) {
	dir := filepath.Join("..", "..", "configs")

	t.Run("client", func(t *testing.T) {
		c, err := LoadClient(filepath.Join(dir, "client.yaml.example"))
		if err != nil {
			t.Fatalf("LoadClient: %v", err)
		}
		if c.Tun.MTU != 1400 {
			t.Errorf("MTU = %d, want 1400", c.Tun.MTU)
		}
		if c.Relay.Redundancy != 2 {
			t.Errorf("redundancy = %d, want 2", c.Relay.Redundancy)
		}
	})

	t.Run("relay", func(t *testing.T) {
		c, err := LoadRelay(filepath.Join(dir, "relay.yaml.example"))
		if err != nil {
			t.Fatalf("LoadRelay: %v", err)
		}
		if len(c.Outbound.Ports) != 4 {
			t.Errorf("outbound ports = %d, want 4", len(c.Outbound.Ports))
		}
	})

	t.Run("exit", func(t *testing.T) {
		c, err := LoadExit(filepath.Join(dir, "exit.yaml.example"))
		if err != nil {
			t.Fatalf("LoadExit: %v", err)
		}
		if c.NATTimeout() != 2*time.Minute {
			t.Errorf("NAT timeout = %s, want 2m", c.NATTimeout())
		}
	})
}

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const goodPassword = "a-sufficiently-long-secret"

func TestRelayRejectsMismatchedPasswords(t *testing.T) {
	p := write(t, `
mode: relay
inbound:
  ports: [20001]
  password: "`+goodPassword+`"
outbound:
  host: "10.0.0.1"
  ports: [20001]
  password: "a-different-long-secret-value"
`)
	_, err := LoadRelay(p)
	if err == nil {
		t.Fatal("LoadRelay accepted differing inbound and outbound passwords")
	}
	if !strings.Contains(err.Error(), "must match") {
		t.Errorf("error = %v, want one about matching passwords", err)
	}
}

// Redundancy above the port count would send copies to ports nobody listens on.
func TestRejectsRedundancyAbovePortCount(t *testing.T) {
	p := write(t, `
mode: client
tun:
  address: "10.88.0.2/24"
relay:
  host: "10.0.0.1"
  ports: [20001, 20002]
  password: "`+goodPassword+`"
  redundancy: 5
routing:
  mode: "bypass_cn"
`)
	_, err := LoadClient(p)
	if err == nil {
		t.Fatal("LoadClient accepted redundancy greater than the port count")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error = %v, want one about exceeding the port count", err)
	}
}

func TestRejectsShortPassword(t *testing.T) {
	p := write(t, `
mode: relay
inbound:
  ports: [20001]
  password: "short"
outbound:
  host: "10.0.0.1"
  ports: [20001]
  password: "short"
`)
	if _, err := LoadRelay(p); err == nil {
		t.Error("LoadRelay accepted a five-character password")
	}
}

func TestRejectsMissingFields(t *testing.T) {
	tests := []struct {
		name, body string
	}{
		{"no ports", `
mode: relay
inbound:
  ports: []
  password: "` + goodPassword + `"
outbound:
  host: "10.0.0.1"
  ports: [1]
  password: "` + goodPassword + `"`},

		{"no outbound host", `
mode: relay
inbound:
  ports: [20001]
  password: "` + goodPassword + `"
outbound:
  ports: [20001]
  password: "` + goodPassword + `"`},

		{"invalid port", `
mode: relay
inbound:
  ports: [70000]
  password: "` + goodPassword + `"
outbound:
  host: "10.0.0.1"
  ports: [20001]
  password: "` + goodPassword + `"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadRelay(write(t, tc.body)); err == nil {
				t.Error("LoadRelay accepted an invalid configuration")
			}
		})
	}
}

// A misspelled key must be an error rather than a silent default, since the
// silent version looks like a working config that ignores half your settings.
func TestRejectsUnknownKeys(t *testing.T) {
	p := write(t, `
mode: exit
inbound:
  ports: [20001]
  password: "`+goodPassword+`"
  redundandcy: 3
`)
	if _, err := LoadExit(p); err == nil {
		t.Error("LoadExit accepted a misspelled key")
	}
}

func TestExitRejectsUnknownOutboundMode(t *testing.T) {
	p := write(t, `
mode: exit
inbound:
  ports: [20001]
  password: "`+goodPassword+`"
outbound:
  mode: "socks5"
`)
	if _, err := LoadExit(p); err == nil {
		t.Error("LoadExit accepted an unsupported outbound mode")
	}
}

func TestDefaultsApplied(t *testing.T) {
	p := write(t, `
mode: client
tun:
  address: "10.88.0.2/24"
relay:
  host: "10.0.0.1"
  ports: [20001]
  password: "`+goodPassword+`"
`)
	c, err := LoadClient(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Tun.Name != "Max301" {
		t.Errorf("tun name = %q, want Max301", c.Tun.Name)
	}
	if c.Tun.MTU != 1400 {
		t.Errorf("MTU = %d, want 1400", c.Tun.MTU)
	}
	if c.Routing.Mode != "bypass_cn" {
		t.Errorf("routing mode = %q, want bypass_cn", c.Routing.Mode)
	}
}

func TestClientRequiresTunAddress(t *testing.T) {
	p := write(t, `
mode: client
relay:
  host: "10.0.0.1"
  ports: [20001]
  password: "`+goodPassword+`"
`)
	if _, err := LoadClient(p); err == nil {
		t.Error("LoadClient accepted a config with no tun address")
	}
}

func TestMissingFileIsAnError(t *testing.T) {
	if _, err := LoadRelay(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
		t.Error("LoadRelay accepted a missing file")
	}
}
