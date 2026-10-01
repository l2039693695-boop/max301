// Package config loads the YAML configuration for each node role.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Endpoint describes a set of UDP ports on one host.
type Endpoint struct {
	Host     string `yaml:"host"`
	Listen   string `yaml:"listen"`
	Ports    []int  `yaml:"ports"`
	Password string `yaml:"password"`

	// Redundancy is how many copies of each game packet to send. 1 means no
	// duplication, appropriate for a leased line.
	Redundancy int `yaml:"redundancy"`
}

// LogConfig controls logging.
type LogConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}

// TunConfig describes the local tunnel device.
type TunConfig struct {
	Name    string `yaml:"name"`
	Address string `yaml:"address"`
	MTU     int    `yaml:"mtu"`
}

// RoutingConfig controls which destinations go through the tunnel.
type RoutingConfig struct {
	// Mode is "bypass_cn" to send only foreign traffic through the tunnel, or
	// "global" to send everything.
	Mode string `yaml:"mode"`

	CNIPFile string `yaml:"cnip_file"`
}

// Client is the Windows client configuration.
type Client struct {
	Mode    string        `yaml:"mode"`
	Tun     TunConfig     `yaml:"tun"`
	Relay   Endpoint      `yaml:"relay"`
	Routing RoutingConfig `yaml:"routing"`
	Log     LogConfig     `yaml:"log"`
}

// Relay is the configuration for an intermediate hop.
type Relay struct {
	Mode     string    `yaml:"mode"`
	Inbound  Endpoint  `yaml:"inbound"`
	Outbound Endpoint  `yaml:"outbound"`
	Log      LogConfig `yaml:"log"`
}

// Exit is the configuration for the landing node.
type Exit struct {
	Mode    string   `yaml:"mode"`
	Inbound Endpoint `yaml:"inbound"`

	Outbound struct {
		// Mode is "nat": decrypt, then forward the inner packet from this host.
		Mode string `yaml:"mode"`

		// NATTimeout is how long an idle mapping is kept. Game sessions are
		// long-lived, so this is generous by UDP standards.
		NATTimeout time.Duration `yaml:"nat_timeout"`
	} `yaml:"outbound"`

	Log LogConfig `yaml:"log"`
}

// NATTimeout reports how long an idle NAT mapping is kept.
func (c *Exit) NATTimeout() time.Duration { return c.Outbound.NATTimeout }

// LoadClient reads a client configuration file.
func LoadClient(path string) (*Client, error) {
	var c Client
	if err := load(path, &c); err != nil {
		return nil, err
	}
	if c.Tun.Name == "" {
		c.Tun.Name = "Max301"
	}
	if c.Tun.MTU == 0 {
		c.Tun.MTU = 1400
	}
	if c.Routing.Mode == "" {
		c.Routing.Mode = "bypass_cn"
	}
	if err := validateEndpoint("relay", c.Relay, true); err != nil {
		return nil, err
	}
	if c.Tun.Address == "" {
		return nil, errors.New("config: tun.address is required")
	}
	return &c, nil
}

// LoadRelay reads a relay configuration file.
func LoadRelay(path string) (*Relay, error) {
	var c Relay
	if err := load(path, &c); err != nil {
		return nil, err
	}
	if err := validateEndpoint("inbound", c.Inbound, false); err != nil {
		return nil, err
	}
	if err := validateEndpoint("outbound", c.Outbound, true); err != nil {
		return nil, err
	}
	if c.Inbound.Password != c.Outbound.Password {
		// The MVP uses one key end to end, so a relay that re-keys would break
		// the chain. Catch it at startup rather than as silent packet loss.
		return nil, errors.New("config: inbound.password and outbound.password must match")
	}
	return &c, nil
}

// LoadExit reads an exit node configuration file.
func LoadExit(path string) (*Exit, error) {
	var c Exit
	if err := load(path, &c); err != nil {
		return nil, err
	}
	if err := validateEndpoint("inbound", c.Inbound, false); err != nil {
		return nil, err
	}
	if c.Outbound.Mode == "" {
		c.Outbound.Mode = "nat"
	}
	if c.Outbound.Mode != "nat" {
		return nil, fmt.Errorf("config: unsupported outbound.mode %q, want \"nat\"", c.Outbound.Mode)
	}
	if c.Outbound.NATTimeout == 0 {
		c.Outbound.NATTimeout = 2 * time.Minute
	}
	return &c, nil
}

func load(path string, dst any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: read %s: %w", path, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // a typo in a key should be an error, not a silent default
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("config: parse %s: %w", path, err)
	}
	return nil
}

func validateEndpoint(name string, e Endpoint, needHost bool) error {
	if needHost && e.Host == "" {
		return fmt.Errorf("config: %s.host is required", name)
	}
	if len(e.Ports) == 0 {
		return fmt.Errorf("config: %s.ports must list at least one port", name)
	}
	for _, p := range e.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("config: %s.ports contains invalid port %d", name, p)
		}
	}
	if e.Password == "" {
		return fmt.Errorf("config: %s.password is required", name)
	}
	if len(e.Password) < 16 {
		return fmt.Errorf("config: %s.password is too short; use at least 16 characters", name)
	}
	if e.Redundancy > len(e.Ports) {
		return fmt.Errorf("config: %s.redundancy (%d) exceeds the number of ports (%d)",
			name, e.Redundancy, len(e.Ports))
	}
	return nil
}
