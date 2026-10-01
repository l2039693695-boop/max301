//go:build windows

// Package tun also manages the Windows route table entries the tunnel needs.
package tun

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// run executes a command and returns its combined output on failure, since
// netsh and route report the reason there rather than in the exit code alone.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err,
			strings.TrimSpace(string(out)))
	}
	return nil
}

// setInterfaceAddress assigns an address and prefix length to an interface.
func setInterfaceAddress(iface string, prefix netip.Prefix) error {
	mask := net.CIDRMask(prefix.Bits(), 32)
	return run("netsh", "interface", "ipv4", "set", "address",
		"name="+iface, "static", prefix.Addr().String(), net.IP(mask).String())
}

// setInterfaceMTU sets the interface MTU.
func setInterfaceMTU(iface string, mtu int) error {
	return run("netsh", "interface", "ipv4", "set", "subinterface",
		iface, "mtu="+strconv.Itoa(mtu), "store=persistent")
}

// Route describes one route table entry this process added.
type Route struct {
	Dst     netip.Prefix
	Gateway netip.Addr // zero value means on-link
	IfIndex int
	Metric  int
}

// AddRoute installs a route. A zero gateway makes it on-link, which is what a
// point-to-point tunnel interface wants.
func AddRoute(r Route) error {
	args := []string{"interface", "ipv4", "add", "route",
		r.Dst.String(), "interface=" + strconv.Itoa(r.IfIndex)}
	if r.Gateway.IsValid() && !r.Gateway.IsUnspecified() {
		args = append(args, "nexthop="+r.Gateway.String())
	}
	if r.Metric > 0 {
		args = append(args, "metric="+strconv.Itoa(r.Metric))
	}
	args = append(args, "store=active") // not persistent: a crash must not outlive the process
	return run("netsh", args...)
}

// DelRoute removes a route added by AddRoute.
func DelRoute(r Route) error {
	args := []string{"interface", "ipv4", "delete", "route",
		r.Dst.String(), "interface=" + strconv.Itoa(r.IfIndex)}
	if r.Gateway.IsValid() && !r.Gateway.IsUnspecified() {
		args = append(args, "nexthop="+r.Gateway.String())
	}
	return run("netsh", args...)
}

// RouteSet tracks the routes this process installed so every one can be removed
// on exit. Leaving a stale route behind can leave the machine unable to reach
// the network at all, so teardown is not optional.
type RouteSet struct {
	added []Route
}

// Add installs a route and records it for later removal.
func (s *RouteSet) Add(r Route) error {
	if err := AddRoute(r); err != nil {
		return err
	}
	s.added = append(s.added, r)
	return nil
}

// Len reports how many routes are installed.
func (s *RouteSet) Len() int { return len(s.added) }

// RemoveAll deletes every recorded route, newest first, and reports the errors
// it hit. It always attempts all of them: giving up early would leave the
// machine in a worse state than continuing.
func (s *RouteSet) RemoveAll() []error {
	var errs []error
	for i := len(s.added) - 1; i >= 0; i-- {
		if err := DelRoute(s.added[i]); err != nil {
			errs = append(errs, err)
		}
	}
	s.added = nil
	return errs
}

// DefaultRoute describes the system's pre-existing default route, which the
// client needs in order to pin the relay address to the physical link.
type DefaultRoute struct {
	Gateway netip.Addr
	IfIndex int
	IfName  string
	Metric  int
}

// GetDefaultRoute finds the active IPv4 default route, skipping the tunnel
// interface so it keeps reporting the physical path after the tunnel is up.
func GetDefaultRoute(excludeIfIndex int) (*DefaultRoute, error) {
	out, err := exec.Command("netsh", "interface", "ipv4", "show", "route").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("tun: read route table: %w: %s", err, strings.TrimSpace(string(out)))
	}

	best := -1
	var found *DefaultRoute

	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// Columns: Publish Type Met Prefix Idx Gateway/Interface
		if len(fields) < 6 {
			continue
		}
		if fields[3] != "0.0.0.0/0" {
			continue
		}
		metric, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		idx, err := strconv.Atoi(fields[4])
		if err != nil || idx == excludeIfIndex {
			continue
		}
		gw, err := netip.ParseAddr(fields[5])
		if err != nil {
			continue // an interface name here means an on-link default
		}
		if best == -1 || metric < best {
			best = metric
			found = &DefaultRoute{Gateway: gw, IfIndex: idx, Metric: metric}
		}
	}
	if found == nil {
		return nil, fmt.Errorf("tun: no IPv4 default route found")
	}
	return found, nil
}

// InterfaceIndex returns the Windows interface index for a named adapter.
func InterfaceIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, fmt.Errorf("tun: look up interface %q: %w", name, err)
	}
	return iface.Index, nil
}
