//go:build windows

// Command client is the Windows end of the tunnel.
//
// It creates a Wintun adapter, points the route table at it, and carries
// packets between the adapter and the first relay. Must run as administrator.
//
// Routing, in bypass_cn mode: the default route is split into 0.0.0.0/1 and
// 128.0.0.0/1 pointing at the tunnel. Those are more specific than 0.0.0.0/0,
// so they win without the original default being touched -- which means a crash
// leaves the machine working. Domestic prefixes are pinned to the physical
// gateway, and so is the relay address, without which the tunnel's own traffic
// would route into itself.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"max301/internal/config"
	"max301/internal/crypto"
	"max301/internal/protocol"
	"max301/internal/redundancy"
	"max301/internal/router"
	"max301/internal/session"
	"max301/internal/transport"
	"max301/internal/tun"
	"max301/pkg/types"
)

// Metrics for the routes we install. Lower wins, and these sit below typical
// interface metrics so our entries take precedence.
const (
	metricTunnel = 5
	metricDirect = 3 // domestic and relay pins must beat the tunnel halves
)

func main() {
	cfgPath := flag.String("c", "", "path to the configuration file (default: run the setup wizard)")
	noWizard := flag.Bool("no-wizard", false, "never prompt; require -c")
	flag.Parse()

	setConsoleUTF8()

	// Flag mode keeps the original behaviour for scripted use; with no flags the
	// program is being double-clicked and walks the user through setup.
	if *cfgPath == "" && !*noWizard {
		banner()
		if !ensureAdmin() {
			return // a second, elevated process is taking over
		}
		dir := exeDir()
		p, err := setup(dir)
		if err != nil {
			say("")
			say("  设置失败：%v", err)
			pause()
			return
		}
		*cfgPath = p
		runInteractive(*cfgPath)
		return
	}

	if *cfgPath == "" {
		*cfgPath = "client.yaml"
	}
	run(*cfgPath)
}

// runInteractive is the double-clicked path: it reports progress in Chinese and
// keeps the window open on failure so the error is readable.
func runInteractive(cfgPath string) {
	say("")
	say("----------------------------------------------")
	say("  正在启动加速")
	say("----------------------------------------------")

	cfg, err := config.LoadClient(cfgPath)
	if err != nil {
		say("")
		say("  配置有问题：%v", err)
		pause()
		return
	}

	c, err := newClient(cfg)
	if err != nil {
		say("")
		say("  初始化失败：%v", err)
		pause()
		return
	}
	defer c.shutdown()

	if err := c.start(); err != nil {
		say("")
		say("  启动失败：%v", err)
		say("")
		say("  常见原因：")
		say("    - 服务器那边没启动，或云服务商安全组没放行 UDP 20001-20004")
		say("    - 密码和服务器不一致")
		say("    - wintun.dll 不在本程序同一个目录")
		pause()
		return
	}

	say("")
	say("  加速已启动。关闭本窗口即停止，路由会自动还原。")
	say("  日志写在 client.log。")
	say("")
	c.wait()
	say("  正在还原网络设置...")
}

func run(cfgPath string) {
	cfg, err := config.LoadClient(cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	c, err := newClient(cfg)
	if err != nil {
		log.Fatal(err)
	}

	// Teardown must happen even on a panic, or the route table is left broken.
	defer c.shutdown()

	if err := c.start(); err != nil {
		log.Print(err)
		return
	}
	c.wait()
}

type client struct {
	cfg *config.Client

	dev    *tun.Device
	out    *transport.MultiPathConn
	sess   *session.Session
	sender *redundancy.Sender
	recv   *redundancy.Receiver

	cnip   *router.CNIPMatcher
	routes tun.RouteSet
	dflt   *tun.DefaultRoute

	stats types.Stats
	stop  chan struct{}
}

func newClient(cfg *config.Client) (*client, error) {
	return &client{cfg: cfg, stop: make(chan struct{})}, nil
}

func (c *client) start() error {
	cfg := c.cfg

	prefix, err := netip.ParsePrefix(cfg.Tun.Address)
	if err != nil {
		return fmt.Errorf("tun.address %q: %w", cfg.Tun.Address, err)
	}

	if cfg.Routing.Mode == "bypass_cn" {
		// An unset or missing cnip_file falls back to the compiled-in list, so
		// split routing works on a machine that cannot reach GitHub.
		if cfg.Routing.CNIPFile == "" {
			c.cnip, err = router.EmbeddedCNIPList()
			if err != nil {
				return err
			}
			log.Printf("loaded %d domestic prefixes (built in)", c.cnip.Len())
		} else {
			c.cnip, err = router.LoadCNIPList(cfg.Routing.CNIPFile)
			if err != nil {
				log.Printf("cannot read %s (%v); using the built-in list", cfg.Routing.CNIPFile, err)
				c.cnip, err = router.EmbeddedCNIPList()
				if err != nil {
					return err
				}
				log.Printf("loaded %d domestic prefixes (built in)", c.cnip.Len())
			} else {
				log.Printf("loaded %d domestic prefixes from %s", c.cnip.Len(), cfg.Routing.CNIPFile)
			}
		}
	}

	// Transport first: if the relay is unreachable there is no point disturbing
	// the route table.
	c.out, err = transport.NewMultiPath(cfg.Relay.Host, cfg.Relay.Ports)
	if err != nil {
		return err
	}

	cipher, err := crypto.NewCipher(crypto.DeriveKey(cfg.Relay.Password))
	if err != nil {
		return err
	}
	c.sess = session.New(session.NewID(), cipher, 0)
	c.sender = redundancy.NewSender(c.sess, c.out, cfg.Relay.Redundancy, &c.stats)
	c.recv = redundancy.NewReceiver(c.sess, cipher, &c.stats)

	c.dev, err = tun.Create(cfg.Tun.Name, cfg.Tun.MTU)
	if err != nil {
		return err
	}
	if err := c.dev.SetIP(prefix); err != nil {
		return err
	}

	// Windows needs a moment after netsh before the interface is usable.
	ifIndex, err := waitForInterface(cfg.Tun.Name, 10*time.Second)
	if err != nil {
		return err
	}

	if err := c.installRoutes(ifIndex); err != nil {
		return fmt.Errorf("install routes: %w", err)
	}

	go c.outbound()
	go c.inbound()
	go c.heartbeat()
	go c.report()

	log.Printf("tunnel up: session %#x, %s via %s:%v, redundancy %d",
		c.sess.ID, prefix, cfg.Relay.Host, cfg.Relay.Ports, cfg.Relay.Redundancy)
	return nil
}

// installRoutes points traffic at the tunnel and pins what must stay direct.
func (c *client) installRoutes(ifIndex int) error {
	// The physical default route, needed for the pins. Found before our own
	// routes exist so the tunnel interface cannot be mistaken for it.
	dflt, err := tun.GetDefaultRoute(ifIndex)
	if err != nil {
		return err
	}
	c.dflt = dflt
	log.Printf("physical gateway %s on interface %d", dflt.Gateway, dflt.IfIndex)

	// The relay itself must stay on the physical link, or its packets would be
	// routed into the tunnel they carry.
	relayIPs, err := net.LookupIP(c.cfg.Relay.Host)
	if err != nil {
		return fmt.Errorf("resolve relay %q: %w", c.cfg.Relay.Host, err)
	}
	var pinned int
	for _, ip := range relayIPs {
		v4, ok := netip.AddrFromSlice(ip.To4())
		if !ok {
			continue
		}
		if err := c.routes.Add(tun.Route{
			Dst:     netip.PrefixFrom(v4, 32),
			Gateway: dflt.Gateway,
			IfIndex: dflt.IfIndex,
			Metric:  metricDirect,
		}); err != nil {
			return fmt.Errorf("pin relay %s: %w", v4, err)
		}
		pinned++
	}
	if pinned == 0 {
		return fmt.Errorf("relay %q has no IPv4 address to pin", c.cfg.Relay.Host)
	}

	// Domestic prefixes stay on the physical link. Failures here are logged and
	// skipped: a few thousand routes go in, and one rejection should not stop
	// the tunnel coming up.
	if c.cnip != nil {
		var ok, failed int
		for _, n := range c.cnip.CIDRs() {
			p, err := prefixFromIPNet(n)
			if err != nil {
				failed++
				continue
			}
			if err := c.routes.Add(tun.Route{
				Dst:     p,
				Gateway: dflt.Gateway,
				IfIndex: dflt.IfIndex,
				Metric:  metricDirect,
			}); err != nil {
				failed++
				continue
			}
			ok++
		}
		log.Printf("pinned %d domestic prefixes to the physical link (%d skipped)", ok, failed)
	}

	// Two halves of the address space, each more specific than the existing
	// default, so the original default route is left untouched.
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		p, err := netip.ParsePrefix(half)
		if err != nil {
			return err
		}
		if err := c.routes.Add(tun.Route{Dst: p, IfIndex: ifIndex, Metric: metricTunnel}); err != nil {
			return fmt.Errorf("route %s into the tunnel: %w", half, err)
		}
	}

	log.Printf("installed %d routes", c.routes.Len())
	return nil
}

// outbound carries packets from the adapter to the relay.
func (c *client) outbound() {
	defer recoverLoop("outbound")

	buf := make([]byte, c.cfg.Tun.MTU)
	for {
		packet, err := c.dev.Read(buf)
		if err != nil {
			if errors.Is(err, tun.ErrClosed) {
				return
			}
			log.Printf("tun read: %v", err)
			continue
		}
		if !router.IsIPv4(packet) {
			continue // IPv6 is not tunnelled
		}
		if err := c.sender.Send(packet, priorityFor(packet)); err != nil {
			log.Printf("send: %v", err)
		}
	}
}

// inbound carries packets from the relay back into the local stack.
func (c *client) inbound() {
	defer recoverLoop("inbound")

	buf := make([]byte, protocol.MaxFrameSize)
	for {
		select {
		case pkt := <-c.out.Recv():
			res, err := c.recv.Recv(pkt.Data, buf)
			if err != nil {
				continue // duplicate, malformed, or failed authentication
			}
			if res.Type != protocol.TypeData {
				continue
			}
			if err := c.dev.Write(res.Payload); err != nil {
				log.Printf("tun write: %v", err)
			}
		case <-c.stop:
			return
		}
	}
}

// heartbeat keeps NAT mappings alive along the chain while a game is idle.
func (c *client) heartbeat() {
	defer recoverLoop("heartbeat")
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if err := c.sender.SendControl(nil, protocol.TypeHeartbeat); err != nil {
				log.Printf("heartbeat: %v", err)
			}
		case <-c.stop:
			return
		}
	}
}

func (c *client) report() {
	defer recoverLoop("report")
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	var prev types.Snapshot
	for {
		select {
		case <-t.C:
			s := c.stats.Snapshot()
			log.Printf("tx %d (+%d) rx %d (+%d) dup %d invalid %d",
				s.TxPackets, s.TxPackets-prev.TxPackets,
				s.RxPackets, s.RxPackets-prev.RxPackets,
				s.Duplicate, s.Invalid)
			prev = s
		case <-c.stop:
			return
		}
	}
}

func (c *client) wait() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")
}

// shutdown removes the routes and closes the device. Route removal comes first:
// a stale route pointing at a dead interface is what breaks connectivity.
func (c *client) shutdown() {
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}

	if n := c.routes.Len(); n > 0 {
		log.Printf("removing %d routes", n)
		for _, err := range c.routes.RemoveAll() {
			log.Printf("route cleanup: %v", err)
		}
	}
	if c.dev != nil {
		if err := c.dev.Close(); err != nil {
			log.Printf("close tun: %v", err)
		}
	}
	if c.out != nil {
		c.out.Close()
	}
}

// priorityFor classifies a packet. Small UDP datagrams are game traffic and get
// the configured redundancy; everything else is bulk and is sent once, so a
// download cannot multiply itself across the link.
func priorityFor(packet []byte) byte {
	p, err := router.ParseIPv4(packet)
	if err != nil {
		return protocol.PriorityNormal
	}
	if p.Protocol == router.ProtoUDP && len(p.Payload) <= 512 {
		return protocol.PriorityGame
	}
	return protocol.PriorityNormal
}

func prefixFromIPNet(n *net.IPNet) (netip.Prefix, error) {
	addr, ok := netip.AddrFromSlice(n.IP.To4())
	if !ok {
		return netip.Prefix{}, fmt.Errorf("not an IPv4 prefix: %v", n)
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(addr, ones), nil
}

// waitForInterface polls until Windows reports the adapter, which lags the
// netsh call that configures it.
func waitForInterface(name string, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for {
		if idx, err := tun.InterfaceIndex(name); err == nil {
			return idx, nil
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("interface %q did not appear within %s", name, timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func recoverLoop(name string) {
	if v := recover(); v != nil {
		fmt.Fprintf(os.Stderr, "panic in %s: %v\n", name, v)
	}
}
