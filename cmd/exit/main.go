// Command exit is the landing node. It decrypts tunnelled packets, forwards
// the inner payload to the game server from its own address, and sends replies
// back through the tunnel.
//
// Only UDP is forwarded. Games use UDP for play, and NATing TCP properly would
// mean a user-space stack -- out of scope for the MVP. TCP inside the tunnel is
// counted and dropped.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"max301/internal/config"
	"max301/internal/crypto"
	"max301/internal/protocol"
	"max301/internal/redundancy"
	"max301/internal/router"
	"max301/internal/session"
	"max301/internal/transport"
	"max301/pkg/types"
)

func main() {
	cfgPath := flag.String("c", "exit.yaml", "path to the configuration file")
	flag.Parse()

	cfg, err := config.LoadExit(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	e, err := newExit(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer e.close()

	log.Printf("exit listening on %v, NAT timeout %s", e.inbound.Ports(), cfg.NATTimeout())
	e.run()
}

// natKey identifies a flow from one client to one game server endpoint.
type natKey struct {
	session uint32
	srcPort uint16 // the client's inner source port
	dstIP   [4]byte
	dstPort uint16
}

// natEntry is the socket opened towards a game server for one flow, plus the
// details needed to rebuild the inner IP packet on the way back.
type natEntry struct {
	conn    *net.UDPConn
	session *session.Session
	srcIP   [4]byte // the client's inner source address
	srcPort uint16
	dstIP   [4]byte
	dstPort uint16

	lastUsed atomic.Int64 // unix nanos
	closed   atomic.Bool
}

func (e *natEntry) touch() { e.lastUsed.Store(time.Now().UnixNano()) }
func (e *natEntry) idle() time.Duration {
	return time.Since(time.Unix(0, e.lastUsed.Load()))
}

type exitNode struct {
	inbound  *transport.Listener
	cipher   *crypto.Cipher
	sessions *session.Manager
	recv     *redundancy.Receiver

	natTimeout time.Duration

	mu  sync.RWMutex
	nat map[natKey]*natEntry

	// Return path per session: the peer that last delivered frames for it.
	peerMu sync.RWMutex
	peers  map[uint32]*peerAddr

	stats  types.Stats
	nonUDP atomic.Uint64
	stop   chan struct{}
}

type peerAddr struct {
	addr *net.UDPAddr
	port int
}

func newExit(cfg *config.Exit) (*exitNode, error) {
	cipher, err := crypto.NewCipher(crypto.DeriveKey(cfg.Inbound.Password))
	if err != nil {
		return nil, err
	}
	in, err := transport.ListenMulti(cfg.Inbound.Listen, cfg.Inbound.Ports)
	if err != nil {
		return nil, err
	}

	mgr := session.NewManager(0, 0)
	return &exitNode{
		inbound:    in,
		cipher:     cipher,
		sessions:   mgr,
		recv:       redundancy.NewMultiReceiver(mgr, cipher, nil),
		natTimeout: cfg.NATTimeout(),
		nat:        make(map[natKey]*natEntry),
		peers:      make(map[uint32]*peerAddr),
		stop:       make(chan struct{}),
	}, nil
}

func (e *exitNode) close() {
	e.inbound.Close()
	e.mu.Lock()
	for k, entry := range e.nat {
		entry.closed.Store(true)
		entry.conn.Close()
		delete(e.nat, k)
	}
	e.mu.Unlock()
}

func (e *exitNode) run() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go e.inboundLoop()
	go e.expireNAT()
	go e.reportStats()
	go e.sessions.RunCleanup(time.Minute, e.stop)

	<-sig
	log.Println("shutting down")
	close(e.stop)
}

// inboundLoop decrypts tunnelled frames and forwards their payloads.
func (e *exitNode) inboundLoop() {
	defer recoverLoop("inbound")

	buf := make([]byte, protocol.MaxFrameSize)
	for {
		select {
		case pkt := <-e.inbound.Recv():
			e.handleInbound(pkt, buf)
		case <-e.stop:
			return
		}
	}
}

func (e *exitNode) handleInbound(pkt transport.Packet, buf []byte) {
	res, err := e.recv.Recv(pkt.Data, buf)
	if err != nil {
		return // duplicate, malformed, or failed authentication
	}

	e.setPeer(res.SessionID, pkt.Addr, pkt.Port)
	res.Session.SetPeer(pkt.Addr, pkt.Port)

	if res.Type != protocol.TypeData {
		return // heartbeats need no forwarding; the session was already touched
	}

	ip, err := router.ParseIPv4(res.Payload)
	if err != nil {
		if err == router.ErrUnsupported || ip != nil {
			e.nonUDP.Add(1)
		}
		return
	}
	if ip.Protocol != router.ProtoUDP {
		e.nonUDP.Add(1)
		return
	}

	entry, err := e.lookupNAT(res.Session, ip)
	if err != nil {
		log.Printf("nat: %v", err)
		return
	}
	entry.touch()

	if _, err := entry.conn.Write(ip.Payload); err != nil {
		// A dead socket must not be reused; the next packet reopens one.
		e.dropNAT(entry)
		return
	}
}

// lookupNAT returns the socket for a flow, creating one if needed.
func (e *exitNode) lookupNAT(sess *session.Session, ip *router.Packet) (*natEntry, error) {
	var key natKey
	key.session = sess.ID
	key.srcPort = ip.SrcPort
	copy(key.dstIP[:], ip.Dst.To4())
	key.dstPort = ip.DstPort

	e.mu.RLock()
	entry := e.nat[key]
	e.mu.RUnlock()
	if entry != nil {
		return entry, nil
	}

	dst := &net.UDPAddr{IP: net.IP(key.dstIP[:]), Port: int(ip.DstPort)}
	conn, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", dst, err)
	}
	_ = conn.SetReadBuffer(1 << 20)

	entry = &natEntry{
		conn:    conn,
		session: sess,
		srcPort: ip.SrcPort,
		dstPort: ip.DstPort,
	}
	copy(entry.srcIP[:], ip.Src.To4())
	copy(entry.dstIP[:], key.dstIP[:])
	entry.touch()

	e.mu.Lock()
	if existing := e.nat[key]; existing != nil { // lost the race
		e.mu.Unlock()
		conn.Close()
		return existing, nil
	}
	e.nat[key] = entry
	e.mu.Unlock()

	go e.natReadLoop(key, entry)
	return entry, nil
}

// natReadLoop carries replies from one game server back through the tunnel.
func (e *exitNode) natReadLoop(key natKey, entry *natEntry) {
	defer recoverLoop("nat read")
	defer e.dropNATKey(key, entry)

	buf := make([]byte, 65535)
	frame := make([]byte, 0, protocol.MaxFrameSize)

	for {
		n, err := entry.conn.Read(buf)
		if err != nil {
			if entry.closed.Load() || !transport.IsTemporary(err) {
				return
			}
			continue
		}
		entry.touch()

		// Rebuild the reply as the game would have seen it arrive directly:
		// from the server, to the client's tunnel address.
		inner := router.BuildUDPPacket(nil, entry.dstIP, entry.srcIP,
			entry.dstPort, entry.srcPort, buf[:n])
		if inner == nil {
			continue
		}

		if err := e.sendToClient(entry.session, inner, frame); err != nil {
			log.Printf("return path: %v", err)
		}
	}
}

// sendToClient seals an inner packet and sends it back along the tunnel.
func (e *exitNode) sendToClient(sess *session.Session, inner, scratch []byte) error {
	if len(inner)+protocol.Overhead > protocol.MaxFrameSize {
		return fmt.Errorf("reply of %d bytes exceeds the frame budget", len(inner))
	}

	p := e.getPeer(sess.ID)
	if p == nil {
		return fmt.Errorf("session %#x has no known return path", sess.ID)
	}

	f := protocol.Frame{
		Version:   protocol.Version,
		SessionID: sess.ID,
		PacketID:  sess.NextPacketID(),
		Nonce:     sess.Nonce64,
	}
	f.SetPacketType(protocol.TypeData)
	f.SetPriority(protocol.PriorityGame)
	f.SetLast(true)

	buf := scratch[:protocol.HeaderSize]
	f.EncodeHeader(buf)
	out := sess.Cipher.Seal(buf, f.Nonce, f.PacketID, inner, buf[:protocol.HeaderSize])

	if err := e.inbound.Send(out, p.addr, p.port); err != nil {
		return err
	}
	e.stats.TxPackets.Add(1)
	e.stats.TxBytes.Add(uint64(len(out)))
	return nil
}

func (e *exitNode) dropNAT(entry *natEntry) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, v := range e.nat {
		if v == entry {
			entry.closed.Store(true)
			entry.conn.Close()
			delete(e.nat, k)
			return
		}
	}
}

func (e *exitNode) dropNATKey(key natKey, entry *natEntry) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.nat[key] == entry {
		delete(e.nat, key)
	}
	entry.closed.Store(true)
	entry.conn.Close()
}

// expireNAT closes mappings that have gone quiet.
func (e *exitNode) expireNAT() {
	defer recoverLoop("expireNAT")
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			var stale []*natEntry
			e.mu.Lock()
			for k, entry := range e.nat {
				if entry.idle() > e.natTimeout {
					delete(e.nat, k)
					stale = append(stale, entry)
				}
			}
			e.mu.Unlock()

			for _, entry := range stale {
				entry.closed.Store(true)
				entry.conn.Close() // unblocks its read loop
			}
		case <-e.stop:
			return
		}
	}
}

func (e *exitNode) setPeer(id uint32, addr *net.UDPAddr, port int) {
	e.peerMu.Lock()
	defer e.peerMu.Unlock()
	e.peers[id] = &peerAddr{addr: addr, port: port}
}

func (e *exitNode) getPeer(id uint32) *peerAddr {
	e.peerMu.RLock()
	defer e.peerMu.RUnlock()
	return e.peers[id]
}

func (e *exitNode) reportStats() {
	defer recoverLoop("reportStats")
	t := time.NewTicker(time.Minute)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			e.mu.RLock()
			flows := len(e.nat)
			e.mu.RUnlock()
			log.Printf("sessions %d flows %d tx %d non-UDP dropped %d",
				e.sessions.Len(), flows, e.stats.TxPackets.Load(), e.nonUDP.Load())
		case <-e.stop:
			return
		}
	}
}

func recoverLoop(name string) {
	if v := recover(); v != nil {
		fmt.Fprintf(os.Stderr, "panic in %s: %v\n", name, v)
	}
}
