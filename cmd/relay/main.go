// Command relay forwards Max301 frames between two hops.
//
// A relay deliberately does not decrypt payloads. It parses the cleartext
// header, drops duplicates, and forwards the frame untouched. That keeps a
// 1-core box cheap to run and means a compromised relay cannot read traffic --
// though with a single shared password it could still be used to inject frames
// the exit node would reject only at the AEAD check.
//
// Return traffic is matched by session ID: whichever address last sent frames
// for a session is where replies go.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"max301/internal/config"
	"max301/internal/dedup"
	"max301/internal/protocol"
	"max301/internal/transport"
	"max301/pkg/types"
)

func main() {
	cfgPath := flag.String("c", "relay.yaml", "path to the configuration file")
	flag.Parse()

	cfg, err := config.LoadRelay(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}

	r, err := newRelay(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer r.close()

	log.Printf("relay listening on %v, forwarding to %s:%v (redundancy %d)",
		r.inbound.Ports(), cfg.Outbound.Host, r.outbound.Ports(), r.redundancy)

	r.run()
}

// peer records where to send return traffic for a session.
type peer struct {
	addr *net.UDPAddr
	port int // local inbound port the client used
	seen time.Time
}

type relay struct {
	inbound  *transport.Listener
	outbound *transport.MultiPathConn

	redundancy int

	// Separate deduplicators per direction: the two directions have
	// independent packet ID sequences and must not evict each other.
	fwdDedup *dedup.Deduplicator
	revDedup *dedup.Deduplicator

	mu    sync.RWMutex
	peers map[uint32]*peer

	stats types.Stats
	stop  chan struct{}
}

func newRelay(cfg *config.Relay) (*relay, error) {
	in, err := transport.ListenMulti(cfg.Inbound.Listen, cfg.Inbound.Ports)
	if err != nil {
		return nil, err
	}
	out, err := transport.NewMultiPath(cfg.Outbound.Host, cfg.Outbound.Ports)
	if err != nil {
		in.Close()
		return nil, err
	}

	red := cfg.Outbound.Redundancy
	if red < 1 {
		red = 1
	}

	return &relay{
		inbound:    in,
		outbound:   out,
		redundancy: red,
		fwdDedup:   dedup.New(dedup.DefaultWindow),
		revDedup:   dedup.New(dedup.DefaultWindow),
		peers:      make(map[uint32]*peer),
		stop:       make(chan struct{}),
	}, nil
}

func (r *relay) close() {
	r.inbound.Close()
	r.outbound.Close()
}

func (r *relay) run() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go r.forward()
	go r.reverse()
	go r.reportStats()
	go r.expirePeers()

	<-sig
	log.Println("shutting down")
	close(r.stop)
}

// forward moves frames from the client side towards the next hop.
func (r *relay) forward() {
	defer recoverLoop("forward")
	for {
		select {
		case pkt := <-r.inbound.Recv():
			r.handleForward(pkt)
		case <-r.stop:
			return
		}
	}
}

func (r *relay) handleForward(pkt transport.Packet) {
	r.stats.RxPackets.Add(1)
	r.stats.RxBytes.Add(uint64(len(pkt.Data)))

	var f protocol.Frame
	if err := f.DecodeHeader(pkt.Data); err != nil {
		r.stats.Invalid.Add(1)
		return
	}

	// Remember the return path before deduplicating, so a duplicate still
	// refreshes it.
	r.setPeer(f.SessionID, pkt.Addr, pkt.Port)

	if r.fwdDedup.Seen(f.PacketID) {
		r.stats.Duplicate.Add(1)
		return
	}

	if err := r.outbound.SendRedundant(pkt.Data, r.redundancy); err != nil {
		log.Printf("forward: %v", err)
		return
	}
	r.stats.TxPackets.Add(1)
	r.stats.TxBytes.Add(uint64(len(pkt.Data)))
}

// reverse moves frames coming back from the next hop towards the client.
func (r *relay) reverse() {
	defer recoverLoop("reverse")
	for {
		select {
		case pkt := <-r.outbound.Recv():
			r.handleReverse(pkt)
		case <-r.stop:
			return
		}
	}
}

func (r *relay) handleReverse(pkt transport.Packet) {
	r.stats.RxPackets.Add(1)
	r.stats.RxBytes.Add(uint64(len(pkt.Data)))

	var f protocol.Frame
	if err := f.DecodeHeader(pkt.Data); err != nil {
		r.stats.Invalid.Add(1)
		return
	}
	if r.revDedup.Seen(f.PacketID) {
		r.stats.Duplicate.Add(1)
		return
	}

	p := r.getPeer(f.SessionID)
	if p == nil {
		// No client has used this session here yet; nothing to do with it.
		return
	}
	if err := r.inbound.Send(pkt.Data, p.addr, p.port); err != nil {
		log.Printf("reverse: %v", err)
		return
	}
	r.stats.TxPackets.Add(1)
	r.stats.TxBytes.Add(uint64(len(pkt.Data)))
}

func (r *relay) setPeer(id uint32, addr *net.UDPAddr, port int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if p, ok := r.peers[id]; ok {
		p.addr, p.port, p.seen = addr, port, time.Now()
		return
	}
	r.peers[id] = &peer{addr: addr, port: port, seen: time.Now()}
}

func (r *relay) getPeer(id uint32) *peer {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p := r.peers[id]
	if p == nil {
		return nil
	}
	cp := *p
	return &cp
}

// expirePeers drops return paths for sessions that have gone quiet.
func (r *relay) expirePeers() {
	defer recoverLoop("expirePeers")
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			cutoff := time.Now().Add(-10 * time.Minute)
			r.mu.Lock()
			for id, p := range r.peers {
				if p.seen.Before(cutoff) {
					delete(r.peers, id)
				}
			}
			r.mu.Unlock()
		case <-r.stop:
			return
		}
	}
}

func (r *relay) reportStats() {
	defer recoverLoop("reportStats")
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	var prev types.Snapshot
	for {
		select {
		case <-t.C:
			s := r.stats.Snapshot()
			r.mu.RLock()
			sessions := len(r.peers)
			r.mu.RUnlock()
			log.Printf("rx %d (+%d) tx %d (+%d) dup %d invalid %d sessions %d",
				s.RxPackets, s.RxPackets-prev.RxPackets,
				s.TxPackets, s.TxPackets-prev.TxPackets,
				s.Duplicate, s.Invalid, sessions)
			prev = s
		case <-r.stop:
			return
		}
	}
}

// recoverLoop keeps a panic in one packet loop from killing the process.
func recoverLoop(name string) {
	if v := recover(); v != nil {
		fmt.Fprintf(os.Stderr, "panic in %s: %v\n", name, v)
	}
}
