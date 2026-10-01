package transport

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"max301/internal/protocol"
)

// MultiPathConn sends one datagram over several sockets aimed at distinct
// remote ports. Spreading copies across ports makes it likely that at least
// one lands on a different ECMP hash in the carrier's network, so a single
// congested path does not drop every copy.
type MultiPathConn struct {
	conns   []*net.UDPConn
	remotes []*net.UDPAddr
	host    string
	ports   []int

	next   atomic.Uint32 // rotates the starting socket
	out    chan Packet
	wg     sync.WaitGroup
	closed atomic.Bool
	once   sync.Once
}

// NewMultiPath dials one socket per remote port. Each socket is connected, so
// the kernel picks the source address and stray traffic from other peers is
// filtered out.
func NewMultiPath(host string, ports []int) (*MultiPathConn, error) {
	if host == "" {
		return nil, errors.New("transport: outbound host is empty")
	}
	if len(ports) == 0 {
		return nil, errors.New("transport: no outbound ports configured")
	}

	m := &MultiPathConn{host: host, ports: ports, out: make(chan Packet, 1024)}
	for _, p := range ports {
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(p)))
		if err != nil {
			m.Close()
			return nil, fmt.Errorf("resolve %s:%d: %w", host, p, err)
		}
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			m.Close()
			return nil, fmt.Errorf("dial %s:%d: %w", host, p, err)
		}
		tuneSocket(conn)
		m.conns = append(m.conns, conn)
		m.remotes = append(m.remotes, addr)
	}

	for i, conn := range m.conns {
		m.wg.Add(1)
		go m.readLoop(conn, ports[i])
	}
	return m, nil
}

// Paths reports how many sockets are available.
func (m *MultiPathConn) Paths() int { return len(m.conns) }

// Ports lists the remote ports in use.
func (m *MultiPathConn) Ports() []int { return m.ports }

// SendRedundant writes data to count distinct sockets, rotating the starting
// point so load spreads evenly. count is clamped to the number of paths; a
// count below 1 sends one copy.
//
// It succeeds if at least one copy went out, since the point of redundancy is
// surviving partial failure. The error describes the last failure when every
// copy failed.
func (m *MultiPathConn) SendRedundant(data []byte, count int) error {
	n := len(m.conns)
	if n == 0 {
		return net.ErrClosed
	}
	if count < 1 {
		count = 1
	}
	if count > n {
		count = n
	}

	start := int(m.next.Add(1)) % n
	var (
		sent    int
		lastErr error
	)
	for i := 0; i < count; i++ {
		conn := m.conns[(start+i)%n]
		if _, err := conn.Write(data); err != nil {
			lastErr = err
			continue
		}
		sent++
	}
	if sent == 0 {
		return fmt.Errorf("all %d paths failed, last error: %w", count, lastErr)
	}
	return nil
}

// readLoop pumps one socket into the shared channel.
func (m *MultiPathConn) readLoop(conn *net.UDPConn, port int) {
	defer m.wg.Done()
	defer func() { _ = recover() }()

	buf := make([]byte, protocol.MaxFrameSize)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if m.closed.Load() || !IsTemporary(err) {
				return
			}
			continue
		}
		pkt := Packet{Data: append([]byte(nil), buf[:n]...), Addr: addr, Port: port}
		select {
		case m.out <- pkt:
		default:
		}
	}
}

// Recv returns the channel carrying return traffic from every path. Duplicates
// are expected here; the deduplicator upstream collapses them.
func (m *MultiPathConn) Recv() <-chan Packet { return m.out }

// Close shuts every socket and waits for the read loops to exit.
func (m *MultiPathConn) Close() error {
	m.once.Do(func() {
		m.closed.Store(true)
		for _, c := range m.conns {
			_ = c.Close()
		}
		m.wg.Wait()
	})
	return nil
}
