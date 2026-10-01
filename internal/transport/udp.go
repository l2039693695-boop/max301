// Package transport carries Max301 frames over UDP.
//
// Two shapes are provided. UDPConn is a single listening socket used by relay
// and exit nodes for inbound traffic. MultiPathConn fans one datagram out over
// several sockets aimed at different remote ports, which is how redundancy is
// put on the wire.
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

// Socket buffer sizes. Game traffic is small but bursty, and a brief stall in
// the reader must not cost packets.
const (
	ReadBufferSize  = 4 << 20 // 4 MiB
	WriteBufferSize = 4 << 20
)

// Packet is a datagram received from the network together with its sender.
// Data points into a buffer owned by the reader and is only valid until the
// next read on that connection.
type Packet struct {
	Data []byte
	Addr *net.UDPAddr
	Port int // local port it arrived on, for logging
}

// UDPConn is one listening UDP socket.
type UDPConn struct {
	conn *net.UDPConn
	port int
	buf  []byte
}

// Listen opens a UDP socket on addr:port. An empty addr listens on all
// interfaces.
func Listen(addr string, port int) (*UDPConn, error) {
	if addr == "" {
		addr = "0.0.0.0"
	}
	ua, err := net.ResolveUDPAddr("udp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("resolve %s:%d: %w", addr, port, err)
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, fmt.Errorf("listen %s:%d: %w", addr, port, err)
	}
	tuneSocket(conn)
	// Record the port the kernel actually bound. Passing 0 asks for an
	// ephemeral port, and callers need the real number to tell a peer where to
	// send.
	bound := conn.LocalAddr().(*net.UDPAddr).Port
	return &UDPConn{conn: conn, port: bound, buf: make([]byte, protocol.MaxFrameSize)}, nil
}

// Port reports the local port.
func (c *UDPConn) Port() int { return c.port }

// LocalAddr reports the bound address.
func (c *UDPConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// ReadFrom reads one datagram. The returned slice is reused by the next call,
// so copy it if it must outlive this one. Not safe for concurrent use; run one
// reader per UDPConn.
func (c *UDPConn) ReadFrom() ([]byte, *net.UDPAddr, error) {
	n, addr, err := c.conn.ReadFromUDP(c.buf)
	if err != nil {
		return nil, nil, err
	}
	return c.buf[:n], addr, nil
}

// WriteTo sends one datagram. Safe for concurrent use.
func (c *UDPConn) WriteTo(data []byte, addr *net.UDPAddr) error {
	_, err := c.conn.WriteToUDP(data, addr)
	return err
}

// Close closes the socket, unblocking any reader.
func (c *UDPConn) Close() error { return c.conn.Close() }

// IsTemporary reports whether a read or write error is worth retrying.
//
// A closed socket is permanent and ends the loop. ICMP port-unreachable
// surfaces as a per-datagram error on some platforms yet the socket stays
// usable, so anything else is treated as transient.
func IsTemporary(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, net.ErrClosed) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return true
}

// tuneSocket enlarges the kernel buffers, ignoring failures: the OS may cap
// the request, which costs headroom but still works.
func tuneSocket(conn *net.UDPConn) {
	_ = conn.SetReadBuffer(ReadBufferSize)
	_ = conn.SetWriteBuffer(WriteBufferSize)
}

// Listener owns a set of inbound sockets and merges their traffic onto one
// channel, so a node can accept redundant copies spread across ports.
type Listener struct {
	conns  []*UDPConn
	out    chan Packet
	wg     sync.WaitGroup
	closed atomic.Bool
}

// ListenMulti opens one socket per port.
func ListenMulti(addr string, ports []int) (*Listener, error) {
	if len(ports) == 0 {
		return nil, errors.New("transport: no inbound ports configured")
	}
	l := &Listener{out: make(chan Packet, 1024)}
	for _, p := range ports {
		conn, err := Listen(addr, p)
		if err != nil {
			l.Close()
			return nil, err
		}
		l.conns = append(l.conns, conn)
	}
	for _, conn := range l.conns {
		l.wg.Add(1)
		go l.readLoop(conn)
	}
	return l, nil
}

// Ports lists the bound local ports.
func (l *Listener) Ports() []int {
	ports := make([]int, len(l.conns))
	for i, c := range l.conns {
		ports[i] = c.Port()
	}
	return ports
}

// readLoop pumps one socket into the shared channel. Each datagram is copied
// because the consumer runs on another goroutine.
func (l *Listener) readLoop(conn *UDPConn) {
	defer l.wg.Done()
	defer func() {
		// A panic in the hot path must not take the process down with it.
		_ = recover()
	}()

	for {
		data, addr, err := conn.ReadFrom()
		if err != nil {
			if l.closed.Load() || !IsTemporary(err) {
				return
			}
			continue
		}
		pkt := Packet{Data: append([]byte(nil), data...), Addr: addr, Port: conn.Port()}
		select {
		case l.out <- pkt:
		default:
			// Queue full: the consumer is behind. Dropping the newest frame is
			// the right call for a game -- a stale backlog is worse than a gap.
		}
	}
}

// Recv returns the channel carrying inbound packets from every port.
func (l *Listener) Recv() <-chan Packet { return l.out }

// Send writes to the socket bound to the given local port, so the reply
// carries the source port the peer expects. It falls back to the first socket
// if that port is not held.
func (l *Listener) Send(data []byte, addr *net.UDPAddr, port int) error {
	for _, c := range l.conns {
		if c.Port() == port {
			return c.WriteTo(data, addr)
		}
	}
	if len(l.conns) == 0 {
		return net.ErrClosed
	}
	return l.conns[0].WriteTo(data, addr)
}

// Close shuts every socket and waits for the read loops to exit.
func (l *Listener) Close() error {
	if l.closed.Swap(true) {
		return nil
	}
	for _, c := range l.conns {
		_ = c.Close()
	}
	l.wg.Wait()
	return nil
}
