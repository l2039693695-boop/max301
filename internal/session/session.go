// Package session tracks per-client state: the cipher, the outbound packet
// counter, and the inbound deduplicator.
package session

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"max301/internal/crypto"
	"max301/internal/dedup"
)

// DefaultTimeout is how long a session may sit idle before cleanup.
const DefaultTimeout = 10 * time.Minute

// Session holds the state for one client tunnel.
//
// The send counter and nonce base live here: PacketID increments per packet and
// the base is random per session, which together guarantee the AEAD never
// reuses a nonce.
type Session struct {
	ID     uint32
	Cipher *crypto.Cipher

	// Nonce64 is the random per-session nonce base.
	Nonce64 uint64

	CreatedAt time.Time

	nextPacketID atomic.Uint32
	lastSeen     atomic.Int64 // unix nanos

	// Dedup rejects duplicate inbound frames.
	Dedup *dedup.Deduplicator

	mu   sync.RWMutex
	addr *net.UDPAddr // where to send return traffic; learned from inbound
	port int          // local port the client was last seen on
}

// New builds a session with a random nonce base.
func New(id uint32, cipher *crypto.Cipher, window uint32) *Session {
	s := &Session{
		ID:        id,
		Cipher:    cipher,
		Nonce64:   randUint64(),
		CreatedAt: time.Now(),
		Dedup:     dedup.New(window),
	}
	s.Touch()
	return s
}

// NextPacketID returns a fresh packet ID. Safe for concurrent use.
func (s *Session) NextPacketID() uint32 { return s.nextPacketID.Add(1) }

// Touch records activity, deferring cleanup.
func (s *Session) Touch() { s.lastSeen.Store(time.Now().UnixNano()) }

// LastSeen reports the time of the last recorded activity.
func (s *Session) LastSeen() time.Time { return time.Unix(0, s.lastSeen.Load()) }

// Idle reports how long the session has been quiet.
func (s *Session) Idle() time.Duration { return time.Since(s.LastSeen()) }

// SetPeer records where return traffic should go. Called on every inbound
// frame so the session follows a client through a NAT rebind.
func (s *Session) SetPeer(addr *net.UDPAddr, port int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addr = addr
	s.port = port
}

// Peer returns the recorded return path, or nil if none has been seen.
func (s *Session) Peer() (*net.UDPAddr, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.addr, s.port
}

// Manager owns the live sessions.
type Manager struct {
	mu       sync.RWMutex
	sessions map[uint32]*Session
	timeout  time.Duration
	window   uint32
}

// NewManager returns a Manager. A zero timeout selects DefaultTimeout; a zero
// window selects the deduplicator default.
func NewManager(timeout time.Duration, window uint32) *Manager {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Manager{
		sessions: make(map[uint32]*Session),
		timeout:  timeout,
		window:   window,
	}
}

// Get returns the session with the given ID, or nil.
func (m *Manager) Get(id uint32) *Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sessions[id]
}

// GetOrCreate returns the existing session for id, creating one if needed. The
// bool reports whether a session was created.
func (m *Manager) GetOrCreate(id uint32, cipher *crypto.Cipher) (*Session, bool) {
	m.mu.RLock()
	s := m.sessions[id]
	m.mu.RUnlock()
	if s != nil {
		return s, false
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if s = m.sessions[id]; s != nil { // lost the race
		return s, false
	}
	s = New(id, cipher, m.window)
	m.sessions[id] = s
	return s, true
}

// Delete removes a session.
func (m *Manager) Delete(id uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
}

// Len reports the number of live sessions.
func (m *Manager) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// Cleanup drops sessions idle beyond the timeout and returns how many went.
func (m *Manager) Cleanup() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	var dropped int
	for id, s := range m.sessions {
		if s.Idle() > m.timeout {
			delete(m.sessions, id)
			dropped++
		}
	}
	return dropped
}

// RunCleanup sweeps on a ticker until stop is closed.
func (m *Manager) RunCleanup(every time.Duration, stop <-chan struct{}) {
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			m.Cleanup()
		case <-stop:
			return
		}
	}
}

// NewID returns a cryptographically random, non-zero session ID. Zero is
// reserved so an uninitialised header is never mistaken for a valid session.
func NewID() uint32 {
	for {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic("session: crypto/rand failed: " + err.Error())
		}
		if id := binary.BigEndian.Uint32(b[:]); id != 0 {
			return id
		}
	}
}

func randUint64() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("session: crypto/rand failed: " + err.Error())
	}
	return binary.BigEndian.Uint64(b[:])
}
