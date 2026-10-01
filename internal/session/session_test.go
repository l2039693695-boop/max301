package session

import (
	"net"
	"sync"
	"testing"
	"time"

	"max301/internal/crypto"
)

func testCipher(t *testing.T) *crypto.Cipher {
	t.Helper()
	c, err := crypto.NewCipher(crypto.DeriveKey("session-test-password"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Many inbound ports race to create the session for a new client; exactly one
// object must win, or the two halves would hold separate nonce bases and
// deduplicators.
func TestGetOrCreateIsRaceFree(t *testing.T) {
	m := NewManager(time.Minute, 1024)
	cipher := testCipher(t)
	id := NewID()

	const workers = 16
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		got     []*Session
		created int
	)
	start := make(chan struct{})

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s, isNew := m.GetOrCreate(id, cipher)
			mu.Lock()
			got = append(got, s)
			if isNew {
				created++
			}
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if created != 1 {
		t.Errorf("GetOrCreate reported %d creations, want 1", created)
	}
	for i, s := range got {
		if s != got[0] {
			t.Fatalf("worker %d received a different session object", i)
		}
	}
	if m.Len() != 1 {
		t.Errorf("Len = %d, want 1", m.Len())
	}
}

func TestGetReturnsNilForUnknownID(t *testing.T) {
	m := NewManager(time.Minute, 1024)
	if s := m.Get(12345); s != nil {
		t.Errorf("Get on an unknown ID returned %v, want nil", s)
	}
}

func TestCleanupDropsIdleSessions(t *testing.T) {
	m := NewManager(50*time.Millisecond, 1024)
	cipher := testCipher(t)

	stale, _ := m.GetOrCreate(NewID(), cipher)
	fresh, _ := m.GetOrCreate(NewID(), cipher)

	time.Sleep(80 * time.Millisecond)
	fresh.Touch() // keeps this one alive

	if dropped := m.Cleanup(); dropped != 1 {
		t.Errorf("Cleanup dropped %d sessions, want 1", dropped)
	}
	if m.Get(stale.ID) != nil {
		t.Error("the idle session survived cleanup")
	}
	if m.Get(fresh.ID) == nil {
		t.Error("the active session was dropped")
	}
}

func TestDelete(t *testing.T) {
	m := NewManager(time.Minute, 1024)
	s, _ := m.GetOrCreate(NewID(), testCipher(t))

	m.Delete(s.ID)
	if m.Get(s.ID) != nil {
		t.Error("Get returned a deleted session")
	}
	if m.Len() != 0 {
		t.Errorf("Len = %d after Delete, want 0", m.Len())
	}
}

// A client behind a NAT can change source port mid-session; replies must follow
// it rather than going to the stale address.
func TestSetPeerFollowsAddressChange(t *testing.T) {
	s := New(NewID(), testCipher(t), 1024)

	if addr, _ := s.Peer(); addr != nil {
		t.Error("a new session should have no peer recorded")
	}

	first := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1111}
	s.SetPeer(first, 20001)
	if addr, port := s.Peer(); addr != first || port != 20001 {
		t.Errorf("Peer = %v/%d, want %v/20001", addr, port, first)
	}

	second := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 2222}
	s.SetPeer(second, 20002)
	if addr, port := s.Peer(); addr != second || port != 20002 {
		t.Errorf("Peer = %v/%d after rebind, want %v/20002", addr, port, second)
	}
}

func TestNewIDIsNeverZero(t *testing.T) {
	// Zero is reserved so an uninitialised header is never a valid session.
	for i := 0; i < 1000; i++ {
		if NewID() == 0 {
			t.Fatal("NewID returned 0")
		}
	}
}

func TestNewIDIsRandom(t *testing.T) {
	seen := map[uint32]bool{}
	for i := 0; i < 1000; i++ {
		id := NewID()
		if seen[id] {
			t.Fatalf("NewID repeated %#x within 1000 draws", id)
		}
		seen[id] = true
	}
}

// Each session needs its own nonce base, otherwise two clients sharing the key
// would reuse nonces at the same packet ID.
func TestNonceBasesDiffer(t *testing.T) {
	cipher := testCipher(t)
	seen := map[uint64]bool{}
	for i := 0; i < 500; i++ {
		s := New(NewID(), cipher, 128)
		if seen[s.Nonce64] {
			t.Fatalf("nonce base %#x reused across sessions", s.Nonce64)
		}
		seen[s.Nonce64] = true
	}
}

func TestIdleTracksTouch(t *testing.T) {
	s := New(NewID(), testCipher(t), 128)
	time.Sleep(30 * time.Millisecond)

	before := s.Idle()
	if before < 20*time.Millisecond {
		t.Errorf("Idle = %s, want at least 20ms", before)
	}
	s.Touch()
	if after := s.Idle(); after > before {
		t.Errorf("Idle = %s after Touch, want less than %s", after, before)
	}
}

func TestRunCleanupStops(t *testing.T) {
	m := NewManager(10*time.Millisecond, 128)
	m.GetOrCreate(NewID(), testCipher(t))

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		m.RunCleanup(5*time.Millisecond, stop)
		close(done)
	}()

	time.Sleep(60 * time.Millisecond)
	if m.Len() != 0 {
		t.Errorf("Len = %d, want the idle session swept", m.Len())
	}

	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("RunCleanup did not return after stop was closed")
	}
}

// Several NAT flows on the exit node share one session and allocate packet IDs
// concurrently.
func TestConcurrentManagerAccess(t *testing.T) {
	m := NewManager(time.Minute, 4096)
	cipher := testCipher(t)
	ids := make([]uint32, 20)
	for i := range ids {
		ids[i] = NewID()
	}

	var wg sync.WaitGroup
	for w := 0; w < 12; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				id := ids[(w+i)%len(ids)]
				s, _ := m.GetOrCreate(id, cipher)
				s.NextPacketID()
				s.Touch()
				m.Get(id)
				m.Len()
			}
		}(w)
	}
	wg.Wait()

	if m.Len() != len(ids) {
		t.Errorf("Len = %d, want %d", m.Len(), len(ids))
	}
}
