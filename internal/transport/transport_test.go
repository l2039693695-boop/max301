package transport

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestListenReportsEphemeralPort(t *testing.T) {
	// Passing 0 asks the kernel for a port; callers need the real number to
	// tell a peer where to send.
	c, err := Listen("127.0.0.1", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if c.Port() == 0 {
		t.Error("Port = 0; the bound port was not recorded")
	}
	if got := c.LocalAddr().(*net.UDPAddr).Port; got != c.Port() {
		t.Errorf("Port = %d but the socket is bound to %d", c.Port(), got)
	}
}

func TestListenMultiAndSend(t *testing.T) {
	ln, err := ListenMulti("127.0.0.1", []int{0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ports := ln.Ports()
	if len(ports) != 3 {
		t.Fatalf("Ports returned %d entries, want 3", len(ports))
	}
	for i, p := range ports {
		if p == 0 {
			t.Errorf("port %d was reported as 0", i)
		}
	}

	mp, err := NewMultiPath("127.0.0.1", ports)
	if err != nil {
		t.Fatal(err)
	}
	defer mp.Close()

	payload := []byte("hello")
	if err := mp.SendRedundant(payload, 3); err != nil {
		t.Fatalf("SendRedundant: %v", err)
	}

	// All three copies should arrive, one per port.
	seen := map[int]bool{}
	for i := 0; i < 3; i++ {
		select {
		case pkt := <-ln.Recv():
			if !bytes.Equal(pkt.Data, payload) {
				t.Errorf("copy %d = %q, want %q", i, pkt.Data, payload)
			}
			seen[pkt.Port] = true
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d of 3 copies arrived", i)
		}
	}
	if len(seen) != 3 {
		t.Errorf("copies landed on %d distinct ports, want 3", len(seen))
	}
}

// Redundancy above the path count must not panic or silently send nothing.
func TestSendRedundantClampsCount(t *testing.T) {
	ln, err := ListenMulti("127.0.0.1", []int{0, 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mp, err := NewMultiPath("127.0.0.1", ln.Ports())
	if err != nil {
		t.Fatal(err)
	}
	defer mp.Close()

	for _, count := range []int{-1, 0, 1, 2, 99} {
		if err := mp.SendRedundant([]byte("x"), count); err != nil {
			t.Errorf("SendRedundant(count=%d): %v", count, err)
		}
	}

	// Drain whatever arrived; the point is that none of the calls failed.
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case <-ln.Recv():
		case <-deadline:
			return
		}
	}
}

// Copies must rotate across paths so load spreads rather than always hitting
// the first socket.
func TestSendRedundantRotatesPaths(t *testing.T) {
	ln, err := ListenMulti("127.0.0.1", []int{0, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mp, err := NewMultiPath("127.0.0.1", ln.Ports())
	if err != nil {
		t.Fatal(err)
	}
	defer mp.Close()

	const sends = 8
	for i := 0; i < sends; i++ {
		if err := mp.SendRedundant([]byte{byte(i)}, 1); err != nil {
			t.Fatal(err)
		}
	}

	seen := map[int]int{}
	for i := 0; i < sends; i++ {
		select {
		case pkt := <-ln.Recv():
			seen[pkt.Port]++
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d of %d single copies arrived", i, sends)
		}
	}
	if len(seen) < 2 {
		t.Errorf("single copies used %d port(s); they should rotate", len(seen))
	}
}

func TestMultiPathReturnTraffic(t *testing.T) {
	ln, err := ListenMulti("127.0.0.1", []int{0})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mp, err := NewMultiPath("127.0.0.1", ln.Ports())
	if err != nil {
		t.Fatal(err)
	}
	defer mp.Close()

	if err := mp.SendRedundant([]byte("request"), 1); err != nil {
		t.Fatal(err)
	}

	var req Packet
	select {
	case req = <-ln.Recv():
	case <-time.After(3 * time.Second):
		t.Fatal("request did not arrive")
	}

	// Reply from the port the request landed on.
	if err := ln.Send([]byte("response"), req.Addr, req.Port); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case pkt := <-mp.Recv():
		if !bytes.Equal(pkt.Data, []byte("response")) {
			t.Errorf("reply = %q, want \"response\"", pkt.Data)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reply did not arrive on the sending socket")
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	ln, err := ListenMulti("127.0.0.1", []int{0})
	if err != nil {
		t.Fatal(err)
	}
	mp, err := NewMultiPath("127.0.0.1", ln.Ports())
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if err := mp.Close(); err != nil {
			t.Errorf("MultiPathConn.Close call %d: %v", i+1, err)
		}
		if err := ln.Close(); err != nil {
			t.Errorf("Listener.Close call %d: %v", i+1, err)
		}
	}
}

func TestSendAfterCloseFails(t *testing.T) {
	ln, _ := ListenMulti("127.0.0.1", []int{0})
	mp, err := NewMultiPath("127.0.0.1", ln.Ports())
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	mp.Close()

	if err := mp.SendRedundant([]byte("x"), 1); err == nil {
		t.Error("SendRedundant succeeded after Close")
	}
}

func TestConstructorRejectsBadInput(t *testing.T) {
	if _, err := ListenMulti("127.0.0.1", nil); err == nil {
		t.Error("ListenMulti accepted an empty port list")
	}
	if _, err := NewMultiPath("", []int{1}); err == nil {
		t.Error("NewMultiPath accepted an empty host")
	}
	if _, err := NewMultiPath("127.0.0.1", nil); err == nil {
		t.Error("NewMultiPath accepted an empty port list")
	}
}

func TestIsTemporary(t *testing.T) {
	if IsTemporary(net.ErrClosed) {
		t.Error("IsTemporary(net.ErrClosed) = true; a closed socket is permanent")
	}
	if !IsTemporary(nil) {
		t.Error("IsTemporary(nil) = false")
	}
}
