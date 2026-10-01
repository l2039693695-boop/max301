package redundancy

import (
	"bytes"
	"testing"

	"max301/internal/crypto"
	"max301/internal/protocol"
	"max301/internal/session"
	"max301/internal/transport"
	"max301/pkg/types"
)

const testPassword = "max301-test-password"

func testSetup(t *testing.T, base int) (*Sender, *Receiver, *transport.Listener) {
	t.Helper()

	cipher, err := crypto.NewCipher(crypto.DeriveKey(testPassword))
	if err != nil {
		t.Fatal(err)
	}

	// A listener on ephemeral ports stands in for the next hop.
	ln, err := transport.ListenMulti("127.0.0.1", []int{0, 0})
	if err != nil {
		t.Fatal(err)
	}

	mp, err := transport.NewMultiPath("127.0.0.1", ln.Ports())
	if err != nil {
		ln.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { mp.Close(); ln.Close() })

	sendSess := session.New(session.NewID(), cipher, 4096)
	sender := NewSender(sendSess, mp, base, &types.Stats{})
	recv := NewMultiReceiver(session.NewManager(0, 4096), cipher, &types.Stats{})
	return sender, recv, ln
}

func TestSendRecvRoundTrip(t *testing.T) {
	sender, recv, ln := testSetup(t, 1)

	payload := []byte("an IP packet bound for a game server")
	if err := sender.Send(payload, protocol.PriorityGame); err != nil {
		t.Fatalf("Send: %v", err)
	}

	pkt := <-ln.Recv()
	got, err := recv.Recv(pkt.Data, make([]byte, 0, protocol.MaxFrameSize))
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Errorf("payload = %q, want %q", got.Payload, payload)
	}
	if got.Priority != protocol.PriorityGame {
		t.Errorf("priority = %d, want %d", got.Priority, protocol.PriorityGame)
	}
	if got.Type != protocol.TypeData {
		t.Errorf("type = %d, want %d", got.Type, protocol.TypeData)
	}
}

// The wire overhead must stay at the documented 36 bytes, since the MTU budget
// depends on it.
func TestWireOverheadIs36Bytes(t *testing.T) {
	sender, _, ln := testSetup(t, 1)

	payload := bytes.Repeat([]byte{0x7E}, 200)
	if err := sender.Send(payload, protocol.PriorityGame); err != nil {
		t.Fatal(err)
	}
	pkt := <-ln.Recv()

	if overhead := len(pkt.Data) - len(payload); overhead != protocol.Overhead {
		t.Errorf("wire overhead = %d bytes, want %d", overhead, protocol.Overhead)
	}
}

// Redundant copies must reach the next hop, and the receiver must admit only
// the first.
func TestRedundantCopiesArriveAndDeduplicate(t *testing.T) {
	sender, recv, ln := testSetup(t, 2)

	payload := []byte("sent twice")
	if err := sender.Send(payload, protocol.PriorityGame); err != nil {
		t.Fatal(err)
	}

	first := <-ln.Recv()
	second := <-ln.Recv()
	if !bytes.Equal(first.Data, second.Data) {
		t.Fatal("the two copies differ on the wire")
	}
	if first.Port == second.Port {
		t.Error("both copies used the same port; they should span paths")
	}

	buf := make([]byte, 0, protocol.MaxFrameSize)
	if _, err := recv.Recv(first.Data, buf); err != nil {
		t.Fatalf("first copy rejected: %v", err)
	}
	if _, err := recv.Recv(second.Data, buf); err != ErrDuplicate {
		t.Errorf("second copy gave %v, want ErrDuplicate", err)
	}
}

func TestRecvRejectsTamperedHeader(t *testing.T) {
	sender, recv, ln := testSetup(t, 1)

	if err := sender.Send([]byte("payload"), protocol.PriorityGame); err != nil {
		t.Fatal(err)
	}
	pkt := <-ln.Recv()

	// Rewrite the session ID. Because the header is authenticated as AAD, this
	// must fail rather than silently route elsewhere.
	tampered := bytes.Clone(pkt.Data)
	tampered[4] ^= 0xFF
	if _, err := recv.Recv(tampered, make([]byte, 0, protocol.MaxFrameSize)); err == nil {
		t.Error("Recv accepted a frame whose session ID was rewritten")
	}
}

func TestRecvRejectsWrongPassword(t *testing.T) {
	sender, _, ln := testSetup(t, 1)

	other, err := crypto.NewCipher(crypto.DeriveKey("a different password"))
	if err != nil {
		t.Fatal(err)
	}
	stranger := NewMultiReceiver(session.NewManager(0, 4096), other, &types.Stats{})

	if err := sender.Send([]byte("payload"), protocol.PriorityGame); err != nil {
		t.Fatal(err)
	}
	pkt := <-ln.Recv()

	if _, err := stranger.Recv(pkt.Data, make([]byte, 0, protocol.MaxFrameSize)); err == nil {
		t.Error("Recv accepted a frame sealed under another password")
	}
}

func TestRedundancyLevels(t *testing.T) {
	tests := []struct {
		base     int
		priority byte
		want     int
	}{
		{2, protocol.PriorityGame, 2},
		{2, protocol.PriorityCritical, 3},
		{2, protocol.PriorityNormal, 1}, // bulk must not be multiplied
		{1, protocol.PriorityGame, 1},
		{0, protocol.PriorityGame, 1}, // clamped
		{3, protocol.PriorityCritical, 4},
	}
	for _, tc := range tests {
		if got := Redundancy(tc.base, tc.priority); got != tc.want {
			t.Errorf("Redundancy(base=%d, prio=%d) = %d, want %d",
				tc.base, tc.priority, got, tc.want)
		}
	}
}

// Each packet must carry a fresh ID so the deduplicator does not discard
// distinct packets.
func TestPacketIDsIncrement(t *testing.T) {
	sender, recv, ln := testSetup(t, 1)

	const n = 50
	for i := 0; i < n; i++ {
		if err := sender.Send([]byte{byte(i)}, protocol.PriorityGame); err != nil {
			t.Fatal(err)
		}
	}

	buf := make([]byte, 0, protocol.MaxFrameSize)
	seen := map[uint32]bool{}
	for i := 0; i < n; i++ {
		pkt := <-ln.Recv()
		res, err := recv.Recv(pkt.Data, buf)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if seen[res.PacketID] {
			t.Fatalf("packet ID %d reused", res.PacketID)
		}
		seen[res.PacketID] = true
	}
}

func TestSendRejectsOversizedPayload(t *testing.T) {
	sender, _, _ := testSetup(t, 1)
	huge := make([]byte, protocol.MaxFrameSize)
	if err := sender.Send(huge, protocol.PriorityGame); err != ErrPayloadTooLarge {
		t.Errorf("Send(oversized) = %v, want ErrPayloadTooLarge", err)
	}
}

func TestControlFrameTypePreserved(t *testing.T) {
	sender, recv, ln := testSetup(t, 1)

	if err := sender.SendControl(nil, protocol.TypeHeartbeat); err != nil {
		t.Fatal(err)
	}
	pkt := <-ln.Recv()
	res, err := recv.Recv(pkt.Data, make([]byte, 0, protocol.MaxFrameSize))
	if err != nil {
		t.Fatal(err)
	}
	if res.Type != protocol.TypeHeartbeat {
		t.Errorf("type = %d, want TypeHeartbeat(%d)", res.Type, protocol.TypeHeartbeat)
	}
}
