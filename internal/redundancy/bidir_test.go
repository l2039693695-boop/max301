package redundancy

import (
	"bytes"
	"testing"

	"max301/internal/crypto"
	"max301/internal/protocol"
	"max301/internal/session"
	"max301/pkg/types"
)

// Both ends of a tunnel seal frames for the same session ID. Each end holds its
// own session object with its own random nonce base, so the two directions must
// not collide in nonce space even though their packet IDs both start at 1.
func TestBidirectionalNoncesDoNotCollide(t *testing.T) {
	cipher, err := crypto.NewCipher(crypto.DeriveKey(testPassword))
	if err != nil {
		t.Fatal(err)
	}

	id := session.NewID()
	client := session.New(id, cipher, 1024) // outbound side
	exit := session.New(id, cipher, 1024)   // the far end, same session ID

	if client.Nonce64 == exit.Nonce64 {
		t.Fatal("the two ends drew the same nonce base; nonces would repeat")
	}

	// Sealing the same plaintext under the same packet ID at both ends must
	// produce different ciphertext, which is what proves the nonces differ.
	const packetID = 1
	aad := make([]byte, protocol.HeaderSize)
	plaintext := []byte("identical payload")

	a := client.Cipher.Seal(nil, client.Nonce64, packetID, plaintext, aad)
	b := exit.Cipher.Seal(nil, exit.Nonce64, packetID, plaintext, aad)

	if bytes.Equal(a, b) {
		t.Error("both directions produced identical ciphertext for packet ID 1")
	}
}

// Each direction needs its own deduplicator. Sharing one would let a reply
// evict a request that happened to carry the same packet ID.
func TestPerDirectionDedupIsIndependent(t *testing.T) {
	cipher, _ := crypto.NewCipher(crypto.DeriveKey(testPassword))
	id := session.NewID()

	inbound := session.New(id, cipher, 1024)
	outbound := session.New(id, cipher, 1024)

	for pid := uint32(1); pid <= 10; pid++ {
		if inbound.Dedup.Seen(pid) {
			t.Fatalf("inbound rejected fresh packet %d", pid)
		}
		if outbound.Dedup.Seen(pid) {
			t.Fatalf("outbound rejected packet %d after inbound saw it", pid)
		}
	}
}

// Packet IDs must stay unique under concurrent senders, since several NAT flows
// on the exit node share one session.
func TestConcurrentPacketIDsAreUnique(t *testing.T) {
	cipher, _ := crypto.NewCipher(crypto.DeriveKey(testPassword))
	sess := session.New(session.NewID(), cipher, 65536)

	const (
		workers = 8
		each    = 500
	)
	ids := make(chan uint32, workers*each)
	done := make(chan struct{})

	for w := 0; w < workers; w++ {
		go func() {
			for i := 0; i < each; i++ {
				ids <- sess.NextPacketID()
			}
			done <- struct{}{}
		}()
	}
	for w := 0; w < workers; w++ {
		<-done
	}
	close(ids)

	seen := make(map[uint32]bool, workers*each)
	for id := range ids {
		if seen[id] {
			t.Fatalf("packet ID %d was handed out twice", id)
		}
		seen[id] = true
	}
	if len(seen) != workers*each {
		t.Errorf("got %d distinct IDs, want %d", len(seen), workers*each)
	}
}

func TestStatsCountDuplicatesAndInvalid(t *testing.T) {
	sender, recv, ln := testSetup(t, 2)
	stats := &types.Stats{}
	recv.stats = stats

	if err := sender.Send([]byte("payload"), protocol.PriorityGame); err != nil {
		t.Fatal(err)
	}
	first := <-ln.Recv()
	second := <-ln.Recv()

	buf := make([]byte, 0, protocol.MaxFrameSize)
	recv.Recv(first.Data, buf)
	recv.Recv(second.Data, buf)

	garbage := bytes.Repeat([]byte{0xFF}, 64) // wrong version byte
	recv.Recv(garbage, buf)

	s := stats.Snapshot()
	if s.Duplicate != 1 {
		t.Errorf("Duplicate = %d, want 1", s.Duplicate)
	}
	if s.Invalid != 1 {
		t.Errorf("Invalid = %d, want 1", s.Invalid)
	}
	if s.RxPackets != 3 {
		t.Errorf("RxPackets = %d, want 3", s.RxPackets)
	}
}
