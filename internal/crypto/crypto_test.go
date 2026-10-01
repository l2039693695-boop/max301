package crypto

import (
	"bytes"
	"testing"
)

func testCipher(t *testing.T) *Cipher {
	t.Helper()
	c, err := NewCipher(DeriveKey("correct horse battery staple"))
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}
	return c
}

func TestSealOpenRoundTrip(t *testing.T) {
	c := testCipher(t)
	plaintext := []byte("a game packet travelling to Amsterdam")
	aad := []byte("20-byte frame header")

	sealed := c.Seal(nil, 0xAABBCCDD11223344, 42, plaintext, aad)
	if len(sealed) != len(plaintext)+c.Overhead() {
		t.Fatalf("sealed length = %d, want %d", len(sealed), len(plaintext)+c.Overhead())
	}
	if bytes.Contains(sealed, plaintext) {
		t.Error("plaintext appears verbatim in ciphertext")
	}

	opened, err := c.Open(nil, 0xAABBCCDD11223344, 42, sealed, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Errorf("Open = %q, want %q", opened, plaintext)
	}
}

// Tampering with the header must be detected, which is why the header is fed
// in as additional authenticated data.
func TestOpenRejectsModifiedAAD(t *testing.T) {
	c := testCipher(t)
	sealed := c.Seal(nil, 1, 1, []byte("payload"), []byte("header-v1"))

	if _, err := c.Open(nil, 1, 1, sealed, []byte("header-v2")); err == nil {
		t.Error("Open accepted a frame whose AAD was altered")
	}
}

func TestOpenRejectsTamperingAndWrongNonce(t *testing.T) {
	c := testCipher(t)
	aad := []byte("hdr")
	sealed := c.Seal(nil, 7, 7, []byte("payload"), aad)

	t.Run("flipped ciphertext bit", func(t *testing.T) {
		bad := bytes.Clone(sealed)
		bad[0] ^= 0x01
		if _, err := c.Open(nil, 7, 7, bad, aad); err == nil {
			t.Error("Open accepted corrupted ciphertext")
		}
	})

	t.Run("wrong packet id", func(t *testing.T) {
		if _, err := c.Open(nil, 7, 8, sealed, aad); err == nil {
			t.Error("Open accepted a frame replayed under a different packet ID")
		}
	})

	t.Run("wrong nonce base", func(t *testing.T) {
		if _, err := c.Open(nil, 8, 7, sealed, aad); err == nil {
			t.Error("Open accepted a frame under a different nonce base")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		other, err := NewCipher(DeriveKey("a different password"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := other.Open(nil, 7, 7, sealed, aad); err == nil {
			t.Error("Open accepted a frame sealed under another key")
		}
	})
}

// Distinct (nonce base, packet ID) pairs must produce distinct nonces, or
// ChaCha20-Poly1305 loses its security guarantees.
func TestNonceIsUniquePerPacket(t *testing.T) {
	seen := map[[12]byte]struct{}{}
	for _, base := range []uint64{0, 1, 0xFFFFFFFFFFFFFFFF} {
		for _, id := range []uint32{0, 1, 2, 0xFFFFFFFF} {
			n := nonce(base, id)
			if _, dup := seen[n]; dup {
				t.Fatalf("nonce collision at base=%#x id=%#x", base, id)
			}
			seen[n] = struct{}{}
		}
	}
}

func TestDeriveKey(t *testing.T) {
	a := DeriveKey("password-one")
	b := DeriveKey("password-two")

	if len(a) != KeySize {
		t.Errorf("key length = %d, want %d", len(a), KeySize)
	}
	if bytes.Equal(a, b) {
		t.Error("different passwords derived the same key")
	}
	if !bytes.Equal(a, DeriveKey("password-one")) {
		t.Error("DeriveKey is not deterministic")
	}
	if bytes.Contains(a, []byte("password-one")) {
		t.Error("derived key leaks the password")
	}
}

func TestNewCipherRejectsBadKeySize(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := NewCipher(make([]byte, n)); err != ErrBadKeySize {
			t.Errorf("NewCipher(%d bytes) = %v, want %v", n, err, ErrBadKeySize)
		}
	}
}

// Seal must be usable with a caller-supplied buffer so the hot path does not
// allocate per packet.
func TestSealAppendsInPlace(t *testing.T) {
	c := testCipher(t)
	plaintext := []byte("payload")

	buf := make([]byte, 20, 20+len(plaintext)+c.Overhead())
	copy(buf, bytes.Repeat([]byte{0xFF}, 20)) // pretend header
	out := c.Seal(buf, 1, 1, plaintext, buf[:20])

	if !bytes.Equal(out[:20], bytes.Repeat([]byte{0xFF}, 20)) {
		t.Error("Seal overwrote the caller's header bytes")
	}
	opened, err := c.Open(nil, 1, 1, out[20:], out[:20])
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Errorf("round trip = %q, want %q", opened, plaintext)
	}
}

func BenchmarkSeal(b *testing.B) {
	c, _ := NewCipher(DeriveKey("bench"))
	plaintext := bytes.Repeat([]byte{0x5A}, 200) // typical game packet
	aad := make([]byte, 20)
	buf := make([]byte, 0, 20+len(plaintext)+c.Overhead())

	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.Seal(buf[:0], uint64(i), uint32(i), plaintext, aad)
	}
}
