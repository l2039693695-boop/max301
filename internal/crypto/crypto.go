// Package crypto wraps ChaCha20-Poly1305 for Max301 frames.
//
// Nonce construction: the 12-byte AEAD nonce is the 8-byte per-session random
// base concatenated with the 4-byte PacketID. Since PacketID is unique within
// a session and the base is random per session, nonces never repeat for a
// given key -- which ChaCha20-Poly1305 requires for security.
package crypto

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// KeySize is the ChaCha20-Poly1305 key length.
const KeySize = chacha20poly1305.KeySize // 32

// ErrBadKeySize is returned by NewCipher for a key of the wrong length.
var ErrBadKeySize = errors.New("crypto: key must be 32 bytes")

// Cipher seals and opens frame payloads. It is safe for concurrent use.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher builds a Cipher from a 32-byte key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, ErrBadKeySize
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// hkdfInfo binds derived keys to this protocol and version, so the same
// password used elsewhere yields a different key here.
const hkdfInfo = "max301/v1 payload key"

// DeriveKey turns a shared password into a 32-byte key with HKDF-SHA256.
//
// The design sketch proposed a byte-wise XOR over the password. That is
// trivially invertible and keeps the key's entropy at the password's length,
// so HKDF is used instead -- same call signature, no added dependency.
//
// There is no salt: every node must derive the identical key from the config
// password alone. The password is the only secret, so choose a long one.
func DeriveKey(password string) []byte {
	key := make([]byte, KeySize)
	r := hkdf.New(sha256.New, []byte(password), nil, []byte(hkdfInfo))
	if _, err := io.ReadFull(r, key); err != nil {
		// HKDF cannot fail for a 32-byte read from SHA-256.
		panic("crypto: hkdf failed: " + err.Error())
	}
	return key
}

// nonce assembles the 12-byte AEAD nonce from the session base and packet ID.
func nonce(nonce64 uint64, packetID uint32) [chacha20poly1305.NonceSize]byte {
	var n [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint64(n[0:8], nonce64)
	binary.BigEndian.PutUint32(n[8:12], packetID)
	return n
}

// Seal encrypts plaintext and appends the result to dst, returning the
// extended slice. aad carries the cleartext frame header so that tampering
// with the session or packet ID is detected at open time.
//
// Passing a dst with spare capacity (for example the frame buffer right after
// the header) avoids an allocation per packet.
func (c *Cipher) Seal(dst []byte, nonce64 uint64, packetID uint32, plaintext, aad []byte) []byte {
	n := nonce(nonce64, packetID)
	return c.aead.Seal(dst, n[:], plaintext, aad)
}

// Open authenticates and decrypts ciphertext, appending the plaintext to dst
// and returning the extended slice. It fails if aad does not match the value
// used at seal time.
func (c *Cipher) Open(dst []byte, nonce64 uint64, packetID uint32, ciphertext, aad []byte) ([]byte, error) {
	n := nonce(nonce64, packetID)
	return c.aead.Open(dst, n[:], ciphertext, aad)
}

// Overhead is the number of bytes Seal adds beyond the plaintext length.
func (c *Cipher) Overhead() int { return c.aead.Overhead() }
