package redundancy

import (
	"errors"

	"max301/internal/crypto"
	"max301/internal/protocol"
	"max301/internal/session"
	"max301/pkg/types"
)

// Receiver parses, deduplicates and opens inbound frames.
type Receiver struct {
	cipher *crypto.Cipher
	stats  *types.Stats

	// sessions is set on nodes that serve many clients; single-session nodes
	// use fixed instead.
	sessions *session.Manager
	fixed    *session.Session
}

// NewReceiver returns a Receiver for a node with one upstream session.
func NewReceiver(s *session.Session, cipher *crypto.Cipher, stats *types.Stats) *Receiver {
	if stats == nil {
		stats = &types.Stats{}
	}
	return &Receiver{cipher: cipher, stats: stats, fixed: s}
}

// NewMultiReceiver returns a Receiver that looks sessions up by ID, creating
// them on first sight.
func NewMultiReceiver(m *session.Manager, cipher *crypto.Cipher, stats *types.Stats) *Receiver {
	if stats == nil {
		stats = &types.Stats{}
	}
	return &Receiver{cipher: cipher, stats: stats, sessions: m}
}

// ErrDuplicate reports a frame already seen. Callers usually ignore it.
var ErrDuplicate = errors.New("redundancy: duplicate frame")

// Result is a successfully opened frame.
type Result struct {
	Payload   []byte
	SessionID uint32
	PacketID  uint32
	Priority  byte
	Type      byte
	Session   *session.Session
}

// Recv parses and opens one raw datagram. dst, when it has capacity, receives
// the plaintext and avoids an allocation.
//
// A duplicate yields ErrDuplicate. Note the order: dedup runs before the AEAD
// check, so the common case of a redundant copy costs a bitmap lookup rather
// than a decryption. The payload is still authenticated before anything is
// returned, so an attacker can at most make a frame be dropped -- which they
// could already do by dropping the packet.
func (r *Receiver) Recv(raw []byte, dst []byte) (*Result, error) {
	r.stats.RxPackets.Add(1)
	r.stats.RxBytes.Add(uint64(len(raw)))

	var f protocol.Frame
	if err := f.DecodeHeader(raw); err != nil {
		r.stats.Invalid.Add(1)
		return nil, err
	}

	sess := r.fixed
	if sess == nil {
		var created bool
		sess, created = r.sessions.GetOrCreate(f.SessionID, r.cipher)
		_ = created
	}

	if sess.Dedup.Seen(f.PacketID) {
		r.stats.Duplicate.Add(1)
		return nil, ErrDuplicate
	}

	plaintext, err := sess.Cipher.Open(dst[:0], f.Nonce, f.PacketID, f.Payload, raw[:protocol.HeaderSize])
	if err != nil {
		r.stats.Invalid.Add(1)
		return nil, err
	}

	sess.Touch()
	return &Result{
		Payload:   plaintext,
		SessionID: f.SessionID,
		PacketID:  f.PacketID,
		Priority:  f.Priority(),
		Type:      f.PacketType(),
		Session:   sess,
	}, nil
}
