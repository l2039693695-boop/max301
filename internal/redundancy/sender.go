// Package redundancy turns payloads into wire frames and back.
//
// Sending: build the header, seal the payload with the header as AAD, then emit
// N copies across distinct paths. There is no retransmission and no reorder
// buffer -- for a game, a packet that needs a round trip to recover has already
// missed its tick.
//
// Receiving: parse the header, drop duplicates, authenticate, hand back the
// plaintext.
package redundancy

import (
	"errors"
	"sync"

	"max301/internal/protocol"
	"max301/internal/session"
	"max301/internal/transport"
	"max301/pkg/types"
)

// Redundancy returns the number of copies to send for a priority class, given
// the configured base level. Game traffic gets the configured level; critical
// traffic gets one extra; bulk traffic gets a single copy so a download cannot
// multiply itself across the link.
func Redundancy(base int, priority byte) int {
	if base < 1 {
		base = 1
	}
	switch priority {
	case protocol.PriorityCritical:
		return base + 1
	case protocol.PriorityGame:
		return base
	default:
		return 1
	}
}

// Sender seals payloads and writes them to a MultiPathConn.
type Sender struct {
	session   *session.Session
	transport *transport.MultiPathConn
	base      int
	stats     *types.Stats

	bufPool sync.Pool
}

// NewSender returns a Sender. base is the default number of copies for game
// traffic.
func NewSender(s *session.Session, t *transport.MultiPathConn, base int, stats *types.Stats) *Sender {
	if stats == nil {
		stats = &types.Stats{}
	}
	return &Sender{
		session:   s,
		transport: t,
		base:      base,
		stats:     stats,
		bufPool: sync.Pool{New: func() any {
			b := make([]byte, 0, protocol.MaxFrameSize)
			return &b
		}},
	}
}

// ErrPayloadTooLarge is returned when a payload plus overhead exceeds the
// maximum frame size.
var ErrPayloadTooLarge = errors.New("redundancy: payload exceeds maximum frame size")

// Send seals payload and emits it with the redundancy implied by priority.
func (s *Sender) Send(payload []byte, priority byte) error {
	return s.send(payload, priority, protocol.TypeData)
}

// SendControl emits a control or heartbeat frame.
func (s *Sender) SendControl(payload []byte, typ byte) error {
	return s.send(payload, protocol.PriorityCritical, typ)
}

func (s *Sender) send(payload []byte, priority, typ byte) error {
	if len(payload)+protocol.Overhead > protocol.MaxFrameSize {
		return ErrPayloadTooLarge
	}

	f := protocol.Frame{
		Version:   protocol.Version,
		SessionID: s.session.ID,
		PacketID:  s.session.NextPacketID(),
		Nonce:     s.session.Nonce64,
	}
	f.SetPacketType(typ)
	f.SetPriority(priority)
	f.SetLast(true) // the MVP never fragments

	bufp := s.bufPool.Get().(*[]byte)
	defer s.bufPool.Put(bufp)

	buf := (*bufp)[:protocol.HeaderSize]
	f.EncodeHeader(buf)

	// The header doubles as additional authenticated data, so a relay cannot
	// rewrite the session or packet ID without the exit node noticing.
	frame := s.session.Cipher.Seal(buf, f.Nonce, f.PacketID, payload, buf[:protocol.HeaderSize])
	*bufp = frame[:0]

	copies := Redundancy(s.base, priority)
	if err := s.transport.SendRedundant(frame, copies); err != nil {
		return err
	}

	s.stats.TxPackets.Add(1)
	s.stats.TxBytes.Add(uint64(len(frame)))
	return nil
}
