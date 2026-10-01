// Package protocol defines the Max301 wire format.
//
// A frame on the wire looks like this:
//
//	offset  size  field
//	0       1     Version
//	1       1     Flags
//	2       2     Reserved (must be zero)
//	4       4     SessionID   (big endian)
//	8       4     PacketID    (big endian, used for dedup)
//	12      8     Nonce       (big endian, per-session random base)
//	20      N     Ciphertext  (AEAD sealed payload)
//	20+N    16    AuthTag     (Poly1305, appended by Seal)
//
// The 20-byte header travels in the clear so that relays can deduplicate and
// forward without holding the payload key, but it is fed to the AEAD as
// additional authenticated data, so the exit node still detects any tampering.
package protocol

import (
	"encoding/binary"
	"errors"
)

const (
	// Version is the protocol version this build speaks.
	Version byte = 1

	// HeaderSize is the fixed cleartext header length.
	HeaderSize = 20
	// TagSize is the Poly1305 authentication tag length.
	TagSize = 16
	// Overhead is the total per-packet cost on the wire.
	Overhead = HeaderSize + TagSize // 36

	// MaxFrameSize bounds a datagram we are willing to parse. Well above the
	// 1400-byte tunnel MTU plus overhead, but small enough to use as a
	// fixed read buffer.
	MaxFrameSize = 2048
)

// Packet types, carried in Flags bits 0-1.
//
// Note: the design sketch allotted a single bit to the type field while
// defining three types. Two bits are used here so heartbeat is representable.
const (
	TypeData      byte = 0
	TypeControl   byte = 1
	TypeHeartbeat byte = 2
)

// Priorities, carried in Flags bits 2-3. Priority selects how many redundant
// copies the sender emits; it is not a queueing discipline.
const (
	PriorityNormal   byte = 0
	PriorityGame     byte = 1
	PriorityCritical byte = 2
)

// Flags bit layout.
const (
	flagTypeShift     = 0
	flagTypeMask      = 0x03
	flagPriorityShift = 2
	flagPriorityMask  = 0x03
	flagLast          = 1 << 4
)

// Errors returned by DecodeHeader.
var (
	ErrShortFrame   = errors.New("protocol: frame shorter than header")
	ErrBadVersion   = errors.New("protocol: unsupported version")
	ErrFrameTooBig  = errors.New("protocol: frame exceeds maximum size")
	ErrShortPayload = errors.New("protocol: frame carries no authentication tag")
)

// Frame is a decoded header plus a reference to its payload. Payload aliases
// the caller's buffer; it is not copied.
type Frame struct {
	Version   byte
	Flags     byte
	SessionID uint32
	PacketID  uint32
	Nonce     uint64
	Payload   []byte
}

// EncodeHeader writes the header into buf and returns the number of bytes
// written. buf must be at least HeaderSize long.
func (f *Frame) EncodeHeader(buf []byte) int {
	buf[0] = f.Version
	buf[1] = f.Flags
	buf[2] = 0
	buf[3] = 0
	binary.BigEndian.PutUint32(buf[4:8], f.SessionID)
	binary.BigEndian.PutUint32(buf[8:12], f.PacketID)
	binary.BigEndian.PutUint64(buf[12:20], f.Nonce)
	return HeaderSize
}

// DecodeHeader parses a header from buf and points Payload at the remainder.
// The payload is left encrypted; the caller decrypts it.
func (f *Frame) DecodeHeader(buf []byte) error {
	if len(buf) < HeaderSize {
		return ErrShortFrame
	}
	if len(buf) > MaxFrameSize {
		return ErrFrameTooBig
	}
	if buf[0] != Version {
		return ErrBadVersion
	}
	if len(buf) < HeaderSize+TagSize {
		return ErrShortPayload
	}
	f.Version = buf[0]
	f.Flags = buf[1]
	f.SessionID = binary.BigEndian.Uint32(buf[4:8])
	f.PacketID = binary.BigEndian.Uint32(buf[8:12])
	f.Nonce = binary.BigEndian.Uint64(buf[12:20])
	f.Payload = buf[HeaderSize:]
	return nil
}

// PacketType reports the frame type.
func (f *Frame) PacketType() byte { return (f.Flags >> flagTypeShift) & flagTypeMask }

// SetPacketType sets the frame type.
func (f *Frame) SetPacketType(t byte) {
	f.Flags = f.Flags&^(flagTypeMask<<flagTypeShift) | (t&flagTypeMask)<<flagTypeShift
}

// Priority reports the redundancy class of the frame.
func (f *Frame) Priority() byte { return (f.Flags >> flagPriorityShift) & flagPriorityMask }

// SetPriority sets the redundancy class of the frame.
func (f *Frame) SetPriority(p byte) {
	f.Flags = f.Flags&^(flagPriorityMask<<flagPriorityShift) | (p&flagPriorityMask)<<flagPriorityShift
}

// IsLast reports whether this is the final fragment of a datagram. The MVP
// never fragments, so senders always set it.
func (f *Frame) IsLast() bool { return f.Flags&flagLast != 0 }

// SetLast sets the final-fragment flag.
func (f *Frame) SetLast(last bool) {
	if last {
		f.Flags |= flagLast
	} else {
		f.Flags &^= flagLast
	}
}
