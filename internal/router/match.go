// Package router inspects IP packets and decides where they go.
package router

import (
	"encoding/binary"
	"errors"
	"net"
)

// IP protocol numbers.
const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
)

// Errors returned when parsing an inner packet.
var (
	ErrTooShort    = errors.New("router: packet shorter than an IPv4 header")
	ErrNotIPv4     = errors.New("router: not an IPv4 packet")
	ErrBadIHL      = errors.New("router: header length outside the packet")
	ErrNoPorts     = errors.New("router: transport header truncated")
	ErrUnsupported = errors.New("router: unsupported transport protocol")
	ErrFragmented  = errors.New("router: fragmented packet")
)

// Packet is a parsed IPv4 packet. Payload aliases the input buffer.
type Packet struct {
	Src      net.IP
	Dst      net.IP
	Protocol uint8
	SrcPort  uint16
	DstPort  uint16
	Payload  []byte // transport payload, after the UDP or TCP header
	Header   []byte // IP header, for rewriting addresses
}

// ParseIPv4 reads an IPv4 packet far enough to route it. UDP and TCP yield
// ports; other protocols return ErrUnsupported with the addresses still set.
func ParseIPv4(buf []byte) (*Packet, error) {
	if len(buf) < 20 {
		return nil, ErrTooShort
	}
	if buf[0]>>4 != 4 {
		return nil, ErrNotIPv4
	}

	ihl := int(buf[0]&0x0F) * 4
	if ihl < 20 || ihl > len(buf) {
		return nil, ErrBadIHL
	}

	// Drop fragments: reassembly would add latency and state, and games do not
	// send packets large enough to fragment at a 1400-byte MTU.
	fragOff := binary.BigEndian.Uint16(buf[6:8])
	if fragOff&0x1FFF != 0 || fragOff&0x2000 != 0 {
		return nil, ErrFragmented
	}

	p := &Packet{
		Src:      net.IP(buf[12:16]),
		Dst:      net.IP(buf[16:20]),
		Protocol: buf[9],
		Header:   buf[:ihl],
	}

	rest := buf[ihl:]
	switch p.Protocol {
	case ProtoUDP:
		if len(rest) < 8 {
			return nil, ErrNoPorts
		}
		p.SrcPort = binary.BigEndian.Uint16(rest[0:2])
		p.DstPort = binary.BigEndian.Uint16(rest[2:4])
		p.Payload = rest[8:]
		return p, nil

	case ProtoTCP:
		if len(rest) < 20 {
			return nil, ErrNoPorts
		}
		p.SrcPort = binary.BigEndian.Uint16(rest[0:2])
		p.DstPort = binary.BigEndian.Uint16(rest[2:4])
		dataOff := int(rest[12]>>4) * 4
		if dataOff < 20 || dataOff > len(rest) {
			return nil, ErrNoPorts
		}
		p.Payload = rest[dataOff:]
		return p, nil

	default:
		return p, ErrUnsupported
	}
}

// IsIPv4 reports whether buf looks like an IPv4 packet. Used to skip IPv6
// traffic, which the MVP does not tunnel.
func IsIPv4(buf []byte) bool {
	return len(buf) >= 20 && buf[0]>>4 == 4
}
