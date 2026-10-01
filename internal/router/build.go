package router

import "encoding/binary"

// BuildUDPPacket assembles an IPv4 UDP packet from the given endpoints and
// payload, appending to dst and returning the extended slice.
//
// The exit node uses this to rebuild the packet a game server's reply would
// have looked like had it arrived at the client directly: source is the server,
// destination is the client's tunnel address. The client's stack then delivers
// it to the game as an ordinary inbound datagram.
func BuildUDPPacket(dst []byte, srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	const (
		ipHeaderLen  = 20
		udpHeaderLen = 8
	)
	total := ipHeaderLen + udpHeaderLen + len(payload)

	start := len(dst)
	buf := append(dst, make([]byte, total)...)
	p := buf[start:]

	// IPv4 header.
	p[0] = 4<<4 | ipHeaderLen/4 // version and header length
	p[1] = 0                    // DSCP/ECN
	binary.BigEndian.PutUint16(p[2:4], uint16(total))
	binary.BigEndian.PutUint16(p[4:6], 0)      // identification; no fragmentation
	binary.BigEndian.PutUint16(p[6:8], 0x4000) // don't fragment
	p[8] = 64                                  // TTL
	p[9] = ProtoUDP
	// p[10:12] checksum, filled in below
	copy(p[12:16], srcIP[:])
	copy(p[16:20], dstIP[:])
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:ipHeaderLen]))

	// UDP header.
	u := p[ipHeaderLen:]
	binary.BigEndian.PutUint16(u[0:2], srcPort)
	binary.BigEndian.PutUint16(u[2:4], dstPort)
	binary.BigEndian.PutUint16(u[4:6], uint16(udpHeaderLen+len(payload)))
	copy(u[udpHeaderLen:], payload)

	// UDP checksum covers a pseudo-header plus the datagram. It is optional in
	// IPv4, but some stacks and middleboxes drop zero-checksum UDP, so compute
	// it.
	binary.BigEndian.PutUint16(u[6:8], udpChecksum(srcIP, dstIP, u))

	return buf
}

// checksum is the standard one's-complement sum over 16-bit words.
func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// udpChecksum computes the UDP checksum over the IPv4 pseudo-header and the
// UDP datagram. The checksum field in udp must be zero on entry.
func udpChecksum(srcIP, dstIP [4]byte, udp []byte) uint16 {
	var sum uint32

	// Pseudo-header: addresses, zero, protocol, UDP length.
	sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
	sum += uint32(ProtoUDP)
	sum += uint32(len(udp))

	for i := 0; i+1 < len(udp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udp[i : i+2]))
	}
	if len(udp)%2 == 1 {
		sum += uint32(udp[len(udp)-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	c := ^uint16(sum)
	if c == 0 {
		// Zero means "no checksum" on the wire, so the all-ones form is used
		// to represent a genuine zero result.
		c = 0xFFFF
	}
	return c
}
