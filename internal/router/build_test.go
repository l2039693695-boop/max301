package router

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// A packet we build must parse back to the same endpoints, and its checksums
// must be the ones a receiving stack expects -- a wrong checksum means the game
// silently never sees the reply.
func TestBuildUDPPacketRoundTrip(t *testing.T) {
	src := [4]byte{185, 60, 112, 157}
	dst := [4]byte{10, 88, 0, 2}
	payload := []byte("reply from the game server")

	raw := BuildUDPPacket(nil, src, dst, 7000, 54321, payload)

	p, err := ParseIPv4(raw)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}
	if !p.Src.Equal(net.IP(src[:])) {
		t.Errorf("Src = %v, want %v", p.Src, net.IP(src[:]))
	}
	if !p.Dst.Equal(net.IP(dst[:])) {
		t.Errorf("Dst = %v, want %v", p.Dst, net.IP(dst[:]))
	}
	if p.Protocol != ProtoUDP {
		t.Errorf("Protocol = %d, want %d", p.Protocol, ProtoUDP)
	}
	if p.SrcPort != 7000 || p.DstPort != 54321 {
		t.Errorf("ports = %d -> %d, want 7000 -> 54321", p.SrcPort, p.DstPort)
	}
	if !bytes.Equal(p.Payload, payload) {
		t.Errorf("Payload = %q, want %q", p.Payload, payload)
	}
}

// A correct header checksums to zero when summed including the checksum field.
func TestBuildUDPPacketChecksums(t *testing.T) {
	for _, n := range []int{0, 1, 2, 7, 200, 1300} { // includes odd lengths
		payload := bytes.Repeat([]byte{0xA5}, n)
		raw := BuildUDPPacket(nil, [4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, 1234, 5678, payload)

		if got := checksum(raw[:20]); got != 0 {
			t.Errorf("payload %d bytes: IP header checksum verifies to %#x, want 0", n, got)
		}

		udp := raw[20:]
		stored := binary.BigEndian.Uint16(udp[6:8])
		if stored == 0 {
			t.Errorf("payload %d bytes: UDP checksum left as zero", n)
		}
		// Recompute with the field zeroed and compare.
		scratch := bytes.Clone(udp)
		binary.BigEndian.PutUint16(scratch[6:8], 0)
		if want := udpChecksum([4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}, scratch); stored != want {
			t.Errorf("payload %d bytes: UDP checksum = %#x, want %#x", n, stored, want)
		}
	}
}

func TestBuildUDPPacketLengths(t *testing.T) {
	payload := bytes.Repeat([]byte{0x11}, 100)
	raw := BuildUDPPacket(nil, [4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 1, 2, payload)

	if len(raw) != 20+8+len(payload) {
		t.Errorf("total length = %d, want %d", len(raw), 20+8+len(payload))
	}
	if got := binary.BigEndian.Uint16(raw[2:4]); int(got) != len(raw) {
		t.Errorf("IP total length field = %d, want %d", got, len(raw))
	}
	if got := binary.BigEndian.Uint16(raw[24:26]); int(got) != 8+len(payload) {
		t.Errorf("UDP length field = %d, want %d", got, 8+len(payload))
	}
	if raw[8] == 0 {
		t.Error("TTL is zero; the packet would be dropped at the first hop")
	}
}

// Appending to a caller's buffer keeps the reply path allocation-free.
func TestBuildUDPPacketAppends(t *testing.T) {
	prefix := []byte{0xDE, 0xAD}
	buf := make([]byte, 0, 1500)
	buf = append(buf, prefix...)

	out := BuildUDPPacket(buf, [4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 1, 2, []byte("x"))

	if !bytes.Equal(out[:2], prefix) {
		t.Error("BuildUDPPacket overwrote the caller's existing bytes")
	}
	if _, err := ParseIPv4(out[2:]); err != nil {
		t.Errorf("appended packet does not parse: %v", err)
	}
}

func TestParseIPv4Errors(t *testing.T) {
	valid := BuildUDPPacket(nil, [4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 1, 2, []byte("payload"))

	t.Run("too short", func(t *testing.T) {
		if _, err := ParseIPv4(valid[:10]); err != ErrTooShort {
			t.Errorf("err = %v, want ErrTooShort", err)
		}
	})

	t.Run("not ipv4", func(t *testing.T) {
		bad := bytes.Clone(valid)
		bad[0] = 6<<4 | 5
		if _, err := ParseIPv4(bad); err != ErrNotIPv4 {
			t.Errorf("err = %v, want ErrNotIPv4", err)
		}
	})

	t.Run("header length overruns packet", func(t *testing.T) {
		bad := bytes.Clone(valid)
		bad[0] = 4<<4 | 15 // claims a 60-byte header
		if _, err := ParseIPv4(bad[:30]); err != ErrBadIHL {
			t.Errorf("err = %v, want ErrBadIHL", err)
		}
	})

	t.Run("fragment", func(t *testing.T) {
		bad := bytes.Clone(valid)
		binary.BigEndian.PutUint16(bad[6:8], 0x2000) // more-fragments set
		if _, err := ParseIPv4(bad); err != ErrFragmented {
			t.Errorf("err = %v, want ErrFragmented", err)
		}
	})

	t.Run("truncated udp header", func(t *testing.T) {
		if _, err := ParseIPv4(valid[:24]); err != ErrNoPorts {
			t.Errorf("err = %v, want ErrNoPorts", err)
		}
	})

	t.Run("icmp is unsupported but addresses still parse", func(t *testing.T) {
		bad := bytes.Clone(valid)
		bad[9] = ProtoICMP
		p, err := ParseIPv4(bad)
		if err != ErrUnsupported {
			t.Errorf("err = %v, want ErrUnsupported", err)
		}
		if p == nil || !p.Dst.Equal(net.IP{2, 2, 2, 2}) {
			t.Error("addresses should still be available for an unsupported protocol")
		}
	})
}

func TestParseTCP(t *testing.T) {
	// Hand-build a minimal TCP packet: 20-byte IP header, 20-byte TCP header.
	raw := make([]byte, 40+4)
	raw[0] = 4<<4 | 5
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	raw[9] = ProtoTCP
	copy(raw[12:16], []byte{10, 0, 0, 1})
	copy(raw[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(raw[20:22], 1234)
	binary.BigEndian.PutUint16(raw[22:24], 443)
	raw[32] = 5 << 4 // data offset of 20 bytes
	copy(raw[40:], []byte("data"))

	p, err := ParseIPv4(raw)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}
	if p.SrcPort != 1234 || p.DstPort != 443 {
		t.Errorf("ports = %d -> %d, want 1234 -> 443", p.SrcPort, p.DstPort)
	}
	if !bytes.Equal(p.Payload, []byte("data")) {
		t.Errorf("Payload = %q, want \"data\"", p.Payload)
	}
}

func TestIsIPv4(t *testing.T) {
	valid := BuildUDPPacket(nil, [4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}, 1, 2, nil)
	if !IsIPv4(valid) {
		t.Error("IsIPv4 = false for an IPv4 packet")
	}
	if IsIPv4(valid[:5]) {
		t.Error("IsIPv4 = true for a runt")
	}

	v6 := make([]byte, 40)
	v6[0] = 6 << 4
	if IsIPv4(v6) {
		t.Error("IsIPv4 = true for an IPv6 packet")
	}
}
