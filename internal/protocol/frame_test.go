package protocol

import (
	"bytes"
	"testing"
)

func TestHeaderRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xAB}, 64) // stands in for ciphertext+tag

	out := &Frame{
		Version:   Version,
		SessionID: 0xDEADBEEF,
		PacketID:  0x01020304,
		Nonce:     0x1122334455667788,
	}
	out.SetPacketType(TypeData)
	out.SetPriority(PriorityGame)
	out.SetLast(true)

	buf := make([]byte, HeaderSize+len(payload))
	if n := out.EncodeHeader(buf); n != HeaderSize {
		t.Fatalf("EncodeHeader returned %d, want %d", n, HeaderSize)
	}
	copy(buf[HeaderSize:], payload)

	var in Frame
	if err := in.DecodeHeader(buf); err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}

	if in.SessionID != out.SessionID {
		t.Errorf("SessionID = %#x, want %#x", in.SessionID, out.SessionID)
	}
	if in.PacketID != out.PacketID {
		t.Errorf("PacketID = %#x, want %#x", in.PacketID, out.PacketID)
	}
	if in.Nonce != out.Nonce {
		t.Errorf("Nonce = %#x, want %#x", in.Nonce, out.Nonce)
	}
	if !bytes.Equal(in.Payload, payload) {
		t.Error("Payload did not survive the round trip")
	}
	if in.PacketType() != TypeData {
		t.Errorf("PacketType = %d, want %d", in.PacketType(), TypeData)
	}
	if in.Priority() != PriorityGame {
		t.Errorf("Priority = %d, want %d", in.Priority(), PriorityGame)
	}
	if !in.IsLast() {
		t.Error("IsLast = false, want true")
	}
}

// All three packet types must survive the flags encoding. The single-bit type
// field in the original design could not represent heartbeat.
func TestFlagsHoldAllTypesAndPriorities(t *testing.T) {
	types := []byte{TypeData, TypeControl, TypeHeartbeat}
	prios := []byte{PriorityNormal, PriorityGame, PriorityCritical}

	for _, typ := range types {
		for _, prio := range prios {
			for _, last := range []bool{false, true} {
				var f Frame
				f.SetPacketType(typ)
				f.SetPriority(prio)
				f.SetLast(last)

				if got := f.PacketType(); got != typ {
					t.Errorf("type %d prio %d last %v: PacketType = %d", typ, prio, last, got)
				}
				if got := f.Priority(); got != prio {
					t.Errorf("type %d prio %d last %v: Priority = %d", typ, prio, last, got)
				}
				if got := f.IsLast(); got != last {
					t.Errorf("type %d prio %d last %v: IsLast = %v", typ, prio, last, got)
				}
			}
		}
	}
}

// Setting one subfield must not disturb the others.
func TestFlagsFieldsAreIndependent(t *testing.T) {
	var f Frame
	f.SetPacketType(TypeHeartbeat)
	f.SetPriority(PriorityCritical)
	f.SetLast(true)

	f.SetPacketType(TypeData)
	if f.Priority() != PriorityCritical || !f.IsLast() {
		t.Error("SetPacketType clobbered priority or last flag")
	}

	f.SetPriority(PriorityNormal)
	if f.PacketType() != TypeData || !f.IsLast() {
		t.Error("SetPriority clobbered type or last flag")
	}

	f.SetLast(false)
	if f.PacketType() != TypeData || f.Priority() != PriorityNormal {
		t.Error("SetLast clobbered type or priority")
	}
}

func TestDecodeRejectsBadFrames(t *testing.T) {
	good := make([]byte, HeaderSize+TagSize)
	good[0] = Version

	tests := []struct {
		name string
		buf  []byte
		want error
	}{
		{"truncated header", make([]byte, HeaderSize-1), ErrShortFrame},
		{"oversized", make([]byte, MaxFrameSize+1), ErrFrameTooBig},
		{"header only, no tag", good[:HeaderSize], ErrShortPayload},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.buf) > 0 && len(tc.buf) >= 1 {
				tc.buf[0] = Version
			}
			var f Frame
			if err := f.DecodeHeader(tc.buf); err != tc.want {
				t.Errorf("DecodeHeader = %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("wrong version", func(t *testing.T) {
		buf := make([]byte, HeaderSize+TagSize)
		buf[0] = Version + 1
		var f Frame
		if err := f.DecodeHeader(buf); err != ErrBadVersion {
			t.Errorf("DecodeHeader = %v, want %v", err, ErrBadVersion)
		}
	})
}

func TestOverheadMatchesLayout(t *testing.T) {
	if Overhead != 36 {
		t.Errorf("Overhead = %d, want 36", Overhead)
	}
}
