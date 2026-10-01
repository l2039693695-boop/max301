//go:build windows

// Package tun wraps the Wintun driver and the Windows route table.
package tun

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// RingCapacity is the driver's ring buffer size. The driver accepts powers of
// two from 128 KiB to 64 MiB; 4 MiB absorbs a burst without adding latency,
// since the ring is drained as fast as the reader runs.
const RingCapacity = 0x400000 // 4 MiB

// guid keeps the adapter stable across restarts, so Windows reuses the same
// interface and its firewall and route entries instead of creating a new one
// each run.
var guid = windows.GUID{
	Data1: 0x4d617833,
	Data2: 0x3031,
	Data3: 0x4d61,
	Data4: [8]byte{0x78, 0x33, 0x30, 0x31, 0x54, 0x55, 0x4e, 0x00},
}

// Device is an open Wintun adapter.
type Device struct {
	adapter *wintun.Adapter
	session wintun.Session
	name    string
	mtu     int
	luid    uint64
	closed  bool
}

// Create opens or creates the adapter named name. It requires administrator
// privileges and wintun.dll beside the executable.
func Create(name string, mtu int) (*Device, error) {
	if mtu <= 0 {
		mtu = 1400
	}

	adapter, err := wintun.CreateAdapter(name, "Max301", &guid)
	if err != nil {
		return nil, fmt.Errorf("tun: create adapter %q: %w (run as administrator, and keep wintun.dll next to the executable)", name, err)
	}

	session, err := adapter.StartSession(RingCapacity)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("tun: start session: %w", err)
	}

	return &Device{
		adapter: adapter,
		session: session,
		name:    name,
		mtu:     mtu,
		luid:    adapter.LUID(),
	}, nil
}

// Name reports the adapter name.
func (d *Device) Name() string { return d.name }

// MTU reports the configured MTU.
func (d *Device) MTU() int { return d.mtu }

// LUID reports the Windows interface identifier, needed when adding routes.
func (d *Device) LUID() uint64 { return d.luid }

// ErrClosed is returned once the device is closed.
var ErrClosed = errors.New("tun: device is closed")

// Read copies the next outbound IP packet into dst and returns the filled
// prefix. It blocks until a packet is available.
//
// dst must be at least MTU bytes; a larger packet is dropped rather than
// truncated, since a partial IP packet is worse than none.
func (d *Device) Read(dst []byte) ([]byte, error) {
	for {
		if d.closed {
			return nil, ErrClosed
		}

		packet, err := d.session.ReceivePacket()
		switch err {
		case nil:
			// The ring buffer must be handed back promptly or the driver stalls,
			// so copy out before releasing rather than returning its memory.
			var out []byte
			if len(packet) <= len(dst) {
				n := copy(dst, packet)
				out = dst[:n]
			}
			d.session.ReleaseReceivePacket(packet)
			if out == nil {
				continue // oversized; skip it
			}
			return out, nil

		case windows.ERROR_NO_MORE_ITEMS:
			// Ring empty: wait for the driver to signal more data.
			if _, err := windows.WaitForSingleObject(d.session.ReadWaitEvent(), windows.INFINITE); err != nil {
				return nil, fmt.Errorf("tun: wait: %w", err)
			}
			continue

		case windows.ERROR_HANDLE_EOF:
			return nil, ErrClosed

		case windows.ERROR_INVALID_DATA:
			return nil, errors.New("tun: driver reported a corrupt ring buffer")

		default:
			return nil, fmt.Errorf("tun: receive: %w", err)
		}
	}
}

// Write injects an inbound IP packet into the local stack.
func (d *Device) Write(packet []byte) error {
	if d.closed {
		return ErrClosed
	}
	if len(packet) == 0 {
		return nil
	}

	buf, err := d.session.AllocateSendPacket(len(packet))
	if err != nil {
		if err == windows.ERROR_BUFFER_OVERFLOW {
			// Ring full: the stack is not draining. Dropping is correct for a
			// game -- a queued stale packet is worse than a gap.
			return nil
		}
		return fmt.Errorf("tun: allocate: %w", err)
	}
	copy(buf, packet)
	d.session.SendPacket(buf)
	return nil
}

// Close ends the session and removes the adapter.
func (d *Device) Close() error {
	if d.closed {
		return nil
	}
	d.closed = true
	d.session.End()
	return d.adapter.Close()
}

// SetIP assigns an address and prefix to the adapter and sets its MTU.
func (d *Device) SetIP(prefix netip.Prefix) error {
	if err := setInterfaceAddress(d.name, prefix); err != nil {
		return err
	}
	return setInterfaceMTU(d.name, d.mtu)
}
