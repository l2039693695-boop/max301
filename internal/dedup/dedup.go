// Package dedup discards duplicate frames produced by redundant sending.
//
// The deduplicator keeps a sliding window of recently seen PacketIDs as a
// bitmap. A frame whose ID falls inside the window and is already marked is a
// duplicate; one ahead of the window advances it. Frames that arrive so late
// that the window has moved past them are treated as duplicates, since
// accepting them would require unbounded state and they are useless to a game
// anyway.
//
// PacketIDs wrap at 2^32. All comparisons therefore use signed differences,
// so a wrap looks like ordinary forward motion rather than a 4-billion-packet
// jump backwards.
package dedup

import "sync"

// DefaultWindow is the window size used when none is given: 65536 packets,
// roughly 18 minutes at 60 packets per second.
const DefaultWindow = 65536

// Deduplicator tracks which PacketIDs have been seen. It is safe for
// concurrent use.
type Deduplicator struct {
	mu   sync.Mutex
	bits []uint64 // bitmap, one bit per ID in the window
	size uint32   // window size in packets, a power of two
	mask uint32   // size - 1, for cheap modulo
	head uint32   // highest ID seen so far
	init bool     // false until the first frame arrives
}

// New returns a Deduplicator with the given window size, rounded up to a
// power of two. A size of zero selects DefaultWindow.
func New(size uint32) *Deduplicator {
	if size == 0 {
		size = DefaultWindow
	}
	size = roundUpPow2(size)
	return &Deduplicator{
		bits: make([]uint64, (size+63)/64),
		size: size,
		mask: size - 1,
	}
}

// Window returns the configured window size in packets.
func (d *Deduplicator) Window() uint32 { return d.size }

// Seen reports whether packetID has been seen before, and records it if not.
// A true result means the frame is a duplicate and should be dropped.
func (d *Deduplicator) Seen(packetID uint32) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.init {
		d.init = true
		d.head = packetID
		d.set(packetID)
		return false
	}

	// Signed difference so that wrap-around reads as a small delta.
	delta := int32(packetID - d.head)

	switch {
	case delta > 0:
		// Ahead of the window: advance, clearing the IDs we slide past so
		// their bits are not mistaken for recent ones.
		if uint32(delta) >= d.size {
			// Jumped clear of the window; everything buffered is stale.
			d.clearAll()
		} else {
			for id := d.head + 1; id != packetID+1; id++ {
				d.clear(id)
			}
		}
		d.head = packetID
		d.set(packetID)
		return false

	case delta == 0:
		return true // the head itself, already recorded

	default:
		// Behind the head. Older than the window means unrecoverably late.
		if uint32(-delta) >= d.size {
			return true
		}
		if d.get(packetID) {
			return true
		}
		d.set(packetID)
		return false
	}
}

// Reset forgets all history, as when a session is rekeyed.
func (d *Deduplicator) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.clearAll()
	d.init = false
	d.head = 0
}

// Bit helpers. All require d.mu to be held.

func (d *Deduplicator) slot(id uint32) (word uint32, bit uint64) {
	i := id & d.mask
	return i / 64, 1 << (i % 64)
}

func (d *Deduplicator) set(id uint32) {
	w, b := d.slot(id)
	d.bits[w] |= b
}

func (d *Deduplicator) clear(id uint32) {
	w, b := d.slot(id)
	d.bits[w] &^= b
}

func (d *Deduplicator) get(id uint32) bool {
	w, b := d.slot(id)
	return d.bits[w]&b != 0
}

func (d *Deduplicator) clearAll() {
	for i := range d.bits {
		d.bits[i] = 0
	}
}

func roundUpPow2(n uint32) uint32 {
	if n == 0 {
		return 1
	}
	if n&(n-1) == 0 {
		return n
	}
	// Largest power of two representable in uint32.
	if n > 1<<31 {
		return 1 << 31
	}
	p := uint32(1)
	for p < n {
		p <<= 1
	}
	return p
}
