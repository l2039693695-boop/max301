package dedup

import (
	"math/rand"
	"sync"
	"testing"
)

func TestFirstSightIsNeverDuplicate(t *testing.T) {
	d := New(1024)
	for _, id := range []uint32{0, 1, 2, 500, 1000} {
		if d.Seen(id) {
			t.Errorf("Seen(%d) = true on first sight", id)
		}
	}
}

func TestRepeatIsDuplicate(t *testing.T) {
	d := New(1024)
	for _, id := range []uint32{100, 101, 102} {
		if d.Seen(id) {
			t.Fatalf("Seen(%d) = true on first sight", id)
		}
	}
	for _, id := range []uint32{100, 101, 102} {
		if !d.Seen(id) {
			t.Errorf("Seen(%d) = false on repeat", id)
		}
	}
}

// Redundant sending means every packet arrives N times; only the first copy
// may pass.
func TestRedundantCopiesCollapseToOne(t *testing.T) {
	const redundancy = 3
	d := New(4096)
	passed := 0
	for id := uint32(1); id <= 1000; id++ {
		for c := 0; c < redundancy; c++ {
			if !d.Seen(id) {
				passed++
			}
		}
	}
	if passed != 1000 {
		t.Errorf("%d packets passed, want 1000", passed)
	}
}

// Reordering inside the window is normal on redundant paths and must not
// cause drops.
func TestOutOfOrderWithinWindowPasses(t *testing.T) {
	d := New(1024)
	for _, id := range []uint32{10, 7, 9, 8, 11, 6} {
		if d.Seen(id) {
			t.Errorf("Seen(%d) = true, want false for a reordered new packet", id)
		}
	}
	for _, id := range []uint32{6, 7, 8, 9, 10, 11} {
		if !d.Seen(id) {
			t.Errorf("Seen(%d) = false on repeat after reordering", id)
		}
	}
}

func TestPacketOlderThanWindowIsDropped(t *testing.T) {
	d := New(256)
	if d.Seen(1) {
		t.Fatal("unexpected duplicate")
	}
	if d.Seen(1000) { // jumps clear of the window
		t.Fatal("unexpected duplicate")
	}
	if !d.Seen(1) {
		t.Error("Seen(1) = false; a packet left far behind the window should drop")
	}
}

// PacketID wraps at 2^32. Signed comparison must keep the window moving
// forward across the boundary instead of seeing a huge backwards jump.
func TestWrapAround(t *testing.T) {
	d := New(1024)

	start := uint32(0xFFFFFFFF - 4)
	for i := uint32(0); i < 10; i++ { // crosses 0xFFFFFFFF -> 0
		id := start + i
		if d.Seen(id) {
			t.Errorf("Seen(%#x) = true across the wrap, want false", id)
		}
	}
	for i := uint32(0); i < 10; i++ {
		id := start + i
		if !d.Seen(id) {
			t.Errorf("Seen(%#x) = false on repeat across the wrap", id)
		}
	}
}

func TestWrapAroundOutOfOrder(t *testing.T) {
	d := New(1024)
	ids := []uint32{0xFFFFFFFE, 0x00000001, 0xFFFFFFFF, 0x00000000, 0x00000002}
	for _, id := range ids {
		if d.Seen(id) {
			t.Errorf("Seen(%#x) = true on first sight across the wrap", id)
		}
	}
	for _, id := range ids {
		if !d.Seen(id) {
			t.Errorf("Seen(%#x) = false on repeat across the wrap", id)
		}
	}
}

// Sliding the window forward must clear the bits it passes, otherwise a stale
// bit makes a fresh packet look like a duplicate once IDs alias onto it.
func TestSlidingClearsStaleBits(t *testing.T) {
	const size = 256
	d := New(size)

	if d.Seen(5) {
		t.Fatal("unexpected duplicate")
	}
	// 5 + size aliases to the same bitmap slot as 5.
	if d.Seen(5 + size) {
		t.Error("Seen(5+size) = true; a stale bit was not cleared when sliding")
	}
}

func TestSlidingClearsStaleBitsAcrossManyLaps(t *testing.T) {
	const size = 64
	d := New(size)
	for lap := uint32(0); lap < 20; lap++ {
		id := lap * size // always the same slot
		if d.Seen(id) {
			t.Fatalf("Seen(%d) = true on lap %d, want false", id, lap)
		}
	}
}

func TestResetForgetsHistory(t *testing.T) {
	d := New(1024)
	d.Seen(42)
	if !d.Seen(42) {
		t.Fatal("Seen(42) = false on repeat")
	}
	d.Reset()
	if d.Seen(42) {
		t.Error("Seen(42) = true after Reset, want false")
	}
}

func TestWindowRoundsUpToPowerOfTwo(t *testing.T) {
	tests := []struct{ in, want uint32 }{
		{0, DefaultWindow},
		{1, 1},
		{64, 64},
		{100, 128},
		{65536, 65536},
	}
	for _, tc := range tests {
		if got := New(tc.in).Window(); got != tc.want {
			t.Errorf("New(%d).Window() = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// Receivers call Seen from one goroutine per inbound port, so it must be
// race-free and must still admit each ID exactly once.
func TestConcurrentSeenAdmitsEachIDOnce(t *testing.T) {
	const (
		workers = 8
		packets = 2000
	)
	d := New(65536)

	var (
		mu     sync.Mutex
		passed = map[uint32]int{}
		wg     sync.WaitGroup
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := uint32(1); id <= packets; id++ {
				if !d.Seen(id) {
					mu.Lock()
					passed[id]++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	for id := uint32(1); id <= packets; id++ {
		if passed[id] != 1 {
			t.Fatalf("packet %d passed %d times, want 1", id, passed[id])
		}
	}
}

func BenchmarkSeenSequential(b *testing.B) {
	d := New(DefaultWindow)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		d.Seen(uint32(i))
	}
}

func BenchmarkSeenJittered(b *testing.B) {
	d := New(DefaultWindow)
	ids := make([]uint32, b.N)
	for i := range ids {
		ids[i] = uint32(i) + uint32(rand.Intn(8)) // mild reordering
	}
	b.ResetTimer()
	for _, id := range ids {
		d.Seen(id)
	}
}
