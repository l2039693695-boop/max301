// Package types holds small shared types used across Max301 packages.
package types

import "sync/atomic"

// Stats holds per-node counters. All fields are updated atomically so a
// reporting goroutine can read them without locking.
type Stats struct {
	RxPackets atomic.Uint64
	TxPackets atomic.Uint64
	RxBytes   atomic.Uint64
	TxBytes   atomic.Uint64

	// Duplicate counts frames discarded by the deduplicator. Under redundant
	// sending this is expected to be roughly (redundancy-1)/redundancy of RX.
	Duplicate atomic.Uint64

	// Invalid counts frames that failed header parsing or AEAD authentication.
	// A non-zero rate here means either a key mismatch or injected traffic.
	Invalid atomic.Uint64
}

// Snapshot is a plain-value copy of Stats, safe to format or serialise.
type Snapshot struct {
	RxPackets uint64
	TxPackets uint64
	RxBytes   uint64
	TxBytes   uint64
	Duplicate uint64
	Invalid   uint64
}

// Snapshot reads all counters. The values are not mutually consistent, which
// is fine for logging.
func (s *Stats) Snapshot() Snapshot {
	return Snapshot{
		RxPackets: s.RxPackets.Load(),
		TxPackets: s.TxPackets.Load(),
		RxBytes:   s.RxBytes.Load(),
		TxBytes:   s.TxBytes.Load(),
		Duplicate: s.Duplicate.Load(),
		Invalid:   s.Invalid.Load(),
	}
}
