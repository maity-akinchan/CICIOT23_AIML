package main

import (
	"log"
	"sync/atomic"
	"time"
)

// Stats are process counters. Queue drops are separate from kernel pcap drops.
type Stats struct {
	Captured            atomic.Uint64
	Accepted            atomic.Uint64
	DroppedQueue        atomic.Uint64
	Skipped             atomic.Uint64
	Truncated           atomic.Uint64
	Fragments           atomic.Uint64
	Malformed           atomic.Uint64
	Late                atomic.Uint64
	Control             atomic.Uint64
	WindowsEmitted      atomic.Uint64
	WindowsInsufficient atomic.Uint64
	WindowsDropped      atomic.Uint64
	HTTPSuccess         atomic.Uint64
	HTTPFailures        atomic.Uint64
}

func (s *Stats) log(prefix string, kernelDrops uint64, backlogPackets, backlogWindows int) {
	log.Printf(
		"%s captured=%d accepted=%d dropped_queue=%d dropped_kernel=%d skipped=%d truncated=%d fragments=%d malformed=%d late=%d control=%d windows_emitted=%d windows_insufficient=%d windows_dropped=%d http_ok=%d http_fail=%d backlog_packets=%d backlog_windows=%d",
		prefix,
		s.Captured.Load(),
		s.Accepted.Load(),
		s.DroppedQueue.Load(),
		kernelDrops,
		s.Skipped.Load(),
		s.Truncated.Load(),
		s.Fragments.Load(),
		s.Malformed.Load(),
		s.Late.Load(),
		s.Control.Load(),
		s.WindowsEmitted.Load(),
		s.WindowsInsufficient.Load(),
		s.WindowsDropped.Load(),
		s.HTTPSuccess.Load(),
		s.HTTPFailures.Load(),
		backlogPackets,
		backlogWindows,
	)
}

func logStatsLoop(stop <-chan struct{}, every time.Duration, stats *Stats, kernel func() uint64, backlog func() (int, int)) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			packets, windows := backlog()
			stats.log("health", kernel(), packets, windows)
		}
	}
}
