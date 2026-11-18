package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

func run(ctx context.Context, cfg Config) error {
	if err := probeHealth(ctx, cfg); err != nil {
		return err
	}
	src, err := openSource(cfg)
	if err != nil {
		return err
	}
	defer src.Close()
	if !supportedLink(src.LinkType()) {
		return fmt.Errorf("unsupported link type %s (%d); supported: %s", src.LinkType(), uint32(src.LinkType()), supportedLinkNames())
	}
	log.Printf("capture source=%s interface=%q link=%s contract=%s extractor=%s window=%d stride=%d timeout=%.0fs min=%d",
		cfg.sourceType(), cfg.Iface, src.LinkType(), contractID, extractorVersion, cfg.WindowSize, cfg.Stride, windowTimeoutSecond, minWindowPackets)
	return serve(ctx, cfg, src)
}

func serve(ctx context.Context, cfg Config, src PacketSource) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stats := &Stats{}
	session := newSessionID()
	packets := make(chan Packet, packetQueue)
	windows := make(chan Window, windowQueue)
	agg := newAggregator(cfg, session, windows, stats)
	ship := newShipper(cfg, session, src.LinkType().String(), stats)

	if cfg.Mode == "live" {
		go ship.reportCoverage(runCtx, cfg.Iface, src.KernelDrops)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		captureLoop(runCtx, src, packets, stats)
		close(packets)
	}()
	go func() {
		defer wg.Done()
		aggregateLoop(agg, packets)
		close(windows)
	}()

	stopLogs := make(chan struct{})
	go logStatsLoop(stopLogs, 10*time.Second, stats, src.KernelDrops, func() (int, int) {
		return len(packets), len(windows)
	})

	// Closing the capture handle unblocks a live read after SIGINT/SIGTERM.
	go func() {
		<-runCtx.Done()
		_ = src.Close()
	}()

	shipErr := ship.loop(windows)
	cancel()
	wg.Wait()
	close(stopLogs)
	stats.log("final", src.KernelDrops(), len(packets), len(windows))
	if shipErr != nil && !errors.Is(shipErr, context.Canceled) {
		return shipErr
	}
	if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func aggregateLoop(agg *Aggregator, packets <-chan Packet) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case pkt, ok := <-packets:
			if !ok {
				agg.FlushEOF()
				return
			}
			agg.Add(pkt)
		case now := <-ticker.C:
			agg.FlushIdle(now)
		}
	}
}
