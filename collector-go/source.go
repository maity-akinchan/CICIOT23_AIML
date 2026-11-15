package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// PacketSource yields owned packet bytes. Live and offline sources share this
// so windowing does not depend on which reader produced the frame.
type PacketSource interface {
	Next(ctx context.Context) ([]byte, gopacket.CaptureInfo, error)
	Close() error
	LinkType() layers.LinkType
	KernelDrops() uint64
}

func openSource(cfg Config) (PacketSource, error) {
	switch cfg.Mode {
	case "pcap":
		return openFile(cfg.PcapFile, cfg.ReplaySpeed)
	case "live":
		return openLive(cfg.Iface)
	default:
		return nil, fmt.Errorf("unknown mode %q", cfg.Mode)
	}
}

type packetReader interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	LinkType() layers.LinkType
}

type fileSource struct {
	reader    packetReader
	file      *os.File
	link      layers.LinkType
	speed     float64
	prev      time.Time
	hasPrev   bool
	closeOnce sync.Once
	closeErr  error
}

func openFile(path string, speed float64) (PacketSource, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}
	buffered := bufio.NewReaderSize(file, 1<<20)
	magic, err := buffered.Peek(4)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("read pcap header: %w", err)
	}
	var reader packetReader
	if bytes.Equal(magic, []byte{0x0a, 0x0d, 0x0d, 0x0a}) {
		ng, err := pcapgo.NewNgReader(buffered, pcapgo.NgReaderOptions{
			WantMixedLinkType:          true,
			ErrorOnMismatchingLinkType: false,
			SkipUnknownVersion:         true,
		})
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("pcapng: %w", err)
		}
		reader = ng
	} else {
		classic, err := pcapgo.NewReader(buffered)
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("pcap: %w", err)
		}
		reader = classic
	}
	return &fileSource{reader: reader, file: file, link: reader.LinkType(), speed: speed}, nil
}

func (s *fileSource) Next(ctx context.Context) ([]byte, gopacket.CaptureInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}
	data, ci, err := s.reader.ReadPacketData()
	if err != nil {
		return nil, ci, err
	}
	if s.speed > 0 && s.hasPrev && !ci.Timestamp.IsZero() {
		delta := ci.Timestamp.Sub(s.prev)
		if delta > 0 {
			sleep := time.Duration(float64(delta) / s.speed)
			const maxSleep = 30 * time.Second
			if sleep > maxSleep {
				sleep = maxSleep
			}
			timer := time.NewTimer(sleep)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, gopacket.CaptureInfo{}, ctx.Err()
			case <-timer.C:
			}
		}
	}
	if !ci.Timestamp.IsZero() {
		s.prev = ci.Timestamp
		s.hasPrev = true
	}
	owned := make([]byte, len(data))
	copy(owned, data)
	return owned, ci, nil
}

func (s *fileSource) Close() error {
	s.closeOnce.Do(func() { s.closeErr = s.file.Close() })
	return s.closeErr
}

func (s *fileSource) LinkType() layers.LinkType { return s.link }

func (s *fileSource) KernelDrops() uint64 { return 0 }

func captureLoop(ctx context.Context, src PacketSource, out chan<- Packet, stats *Stats) {
	link := src.LinkType()
	for {
		data, ci, err := src.Next(ctx)
		if err != nil {
			if ctx.Err() == nil && err != io.EOF {
				logCaptureEnd(err)
			}
			return
		}
		stats.Captured.Add(1)
		pkt, decErr := Decode(link, data, ci)
		if decErr != nil {
			switch {
			case errors.Is(decErr, errTruncated), errors.Is(decErr, errNoWireLength):
				stats.Truncated.Add(1)
			case errors.Is(decErr, errFragment):
				stats.Fragments.Add(1)
			case errors.Is(decErr, errMalformed):
				stats.Malformed.Add(1)
				stats.Skipped.Add(1)
			default:
				stats.Skipped.Add(1)
			}
			continue
		}
		if payloadTruncated(data, ci) {
			stats.Truncated.Add(1)
		}
		select {
		case out <- pkt:
			stats.Accepted.Add(1)
		default:
			stats.DroppedQueue.Add(1)
		}
	}
}

func logCaptureEnd(err error) {
	log.Printf("capture ended: %v", err)
}
