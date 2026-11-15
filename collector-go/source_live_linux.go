//go:build linux && cgo

package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type liveSource struct {
	mu     sync.Mutex
	handle *pcap.Handle
	iface  string
	closed bool
}

func openLive(iface string) (PacketSource, error) {
	if iface == "" {
		return nil, fmt.Errorf("live mode requires --iface")
	}
	handle, err := pcap.OpenLive(iface, 65535, true, 200*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", iface, err)
	}
	return &liveSource{handle: handle, iface: iface}, nil
}

func (s *liveSource) Next(ctx context.Context) ([]byte, gopacket.CaptureInfo, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, gopacket.CaptureInfo{}, err
		}
		s.mu.Lock()
		handle := s.handle
		closed := s.closed
		s.mu.Unlock()
		if closed || handle == nil {
			return nil, gopacket.CaptureInfo{}, context.Canceled
		}
		data, ci, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, gopacket.CaptureInfo{}, ctx.Err()
			}
			return nil, ci, err
		}
		owned := make([]byte, len(data))
		copy(owned, data)
		return owned, ci, nil
	}
}

func (s *liveSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle != nil && !s.closed {
		s.closed = true
		s.handle.Close()
	}
	return nil
}

func (s *liveSource) LinkType() layers.LinkType {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return layers.LinkTypeEthernet
	}
	return s.handle.LinkType()
}

func (s *liveSource) KernelDrops() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil || s.closed {
		return 0
	}
	stats, err := s.handle.Stats()
	if err != nil || stats == nil {
		return 0
	}
	dropped := stats.PacketsDropped + stats.PacketsIfDropped
	if dropped < 0 {
		return 0
	}
	return uint64(dropped)
}
