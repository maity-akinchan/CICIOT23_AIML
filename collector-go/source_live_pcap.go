//go:build (linux && cgo) || windows

package main

import (
	"context"
	"fmt"
	"io"
	"runtime"
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

func listInterfaces(out io.Writer) error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return captureSetupError(err)
	}
	for _, device := range devices {
		fmt.Fprintf(out, "%s\t%s\n", device.Name, device.Description)
	}
	return nil
}

func captureSetupError(err error) error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("check that Npcap is installed and that the selected interface is accessible: %w", err)
	}
	return err
}

func openLive(iface string) (PacketSource, error) {
	if iface == "" {
		return nil, fmt.Errorf("live mode requires --iface")
	}
	handle, err := pcap.OpenLive(iface, 65535, true, 200*time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", iface, captureSetupError(err))
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
