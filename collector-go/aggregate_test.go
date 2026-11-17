package main

import (
	"testing"
	"time"
)

func testAggregator(mode string) (*Aggregator, chan Window, *Stats) {
	out := make(chan Window, 8)
	stats := &Stats{}
	cfg := Config{
		Mode:       mode,
		APIURL:     defaultAPIURL,
		WindowSize: defaultWindowSize,
		Stride:     defaultWindowSize,
	}
	return newAggregator(cfg, "session01", out, stats), out, stats
}

func TestAggregatorSYNWindowMatchesContract(t *testing.T) {
	agg, out, stats := testAggregator("pcap")
	for _, pkt := range flowPackets(100, "TCP", flagSYN, 54, 40, 64, 100*time.Microsecond) {
		agg.Add(pkt)
	}
	if stats.WindowsEmitted.Load() != 1 {
		t.Fatalf("emitted %d windows, want 1", stats.WindowsEmitted.Load())
	}
	got := <-out
	if got.PacketCount != 100 || got.Metadata.SrcIP != "172.18.0.50" || got.Metadata.DstIP != "172.18.0.10" {
		t.Fatalf("window metadata %+v", got.Metadata)
	}
	if got.Metadata.DominantProtocol != "TCP" || got.Metadata.SrcPort != 40000 || got.Metadata.DstPort != 80 {
		t.Fatalf("ports/protocol %+v", got.Metadata)
	}
	if got.Metadata.SrcMAC != "02:00:00:00:00:32" || got.WindowID == "" {
		t.Fatalf("mac/id %+v %s", got.Metadata, got.WindowID)
	}
	if len(got.WindowID) > 64 {
		t.Fatalf("window_id length %d exceeds schema max 64", len(got.WindowID))
	}
	nearly(t, "flow_duration", got.Features.FlowDuration, 0.0099)
	nearly(t, "Rate", got.Features.Rate, 100/0.0099)
	nearly(t, "Header_Length", got.Features.HeaderLength, 40)
	nearly(t, "syn_count", got.Features.SynCount, 100)
	nearly(t, "Std", got.Features.Std, 0)
}

func TestAggregatorDoesNotMergeEndpointPairs(t *testing.T) {
	agg, out, _ := testAggregator("pcap")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	add := func(src, dst string, port int, proto string) {
		for i := 0; i < 5; i++ {
			agg.Add(Packet{
				Timestamp:   base.Add(time.Duration(i) * time.Millisecond),
				WireBytes:   60,
				HeaderBytes: 28,
				TTL:         64,
				SrcIP:       src,
				DstIP:       dst,
				SrcPort:     port,
				DstPort:     80,
				Protocol:    proto,
			})
		}
	}
	add("10.0.0.1", "10.0.0.2", 1111, "TCP")
	add("10.0.0.3", "10.0.0.4", 2222, "UDP")
	agg.FlushEOF()
	got := map[string]Window{}
	for i := 0; i < 2; i++ {
		select {
		case w := <-out:
			got[w.Metadata.SrcIP+"->"+w.Metadata.DstIP] = w
		default:
			t.Fatal("missing window")
		}
	}
	select {
	case extra := <-out:
		t.Fatalf("unexpected extra window %s -> %s", extra.Metadata.SrcIP, extra.Metadata.DstIP)
	default:
	}
	first, ok := got["10.0.0.1->10.0.0.2"]
	if !ok || first.Metadata.DominantProtocol != "TCP" || first.Metadata.SrcPort != 1111 {
		t.Fatalf("first pair = %+v", first.Metadata)
	}
	second, ok := got["10.0.0.3->10.0.0.4"]
	if !ok || second.Metadata.DominantProtocol != "UDP" || second.Metadata.SrcPort != 2222 {
		t.Fatalf("second pair = %+v", second.Metadata)
	}
	if first.Features.TCP != 1 || second.Features.UDP != 1 {
		t.Fatal("protocol shares were mixed across flows")
	}
}

func TestAggregatorDropsShortWindows(t *testing.T) {
	agg, out, stats := testAggregator("pcap")
	for _, pkt := range flowPackets(4, "TCP", flagACK, 54, 40, 64, time.Millisecond) {
		agg.Add(pkt)
	}
	agg.FlushEOF()
	select {
	case w := <-out:
		t.Fatalf("emitted short window %+v", w.Metadata)
	default:
	}
	if stats.WindowsInsufficient.Load() != 1 || stats.WindowsEmitted.Load() != 0 {
		t.Fatalf("insufficient=%d emitted=%d", stats.WindowsInsufficient.Load(), stats.WindowsEmitted.Load())
	}
}

func TestAggregatorClosesOnEventTimeout(t *testing.T) {
	agg, out, stats := testAggregator("pcap")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		agg.Add(Packet{
			Timestamp: base.Add(time.Duration(i) * 400 * time.Millisecond),
			WireBytes: 54, HeaderBytes: 40, TTL: 64,
			SrcIP: "10.1.1.1", DstIP: "10.1.1.2", SrcPort: 9, DstPort: 9,
			Protocol: "UDP",
		})
	}
	if stats.WindowsEmitted.Load() != 0 {
		t.Fatal("span under 2s closed early")
	}
	agg.Add(Packet{
		Timestamp: base.Add(2 * time.Second),
		WireBytes: 54, HeaderBytes: 40, TTL: 64,
		SrcIP: "10.1.1.1", DstIP: "10.1.1.2", SrcPort: 9, DstPort: 9,
		Protocol: "UDP",
	})
	if stats.WindowsEmitted.Load() != 1 {
		t.Fatalf("emitted %d, want the window closed at the 2s boundary", stats.WindowsEmitted.Load())
	}
	got := <-out
	if got.PacketCount != 5 {
		t.Fatalf("packet_count = %d, want 5", got.PacketCount)
	}
	agg.FlushEOF()
	if stats.WindowsInsufficient.Load() != 1 {
		t.Fatalf("the single packet after the boundary should be insufficient, got %d", stats.WindowsInsufficient.Load())
	}
}

func TestAggregatorDropsLatePacketThatBreaksTimeout(t *testing.T) {
	agg, _, stats := testAggregator("pcap")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	agg.Add(Packet{
		Timestamp: base, WireBytes: 54, HeaderBytes: 40, TTL: 64,
		SrcIP: "10.0.0.8", DstIP: "10.0.0.9", SrcPort: 1, DstPort: 2, Protocol: "TCP", TCPFlags: flagACK,
	})
	agg.Add(Packet{
		Timestamp: base.Add(1900 * time.Millisecond), WireBytes: 54, HeaderBytes: 40, TTL: 64,
		SrcIP: "10.0.0.8", DstIP: "10.0.0.9", SrcPort: 1, DstPort: 2, Protocol: "TCP", TCPFlags: flagACK,
	})
	agg.Add(Packet{
		Timestamp: base.Add(-200 * time.Millisecond), WireBytes: 54, HeaderBytes: 40, TTL: 64,
		SrcIP: "10.0.0.8", DstIP: "10.0.0.9", SrcPort: 1, DstPort: 2, Protocol: "TCP", TCPFlags: flagACK,
	})
	if stats.Late.Load() != 1 {
		t.Fatalf("late = %d, want 1", stats.Late.Load())
	}
	agg.FlushEOF()
	if stats.WindowsInsufficient.Load() != 1 || stats.WindowsEmitted.Load() != 0 {
		t.Fatalf("late packet was kept: insufficient=%d emitted=%d", stats.WindowsInsufficient.Load(), stats.WindowsEmitted.Load())
	}
}
