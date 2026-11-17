package main

import (
	"math"
	"testing"
	"time"
)

func nearly(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("%s = %.12g, want %.12g", name, got, want)
	}
}

func flowPackets(n int, proto string, flags uint8, wire, header, ttl int, gap time.Duration) []Packet {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	out := make([]Packet, n)
	for i := 0; i < n; i++ {
		out[i] = Packet{
			Timestamp:   base.Add(time.Duration(i) * gap),
			WireBytes:   wire,
			HeaderBytes: header,
			TTL:         ttl,
			SrcIP:       "172.18.0.50",
			DstIP:       "172.18.0.10",
			SrcMAC:      "02:00:00:00:00:32",
			DstMAC:      "02:00:00:00:00:0a",
			SrcPort:     40000,
			DstPort:     80,
			Protocol:    proto,
			TCPFlags:    flags,
		}
		if proto != "TCP" {
			out[i].TCPFlags = 0
		}
		if proto == "ICMP" {
			out[i].SrcPort = 0
			out[i].DstPort = 0
		}
	}
	return out
}

func TestSYNFloodFeatures(t *testing.T) {
	// 100 TCP SYN packets, 54 wire bytes, 40 header bytes, TTL 64, 0.0001 s spacing.
	pkts := flowPackets(100, "TCP", flagSYN, 54, 40, 64, 100*time.Microsecond)
	got, err := Compute(pkts)
	if err != nil {
		t.Fatal(err)
	}
	const duration = 0.0099
	nearly(t, "flow_duration", got.FlowDuration, duration)
	nearly(t, "Rate", got.Rate, 100/duration)
	nearly(t, "Header_Length", got.HeaderLength, 40)
	nearly(t, "Duration", got.Duration, 64)
	nearly(t, "syn_flag_number", got.SynFlagNumber, 1)
	nearly(t, "syn_count", got.SynCount, 100)
	nearly(t, "ack_count", got.AckCount, 0)
	nearly(t, "fin_count", got.FinCount, 0)
	nearly(t, "rst_count", got.RstCount, 0)
	nearly(t, "fin_flag_number", got.FinFlagNumber, 0)
	nearly(t, "rst_flag_number", got.RstFlagNumber, 0)
	nearly(t, "psh_flag_number", got.PshFlagNumber, 0)
	nearly(t, "ack_flag_number", got.AckFlagNumber, 0)
	nearly(t, "TCP", got.TCP, 1)
	nearly(t, "UDP", got.UDP, 0)
	nearly(t, "ICMP", got.ICMP, 0)
	nearly(t, "AVG", got.AVG, 54)
	nearly(t, "Std", got.Std, 0)
}

func TestUDPFloodFeatures(t *testing.T) {
	pkts := flowPackets(100, "UDP", 0, 60, 28, 64, 100*time.Microsecond)
	got, err := Compute(pkts)
	if err != nil {
		t.Fatal(err)
	}
	nearly(t, "flow_duration", got.FlowDuration, 0.0099)
	nearly(t, "Rate", got.Rate, 100/0.0099)
	nearly(t, "Header_Length", got.HeaderLength, 28)
	nearly(t, "Duration", got.Duration, 64)
	nearly(t, "UDP", got.UDP, 1)
	nearly(t, "TCP", got.TCP, 0)
	nearly(t, "ICMP", got.ICMP, 0)
	nearly(t, "syn_count", got.SynCount, 0)
	nearly(t, "AVG", got.AVG, 60)
	nearly(t, "Std", got.Std, 0)
}

func TestICMPFeatures(t *testing.T) {
	pkts := flowPackets(10, "ICMP", 0, 42, 28, 128, time.Millisecond)
	got, err := Compute(pkts)
	if err != nil {
		t.Fatal(err)
	}
	nearly(t, "flow_duration", got.FlowDuration, 0.009)
	nearly(t, "Rate", got.Rate, 10/0.009)
	nearly(t, "Header_Length", got.HeaderLength, 28)
	nearly(t, "Duration", got.Duration, 128)
	nearly(t, "ICMP", got.ICMP, 1)
	nearly(t, "TCP", got.TCP, 0)
	nearly(t, "UDP", got.UDP, 0)
	nearly(t, "AVG", got.AVG, 42)
	nearly(t, "Std", got.Std, 0)
	if pkts[0].SrcPort != 0 || pkts[0].DstPort != 0 {
		t.Fatal("ICMP ports must stay 0")
	}
}

func TestBenignTCPFeatures(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	flags := []uint8{flagSYN, flagSYN | flagACK, flagACK, flagPSH | flagACK, flagACK}
	sizes := []int{54, 54, 54, 120, 54}
	pkts := make([]Packet, len(flags))
	for i := range pkts {
		pkts[i] = Packet{
			Timestamp:   base.Add(time.Duration(i) * time.Millisecond),
			WireBytes:   sizes[i],
			HeaderBytes: 40,
			TTL:         64,
			SrcIP:       "172.18.0.50",
			DstIP:       "172.18.0.10",
			SrcPort:     40000,
			DstPort:     80,
			Protocol:    "TCP",
			TCPFlags:    flags[i],
		}
	}
	got, err := Compute(pkts)
	if err != nil {
		t.Fatal(err)
	}
	nearly(t, "flow_duration", got.FlowDuration, 0.004)
	nearly(t, "Rate", got.Rate, 5/0.004)
	nearly(t, "Header_Length", got.HeaderLength, 40)
	nearly(t, "Duration", got.Duration, 64)
	nearly(t, "syn_flag_number", got.SynFlagNumber, 2.0/5)
	nearly(t, "ack_flag_number", got.AckFlagNumber, 4.0/5)
	nearly(t, "psh_flag_number", got.PshFlagNumber, 1.0/5)
	nearly(t, "syn_count", got.SynCount, 2)
	nearly(t, "ack_count", got.AckCount, 4)
	nearly(t, "fin_count", got.FinCount, 0)
	nearly(t, "rst_count", got.RstCount, 0)
	nearly(t, "TCP", got.TCP, 1)
	nearly(t, "AVG", got.AVG, 67.2)
	nearly(t, "Std", got.Std, 26.4)
}

func TestZeroDurationUsesFloor(t *testing.T) {
	pkts := flowPackets(5, "TCP", flagACK, 54, 40, 64, 0)
	got, err := Compute(pkts)
	if err != nil {
		t.Fatal(err)
	}
	nearly(t, "flow_duration", got.FlowDuration, minFlowDuration)
	nearly(t, "Rate", got.Rate, 5/minFlowDuration)
	if math.IsInf(got.Rate, 0) || math.IsNaN(got.Rate) {
		t.Fatal("rate is not finite")
	}
}

func TestComputeRejectsEmptyAndUnknownProtocol(t *testing.T) {
	if _, err := Compute(nil); err == nil {
		t.Fatal("empty window accepted")
	}
	pkts := flowPackets(1, "GRE", 0, 54, 24, 64, 0)
	if _, err := Compute(pkts); err == nil {
		t.Fatal("unsupported protocol accepted")
	}
}
