package main

import (
	"strings"
	"testing"
)

func TestParseComposeLiveFlags(t *testing.T) {
	cfg, err := parseArgs([]string{
		"--mode", "live",
		"--iface", "eth0",
		"--api-url", "http://172.18.0.20:8000/api/v1/ingest/windows",
		"--collector-id", "go-sensor-docker0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "live" || cfg.Iface != "eth0" || cfg.CollectorID != "go-sensor-docker0" {
		t.Fatalf("%+v", cfg)
	}
	if cfg.APIURL != defaultAPIURL || cfg.WindowSize != 100 || cfg.Stride != 100 || cfg.ReplaySpeed != 1 {
		t.Fatalf("defaults %+v", cfg)
	}
	if cfg.captureMode() != "LIVE_INTERFACE" || cfg.sourceType() != "live" {
		t.Fatalf("provenance %s %s", cfg.captureMode(), cfg.sourceType())
	}
}

func TestParsePCAPReplayFlags(t *testing.T) {
	cfg, err := parseArgs([]string{
		"--mode", "pcap",
		"--pcap-file", "captures/lab.pcapng",
		"--replay-speed", "0",
		"--api-url", defaultAPIURL,
		"--collector-id", "go-sensor-docker0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PcapFile != "captures/lab.pcapng" || cfg.ReplaySpeed != 0 {
		t.Fatalf("%+v", cfg)
	}
	if cfg.captureMode() != "PCAP_REPLAY" || cfg.sourceType() != "pcap" {
		t.Fatalf("provenance %s %s", cfg.captureMode(), cfg.sourceType())
	}
}

func TestStrideMatchesTumblingWindow(t *testing.T) {
	_, err := parseArgs([]string{
		"--mode", "pcap",
		"--pcap-file", "x.pcap",
		"--stride", "50",
	})
	if err == nil || !strings.Contains(err.Error(), "stride") {
		t.Fatalf("error = %v, want stride rejection", err)
	}
	_, err = parseArgs([]string{
		"--mode", "pcap",
		"--pcap-file", "x.pcap",
		"--window-size", "50",
		"--stride", "50",
	})
	if err == nil || !strings.Contains(err.Error(), "window-size") {
		t.Fatalf("error = %v, want locked window size", err)
	}
}

func TestModeRequiresSource(t *testing.T) {
	if _, err := parseArgs([]string{"--mode", "live"}); err == nil {
		t.Fatal("live without --iface")
	}
	if _, err := parseArgs([]string{"--mode", "pcap"}); err == nil {
		t.Fatal("pcap without --pcap-file")
	}
	if _, err := parseArgs([]string{"--mode", "csv", "--iface", "eth0"}); err == nil {
		t.Fatal("unknown mode accepted")
	}
}
