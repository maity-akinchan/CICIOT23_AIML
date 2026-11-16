package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func schemaWindow(t *testing.T) Window {
	t.Helper()
	agg, out, _ := testAggregator("pcap")
	for _, pkt := range flowPackets(100, "TCP", flagSYN, 54, 40, 64, 100*time.Microsecond) {
		agg.Add(pkt)
	}
	select {
	case w := <-out:
		return w
	default:
		t.Fatal("no window")
		return Window{}
	}
}

func TestIngestJSONMatchesFastAPISchema(t *testing.T) {
	window := schemaWindow(t)
	cfg := Config{
		Mode:        "pcap",
		PcapFile:    "fixture.pcap",
		APIURL:      defaultAPIURL,
		CollectorID: defaultCollectorID,
		WindowSize:  defaultWindowSize,
		Stride:      defaultWindowSize,
	}
	body, err := encodeBatch(cfg, cfg.CollectorID, cfg.captureMode(), "session01", "Ethernet", &Stats{}, []Window{window})
	if err != nil {
		t.Fatal(err)
	}

	var top map[string]any
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatal(err)
	}
	assertKeys(t, "batch", top, "collector_id", "capture_mode", "source_ref", "windows")
	if top["collector_id"] != defaultCollectorID || top["capture_mode"] != "PCAP_REPLAY" {
		t.Fatalf("identity = %v %v", top["collector_id"], top["capture_mode"])
	}
	ref, _ := top["source_ref"].(string)
	for _, part := range []string{
		"schema_version=" + schemaVersion,
		"feature_contract_id=" + contractID,
		"extractor_version=" + extractorVersion,
		"source_type=pcap",
	} {
		if !strings.Contains(ref, part) {
			t.Fatalf("source_ref %q missing %s", ref, part)
		}
	}

	windows, _ := top["windows"].([]any)
	if len(windows) != 1 {
		t.Fatalf("windows = %#v", top["windows"])
	}
	rawWindow, _ := windows[0].(map[string]any)
	assertKeys(t, "window", rawWindow, "window_id", "timestamp_start", "timestamp_end", "packet_count", "metadata", "features_18")
	if rawWindow["packet_count"].(float64) != 100 {
		t.Fatalf("packet_count = %v", rawWindow["packet_count"])
	}

	meta, _ := rawWindow["metadata"].(map[string]any)
	assertKeys(t, "metadata", meta, "src_ip", "dst_ip", "src_mac", "dst_mac", "src_port", "dst_port", "dominant_protocol", "device_vendor")
	if meta["src_ip"] != "172.18.0.50" || meta["dst_ip"] != "172.18.0.10" || meta["dominant_protocol"] != "TCP" {
		t.Fatalf("metadata = %#v", meta)
	}
	if meta["device_vendor"] != "" {
		t.Fatalf("device_vendor = %v, packet bytes must not invent a vendor", meta["device_vendor"])
	}

	features, _ := rawWindow["features_18"].(map[string]any)
	if len(features) != len(baseFeatureNames) {
		t.Fatalf("features_18 has %d keys, want %d", len(features), len(baseFeatureNames))
	}
	for _, name := range baseFeatureNames {
		if _, ok := features[name].(float64); !ok {
			t.Fatalf("features_18[%s] = %#v, want a JSON number", name, features[name])
		}
	}
	for _, derived := range []string{"bytes_per_sec", "syn_ack_ratio", "hdr_pkt_ratio", "pkt_cv"} {
		if _, ok := features[derived]; ok {
			t.Fatalf("collector shipped derived feature %s", derived)
		}
	}
	nearly(t, "Header_Length", features["Header_Length"].(float64), 40)
	nearly(t, "AVG", features["AVG"].(float64), 54)
	nearly(t, "syn_count", features["syn_count"].(float64), 100)
	nearly(t, "syn_flag_number", features["syn_flag_number"].(float64), 1)
	nearly(t, "Std", features["Std"].(float64), 0)

	var roundTrip ingestRequest
	if err := json.Unmarshal(body, &roundTrip); err != nil {
		t.Fatal(err)
	}
	if roundTrip.Windows[0].Features.Rate <= 0 || roundTrip.Windows[0].Metadata.SrcMAC == "" {
		t.Fatalf("round trip lost fields: %+v", roundTrip.Windows[0])
	}
}

func TestShipperPostsSchemaBatch(t *testing.T) {
	window := schemaWindow(t)
	var got ingestRequest
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type %s", r.Header.Get("Content-Type"))
		}
		defer r.Body.Close()
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("decode: %v", err)
		}
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := Config{Mode: "live", Iface: "eth0", APIURL: server.URL, CollectorID: "go-sensor-docker0", WindowSize: 100, Stride: 100}
	ship := newShipper(cfg, "session01", "Ethernet", &Stats{})
	if err := ship.post([]Window{window}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want one retry after 503", calls)
	}
	if got.CaptureMode != "LIVE_INTERFACE" || got.CollectorID != "go-sensor-docker0" || len(got.Windows) != 1 {
		t.Fatalf("posted %#v", got)
	}
	if !strings.Contains(got.SourceRef, "source_type=live") {
		t.Fatalf("source_ref = %s", got.SourceRef)
	}
	if ship.stats.HTTPSuccess.Load() != 1 || ship.stats.HTTPFailures.Load() != 0 {
		t.Fatalf("http ok=%d fail=%d", ship.stats.HTTPSuccess.Load(), ship.stats.HTTPFailures.Load())
	}
}

func TestShipperStopsOnValidationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "field required", http.StatusUnprocessableEntity)
	}))
	defer server.Close()
	cfg := Config{Mode: "pcap", PcapFile: "x.pcap", APIURL: server.URL, CollectorID: "go-sensor-docker0", WindowSize: 100, Stride: 100}
	ship := newShipper(cfg, "session01", "Ethernet", &Stats{})
	err := ship.post([]Window{schemaWindow(t)})
	var stop *stopShippingError
	if !asStop(err, &stop) {
		t.Fatalf("error = %v, want permanent validation stop", err)
	}
	if ship.stats.HTTPFailures.Load() != 1 {
		t.Fatalf("http failures = %d", ship.stats.HTTPFailures.Load())
	}
}

func assertKeys(t *testing.T, label string, doc map[string]any, keys ...string) {
	t.Helper()
	if len(doc) != len(keys) {
		t.Fatalf("%s keys = %v, want %v", label, mapKeys(doc), keys)
	}
	for _, key := range keys {
		if _, ok := doc[key]; !ok {
			t.Fatalf("%s missing %s in %v", label, key, mapKeys(doc))
		}
	}
}

func mapKeys(doc map[string]any) []string {
	out := make([]string, 0, len(doc))
	for key := range doc {
		out = append(out, key)
	}
	return out
}
