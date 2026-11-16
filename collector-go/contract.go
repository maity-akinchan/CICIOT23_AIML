package main

// sentinel-pcap22-v2 is the candidate capture contract. It is not the legacy
// CSV contract ciciot23-csv22-v1, and these vectors must not be presented as
// rows from that artifact. The serving API derives the four ratios; the
// collector ships only the 18 base measurements.
const (
	contractID       = "sentinel-pcap22-v2"
	extractorVersion = "collector-go/1.0.0"
	schemaVersion    = "legacy-ingest-v1"

	defaultAPIURL       = "http://172.18.0.20:8000/api/v1/ingest/windows"
	defaultCollectorID  = "go-sensor-docker0"
	defaultWindowSize   = 100
	minWindowPackets    = 5
	windowTimeoutSecond = 2.0

	maxBatchWindows = 100
	maxActiveFlows  = 4096
	packetQueue     = 65536
	windowQueue     = 4096

	httpAttempts = 3
)

// baseFeatureNames is the locked order and casing of the 18 base features.
var baseFeatureNames = []string{
	"flow_duration", "Rate", "Header_Length", "Duration",
	"fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number", "ack_flag_number",
	"ack_count", "syn_count", "fin_count", "rst_count",
	"TCP", "UDP", "ICMP",
	"AVG", "Std",
}
