package main

import "time"

// Features18 is the JSON object stored at features_18. Field names match
// Features18Payload in backend-fastapi/app/schemas.py. Derived ratios are omitted.
type Features18 struct {
	FlowDuration  float64 `json:"flow_duration"`
	Rate          float64 `json:"Rate"`
	HeaderLength  float64 `json:"Header_Length"`
	Duration      float64 `json:"Duration"`
	FinFlagNumber float64 `json:"fin_flag_number"`
	SynFlagNumber float64 `json:"syn_flag_number"`
	RstFlagNumber float64 `json:"rst_flag_number"`
	PshFlagNumber float64 `json:"psh_flag_number"`
	AckFlagNumber float64 `json:"ack_flag_number"`
	AckCount      float64 `json:"ack_count"`
	SynCount      float64 `json:"syn_count"`
	FinCount      float64 `json:"fin_count"`
	RstCount      float64 `json:"rst_count"`
	TCP           float64 `json:"TCP"`
	UDP           float64 `json:"UDP"`
	ICMP          float64 `json:"ICMP"`
	AVG           float64 `json:"AVG"`
	Std           float64 `json:"Std"`
}

// Metadata is an observed endpoint, never a majority vote across a window.
// device_vendor is always empty: packet bytes do not establish a vendor.
type Metadata struct {
	SrcIP            string `json:"src_ip"`
	DstIP            string `json:"dst_ip"`
	SrcMAC           string `json:"src_mac"`
	DstMAC           string `json:"dst_mac"`
	SrcPort          int    `json:"src_port"`
	DstPort          int    `json:"dst_port"`
	DominantProtocol string `json:"dominant_protocol"`
	DeviceVendor     string `json:"device_vendor"`
}

// Window is one CollectorWindow. window_id stays stable across HTTP retries.
type Window struct {
	WindowID       string     `json:"window_id"`
	TimestampStart time.Time  `json:"timestamp_start"`
	TimestampEnd   time.Time  `json:"timestamp_end"`
	PacketCount    int        `json:"packet_count"`
	Metadata       Metadata   `json:"metadata"`
	Features       Features18 `json:"features_18"`
}

// ingestRequest is IngestBatchRequest. Unknown JSON fields are rejected by the API.
type ingestRequest struct {
	CollectorID string   `json:"collector_id"`
	CaptureMode string   `json:"capture_mode"`
	SourceRef   string   `json:"source_ref"`
	Windows     []Window `json:"windows"`
}

// Packet is one accepted packet after header validation.
// WireBytes is the original on-wire length from capture metadata, not caplen.
// HeaderBytes is the measured network plus transport header, including TCP
// options and supported IPv6 extension headers, excluding the link header.
type Packet struct {
	Timestamp   time.Time
	WireBytes   int
	HeaderBytes int
	TTL         int
	SrcIP       string
	DstIP       string
	SrcMAC      string
	DstMAC      string
	SrcPort     int
	DstPort     int
	Protocol    string
	TCPFlags    uint8
}

const (
	flagFIN uint8 = 0x01
	flagSYN uint8 = 0x02
	flagRST uint8 = 0x04
	flagPSH uint8 = 0x08
	flagACK uint8 = 0x10
)

// FlowKey is the directed observation key: source, destination, protocol and ports.
// ICMP has no ports; both ICMPv4 and ICMPv6 use protocol ICMP and ports 0.
// The IP version is already distinguished by the address text.
type FlowKey struct {
	SrcIP    string
	DstIP    string
	Protocol string
	SrcPort  int
	DstPort  int
}

func (p Packet) Key() FlowKey {
	return FlowKey{
		SrcIP: p.SrcIP, DstIP: p.DstIP, Protocol: p.Protocol,
		SrcPort: p.SrcPort, DstPort: p.DstPort,
	}
}
