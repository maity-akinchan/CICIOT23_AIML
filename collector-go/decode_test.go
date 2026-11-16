package main

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func serializeLayers(t *testing.T, seq ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, seq...); err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return buf.Bytes()
}

func testEthernet() *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x32},
		DstMAC:       net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x0a},
		EthernetType: layers.EthernetTypeIPv4,
	}
}

func testIPv4(proto layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: proto,
		SrcIP:    net.IP{172, 18, 0, 50},
		DstIP:    net.IP{172, 18, 0, 10},
	}
}

func testTCP() *layers.TCP {
	return &layers.TCP{
		SrcPort: 40000,
		DstPort: 80,
		SYN:     true,
		Seq:     1,
		Window:  65535,
	}
}

func captureAt(data []byte, wire int) gopacket.CaptureInfo {
	return gopacket.CaptureInfo{
		Timestamp:      time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		CaptureLength:  len(data),
		Length:         wire,
		InterfaceIndex: 0,
	}
}

func TestDecodeCleanSYN(t *testing.T) {
	ip := testIPv4(layers.IPProtocolTCP)
	tcp := testTCP()
	tcp.SetNetworkLayerForChecksum(ip)
	frame := serializeLayers(t, testEthernet(), ip, tcp)
	// gopacket pads Ethernet to 60 bytes. The contract fixture is the unpadded
	// 14+20+20 SYN, and wire length comes from capture metadata.
	if len(frame) < 54 {
		t.Fatalf("ethernet SYN length = %d, want at least 54", len(frame))
	}
	frame = frame[:54]
	pkt, err := Decode(layers.LinkTypeEthernet, frame, captureAt(frame, 54))
	if err != nil {
		t.Fatal(err)
	}
	if pkt.WireBytes != 54 || pkt.HeaderBytes != 40 || pkt.TTL != 64 {
		t.Fatalf("wire/header/ttl = %d/%d/%d, want 54/40/64", pkt.WireBytes, pkt.HeaderBytes, pkt.TTL)
	}
	if pkt.Protocol != "TCP" || pkt.TCPFlags != flagSYN || pkt.SrcPort != 40000 || pkt.DstPort != 80 {
		t.Fatalf("flow = %+v", pkt)
	}
	if pkt.SrcIP != "172.18.0.50" || pkt.DstIP != "172.18.0.10" {
		t.Fatalf("endpoints %s -> %s", pkt.SrcIP, pkt.DstIP)
	}
	if pkt.SrcMAC != "02:00:00:00:00:32" || pkt.DstMAC != "02:00:00:00:00:0a" {
		t.Fatalf("mac %s -> %s", pkt.SrcMAC, pkt.DstMAC)
	}
}

func TestDecodeSYNHeaderCutTo30BytesErrors(t *testing.T) {
	ip := testIPv4(layers.IPProtocolTCP)
	tcp := testTCP()
	tcp.SetNetworkLayerForChecksum(ip)
	frame := serializeLayers(t, testEthernet(), ip, tcp)
	cut := frame[:30]
	_, err := Decode(layers.LinkTypeEthernet, cut, captureAt(cut, len(cut)))
	if err == nil {
		t.Fatal("30-byte SYN header was accepted")
	}
	if !errors.Is(err, errTruncated) && !errors.Is(err, errMalformed) && !errors.Is(err, errUnsupported) {
		t.Fatalf("error = %v, want truncated, malformed, or unsupported", err)
	}
}

func TestDecodePayloadTruncatedTo54BytesKeepsWireLength(t *testing.T) {
	ip := testIPv4(layers.IPProtocolTCP)
	tcp := testTCP()
	tcp.SetNetworkLayerForChecksum(ip)
	payload := make([]byte, 100)
	frame := serializeLayers(t, testEthernet(), ip, tcp, gopacket.Payload(payload))
	if len(frame) <= 54 {
		t.Fatalf("frame length = %d, want a payload past the 54-byte headers", len(frame))
	}
	snapped := frame[:54]
	ci := captureAt(snapped, len(frame))
	if !payloadTruncated(snapped, ci) {
		t.Fatal("expected caplen < wirelen")
	}
	pkt, err := Decode(layers.LinkTypeEthernet, snapped, ci)
	if err != nil {
		t.Fatalf("header-complete snaplen was rejected: %v", err)
	}
	if pkt.WireBytes != len(frame) {
		t.Fatalf("WireBytes = %d, want original wire length %d", pkt.WireBytes, len(frame))
	}
	if pkt.HeaderBytes != 40 {
		t.Fatalf("HeaderBytes = %d, want 40", pkt.HeaderBytes)
	}
	if pkt.Protocol != "TCP" || pkt.TCPFlags != flagSYN {
		t.Fatalf("decoded %+v", pkt)
	}
	if pkt.WireBytes == len(snapped) {
		t.Fatal("WireBytes followed the truncated capture length")
	}
}

func TestDecodeTCPOptionsIncludedInHeaderLength(t *testing.T) {
	ip := testIPv4(layers.IPProtocolTCP)
	tcp := testTCP()
	tcp.Options = []layers.TCPOption{{
		OptionType:   layers.TCPOptionKindMSS,
		OptionLength: 4,
		OptionData:   []byte{0x05, 0xb4},
	}}
	tcp.SetNetworkLayerForChecksum(ip)
	frame := serializeLayers(t, testEthernet(), ip, tcp)
	pkt, err := Decode(layers.LinkTypeEthernet, frame, captureAt(frame, len(frame)))
	if err != nil {
		t.Fatal(err)
	}
	if pkt.HeaderBytes != 44 {
		t.Fatalf("HeaderBytes = %d, want 44 (20 IP + 24 TCP with MSS)", pkt.HeaderBytes)
	}
}

func TestDecodeFragmentedIPv4WithTCPIsRejected(t *testing.T) {
	ip := testIPv4(layers.IPProtocolTCP)
	ip.Flags = layers.IPv4MoreFragments
	ip.FragOffset = 0
	tcp := testTCP()
	tcp.SetNetworkLayerForChecksum(ip)
	frame := serializeLayers(t, testEthernet(), ip, tcp)
	_, err := Decode(layers.LinkTypeEthernet, frame, captureAt(frame, len(frame)))
	if !errors.Is(err, errFragment) {
		t.Fatalf("error = %v, want fragment", err)
	}
}

func TestDecodeGREIsNotTCP(t *testing.T) {
	ip := testIPv4(layers.IPProtocolGRE)
	// Four-byte GRE header, protocol type 0, no inner frame.
	frame := serializeLayers(t, testEthernet(), ip, gopacket.Payload{0x00, 0x00, 0x00, 0x00})
	_, err := Decode(layers.LinkTypeEthernet, frame, captureAt(frame, len(frame)))
	if err == nil {
		t.Fatal("GRE packet was accepted")
	}
	if !errors.Is(err, errUnsupported) && !errors.Is(err, errMalformed) {
		t.Fatalf("error = %v, want unsupported or malformed", err)
	}
	if errors.Is(err, errFragment) {
		t.Fatalf("GRE was classified as a fragment: %v", err)
	}
}

func TestDecodeMalformedHeader(t *testing.T) {
	frame := make([]byte, 64)
	frame[12], frame[13] = 0x08, 0x00
	frame[14] = 0x40 // IPv4 with IHL 0
	_, err := Decode(layers.LinkTypeEthernet, frame, captureAt(frame, len(frame)))
	if err == nil {
		t.Fatal("malformed IPv4 header was accepted")
	}
}

func TestDecodeMissingWireLength(t *testing.T) {
	ip := testIPv4(layers.IPProtocolTCP)
	tcp := testTCP()
	tcp.SetNetworkLayerForChecksum(ip)
	frame := serializeLayers(t, testEthernet(), ip, tcp)
	for _, wire := range []int{0, -1} {
		_, err := Decode(layers.LinkTypeEthernet, frame, captureAt(frame, wire))
		if !errors.Is(err, errNoWireLength) {
			t.Fatalf("wire length %d: error = %v, want missing wire length", wire, err)
		}
	}
}

func TestDecodeUnsupportedLink(t *testing.T) {
	_, err := Decode(layers.LinkTypeIEEE802_11, []byte{0, 1, 2, 3}, captureAt([]byte{0, 1, 2, 3}, 4))
	if !errors.Is(err, errUnsupported) {
		t.Fatalf("error = %v, want unsupported link", err)
	}
}

func TestDecodeDoesNotPanic(t *testing.T) {
	cases := [][]byte{nil, {}, {0xff}, make([]byte, 14)}
	for _, data := range cases {
		wire := len(data)
		if wire == 0 {
			wire = 1
		}
		_, err := Decode(layers.LinkTypeEthernet, data, captureAt(data, wire))
		if err == nil {
			t.Fatalf("accepted %d bytes", len(data))
		}
	}
}

func TestDecodeUDPAndICMP(t *testing.T) {
	ip := testIPv4(layers.IPProtocolUDP)
	udp := &layers.UDP{SrcPort: 9000, DstPort: 53}
	udp.SetNetworkLayerForChecksum(ip)
	udpFrame := serializeLayers(t, testEthernet(), ip, udp)
	udpPkt, err := Decode(layers.LinkTypeEthernet, udpFrame, captureAt(udpFrame, len(udpFrame)))
	if err != nil {
		t.Fatal(err)
	}
	if udpPkt.Protocol != "UDP" || udpPkt.HeaderBytes != 28 || udpPkt.SrcPort != 9000 || udpPkt.DstPort != 53 {
		t.Fatalf("udp = %+v", udpPkt)
	}

	icmpIP := testIPv4(layers.IPProtocolICMPv4)
	icmp := &layers.ICMPv4{
		TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		Id:       1,
		Seq:      1,
	}
	icmpFrame := serializeLayers(t, testEthernet(), icmpIP, icmp)
	icmpPkt, err := Decode(layers.LinkTypeEthernet, icmpFrame, captureAt(icmpFrame, len(icmpFrame)))
	if err != nil {
		t.Fatal(err)
	}
	if icmpPkt.Protocol != "ICMP" || icmpPkt.HeaderBytes != 28 || icmpPkt.SrcPort != 0 || icmpPkt.DstPort != 0 {
		t.Fatalf("icmp = %+v", icmpPkt)
	}
}

func TestDecodeIPv6HopLimit(t *testing.T) {
	eth := testEthernet()
	eth.EthernetType = layers.EthernetTypeIPv6
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   32,
		NextHeader: layers.IPProtocolTCP,
		SrcIP:      net.ParseIP("2001:db8::50"),
		DstIP:      net.ParseIP("2001:db8::10"),
	}
	tcp := testTCP()
	tcp.SetNetworkLayerForChecksum(ip)
	frame := serializeLayers(t, eth, ip, tcp)
	pkt, err := Decode(layers.LinkTypeEthernet, frame, captureAt(frame, len(frame)))
	if err != nil {
		t.Fatal(err)
	}
	if pkt.TTL != 32 || pkt.Protocol != "TCP" || pkt.HeaderBytes != 60 {
		t.Fatalf("ipv6 = %+v, want hop 32 header 60", pkt)
	}
	if pkt.SrcIP != net.ParseIP("2001:db8::50").String() || pkt.DstIP != net.ParseIP("2001:db8::10").String() {
		t.Fatalf("ipv6 endpoints %s -> %s", pkt.SrcIP, pkt.DstIP)
	}
}
