package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	errMalformed    = errors.New("malformed packet")
	errTruncated    = errors.New("truncated header")
	errUnsupported  = errors.New("unsupported packet")
	errFragment     = errors.New("ip fragment")
	errNoWireLength = errors.New("missing original wire length")
)

// supportedLink reports link types this collector decodes.
// Ethernet, loopback, raw IPv4/IPv6, and Linux cooked capture are supported.
// Linux SLL2 (276) is not decoded by gopacket v1.1.19, so it stays unsupported
// instead of being mistaken for Ethernet. Other link types are rejected.
func supportedLink(link layers.LinkType) bool {
	switch link {
	case layers.LinkTypeEthernet,
		layers.LinkTypeNull,
		layers.LinkTypeRaw,
		layers.LinkTypeIPv4,
		layers.LinkTypeIPv6,
		layers.LinkTypeLinuxSLL:
		return true
	default:
		return link == layers.LinkType(12) // DLT_RAW on some BSD captures
	}
}

func supportedLinkNames() string {
	return "loopback (0), Ethernet (1), DLT_RAW (12), LINKTYPE_RAW (101), IPv4 (228), IPv6 (229), Linux SLL (113); Linux SLL2 (276) is unsupported"
}

// Decode parses one captured frame. It never panics on short or corrupt input.
// A payload shorter than the original wire length is accepted when the network
// and transport headers are complete. Header truncation, fragments, and unknown
// transports are returned as errors so they cannot be counted as TCP.
func Decode(link layers.LinkType, data []byte, ci gopacket.CaptureInfo) (pkt Packet, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%w: %v", errMalformed, recovered)
		}
	}()
	if !supportedLink(link) {
		return Packet{}, fmt.Errorf("%w: link type %s (%d)", errUnsupported, link, uint32(link))
	}
	if ci.Length <= 0 {
		return Packet{}, errNoWireLength
	}
	packet := gopacket.NewPacket(data, link, gopacket.DecodeOptions{Lazy: false, NoCopy: true})
	decoded, err := interpret(packet)
	if err != nil {
		if packet.Metadata().Truncated && !errors.Is(err, errFragment) && !errors.Is(err, errUnsupported) {
			return Packet{}, fmt.Errorf("%w: %v", errTruncated, err)
		}
		return Packet{}, err
	}
	// A snaplen shorter than the original frame is acceptable once the network
	// and transport headers are complete. Wire length stays ci.Length.
	if ci.Length < decoded.HeaderBytes {
		return Packet{}, errTruncated
	}
	decoded.Timestamp = ci.Timestamp.UTC()
	decoded.WireBytes = ci.Length
	return decoded, nil
}

func interpret(packet gopacket.Packet) (Packet, error) {
	var (
		out         Packet
		sawNet      bool
		netHeader   int
		transHeader int
		fragment    bool
	)
	for _, layer := range packet.Layers() {
		switch l := layer.(type) {
		case *layers.Ethernet:
			out.SrcMAC = l.SrcMAC.String()
			out.DstMAC = l.DstMAC.String()
		case *layers.Dot1Q:
			// VLAN tags stay in the link header and are not part of Header_Length.
		case *layers.LinuxSLL:
			out.SrcMAC = macString(l.Addr)
		case *layers.IPv4:
			if l.Flags&layers.IPv4MoreFragments != 0 || l.FragOffset != 0 {
				fragment = true
			}
			claimed := int(l.IHL) * 4
			if claimed < 20 || len(l.Contents) < claimed {
				return Packet{}, errTruncated
			}
			sawNet = true
			netHeader = claimed
			out.TTL = int(l.TTL)
			out.SrcIP = l.SrcIP.String()
			out.DstIP = l.DstIP.String()
		case *layers.IPv6:
			if len(l.Contents) < 40 {
				return Packet{}, errTruncated
			}
			sawNet = true
			netHeader = 40
			out.TTL = int(l.HopLimit)
			out.SrcIP = l.SrcIP.String()
			out.DstIP = l.DstIP.String()
		case *layers.IPv6HopByHop:
			n, err := extensionLen(l.Contents)
			if err != nil {
				return Packet{}, err
			}
			netHeader += n
		case *layers.IPv6Destination:
			n, err := extensionLen(l.Contents)
			if err != nil {
				return Packet{}, err
			}
			netHeader += n
		case *layers.IPv6Routing:
			n, err := extensionLen(l.Contents)
			if err != nil {
				return Packet{}, err
			}
			netHeader += n
		case *layers.IPv6Fragment:
			return Packet{}, errFragment
		case *layers.TCP:
			claimed := int(l.DataOffset) * 4
			if claimed < 20 || len(l.Contents) < claimed {
				return Packet{}, errTruncated
			}
			transHeader = claimed
			out.Protocol = "TCP"
			out.SrcPort = int(l.SrcPort)
			out.DstPort = int(l.DstPort)
			out.TCPFlags = tcpFlags(l)
		case *layers.UDP:
			if len(l.Contents) < 8 {
				return Packet{}, errTruncated
			}
			transHeader = 8
			out.Protocol = "UDP"
			out.SrcPort = int(l.SrcPort)
			out.DstPort = int(l.DstPort)
		case *layers.ICMPv4:
			// ICMPv4 header is 8 bytes (RFC 792).
			if len(l.Contents) < 8 {
				return Packet{}, errTruncated
			}
			transHeader = 8
			out.Protocol = "ICMP"
		case *layers.ICMPv6:
			// ICMPv6 fixed header is 4 bytes (RFC 4443). Echo identifiers are message body.
			if len(l.Contents) < 4 {
				return Packet{}, errTruncated
			}
			transHeader = 4
			out.Protocol = "ICMP"
		case *layers.GRE:
			// GRE is not a supported transport. Do not walk an inner frame and
			// classify it as TCP, UDP, or ICMP.
			return Packet{}, fmt.Errorf("%w: GRE", errUnsupported)
		}
	}
	if fragment {
		return Packet{}, errFragment
	}
	if !sawNet || out.Protocol == "" || out.SrcIP == "" || out.DstIP == "" {
		if packet.ErrorLayer() != nil {
			return Packet{}, fmt.Errorf("%w: %v", errMalformed, packet.ErrorLayer().Error())
		}
		return Packet{}, errUnsupported
	}
	if netHeader <= 0 || transHeader <= 0 {
		return Packet{}, errTruncated
	}
	out.HeaderBytes = netHeader + transHeader
	out.TransportBytes = transHeader
	return out, nil
}

func extensionLen(contents []byte) (int, error) {
	if len(contents) == 0 {
		return 0, fmt.Errorf("%w: empty IPv6 extension", errUnsupported)
	}
	return len(contents), nil
}

func macString(addr []byte) string {
	if len(addr) < 6 {
		return ""
	}
	return net.HardwareAddr(addr[:6]).String()
}

// payloadTruncated reports a capture whose saved bytes are shorter than the
// original on-wire length. Header-complete packets stay usable; callers must
// keep ci.Length as WireBytes instead of substituting the snaplen.
func payloadTruncated(data []byte, ci gopacket.CaptureInfo) bool {
	captured := ci.CaptureLength
	if captured <= 0 {
		captured = len(data)
	}
	return ci.Length > captured
}

func tcpFlags(tcp *layers.TCP) uint8 {
	var flags uint8
	if tcp.FIN {
		flags |= flagFIN
	}
	if tcp.SYN {
		flags |= flagSYN
	}
	if tcp.RST {
		flags |= flagRST
	}
	if tcp.PSH {
		flags |= flagPSH
	}
	if tcp.ACK {
		flags |= flagACK
	}
	return flags
}
