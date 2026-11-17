package main

import (
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"strconv"
	"time"
)

// Aggregator closes each directed flow after 100 packets or 2 seconds of event
// time, and flushes the remainder at EOF. Windows with fewer than 5 packets are
// counted as insufficient and are not sent for classification.
//
// Out-of-order policy: a packet joins the open window when the resulting
// earliest-to-latest span stays under 2 seconds. A later timestamp at or beyond
// 2 seconds closes the current window and starts the next one. A timestamp that
// would stretch the span to 2 seconds backward is counted as late and dropped.
// Duration always uses the latest minus the earliest timestamp in the window.
type Aggregator struct {
	windowSize int
	minPackets int
	timeout    time.Duration
	wallClock  bool
	session    string
	apiHost    string
	apiPort    int
	out        chan<- Window
	stats      *Stats
	flows      map[FlowKey]*flowWin
	seq        map[FlowKey]int
}

type flowWin struct {
	key     FlowKey
	packets []Packet
	minTS   time.Time
	maxTS   time.Time
	opened  time.Time
	seq     int
}

func newAggregator(cfg Config, session string, out chan<- Window, stats *Stats) *Aggregator {
	host, port := splitAPI(cfg.APIURL)
	return &Aggregator{
		windowSize: cfg.WindowSize,
		minPackets: minWindowPackets,
		timeout:    time.Duration(windowTimeoutSecond * float64(time.Second)),
		wallClock:  cfg.Mode == "live",
		session:    session,
		apiHost:    host,
		apiPort:    port,
		out:        out,
		stats:      stats,
		flows:      make(map[FlowKey]*flowWin),
		seq:        make(map[FlowKey]int),
	}
}

func (a *Aggregator) Add(p Packet) {
	if a.isControl(p) {
		a.stats.Control.Add(1)
		a.stats.Skipped.Add(1)
		return
	}
	key := p.Key()
	st := a.flows[key]
	if st != nil && !p.Timestamp.IsZero() && !st.minTS.IsZero() {
		start, end := st.minTS, st.maxTS
		if p.Timestamp.Before(start) {
			start = p.Timestamp
		}
		if p.Timestamp.After(end) {
			end = p.Timestamp
		}
		if end.Sub(start) >= a.timeout {
			if p.Timestamp.Before(st.minTS) {
				a.stats.Late.Add(1)
				return
			}
			a.finish(st)
			st = nil
		} else if p.Timestamp.Before(st.maxTS) {
			a.stats.Late.Add(1)
		}
	}
	if st == nil {
		if len(a.flows) >= maxActiveFlows {
			a.evictOldest()
		}
		st = &flowWin{
			key:     key,
			opened:  time.Now().UTC(),
			seq:     a.seq[key],
			packets: make([]Packet, 0, a.windowSize),
		}
		a.seq[key] = st.seq + 1
		a.flows[key] = st
		if len(a.seq) > maxActiveFlows*4 {
			a.pruneSeq()
		}
	}
	st.packets = append(st.packets, p)
	if !p.Timestamp.IsZero() {
		if st.minTS.IsZero() || p.Timestamp.Before(st.minTS) {
			st.minTS = p.Timestamp
		}
		if p.Timestamp.After(st.maxTS) {
			st.maxTS = p.Timestamp
		}
	}
	if len(st.packets) >= a.windowSize {
		a.finish(st)
	}
}

// FlushIdle closes live flows that have been open for the timeout without a
// later packet to advance event time. Offline replay uses event time and EOF
// only, so a fast replay cannot split windows on wall-clock processing time.
func (a *Aggregator) FlushIdle(now time.Time) {
	if !a.wallClock {
		return
	}
	for _, st := range a.snapshot() {
		if now.Sub(st.opened) >= a.timeout {
			a.finish(st)
		}
	}
}

// FlushEOF closes every open flow. Short flows are not emitted.
func (a *Aggregator) FlushEOF() {
	for _, st := range a.snapshot() {
		a.finish(st)
	}
}

func (a *Aggregator) snapshot() []*flowWin {
	out := make([]*flowWin, 0, len(a.flows))
	for _, st := range a.flows {
		out = append(out, st)
	}
	return out
}

func (a *Aggregator) evictOldest() {
	var oldest *flowWin
	for _, st := range a.flows {
		if oldest == nil || st.opened.Before(oldest.opened) {
			oldest = st
		}
	}
	if oldest != nil {
		a.finish(oldest)
	}
}

func (a *Aggregator) pruneSeq() {
	for key := range a.seq {
		if _, open := a.flows[key]; !open {
			delete(a.seq, key)
		}
	}
}

func (a *Aggregator) finish(st *flowWin) {
	if _, ok := a.flows[st.key]; ok {
		delete(a.flows, st.key)
	}
	if len(st.packets) < a.minPackets {
		a.stats.WindowsInsufficient.Add(1)
		return
	}
	window, err := buildWindow(a.session, st)
	if err != nil {
		a.stats.Skipped.Add(uint64(len(st.packets)))
		return
	}
	select {
	case a.out <- window:
		a.stats.WindowsEmitted.Add(1)
	default:
		a.stats.WindowsDropped.Add(1)
	}
}

func buildWindow(session string, st *flowWin) (Window, error) {
	features, err := Compute(st.packets)
	if err != nil {
		return Window{}, err
	}
	start, end := st.minTS, st.maxTS
	if start.IsZero() {
		start = st.opened
		end = st.opened
	}
	var srcMAC, dstMAC string
	for _, p := range st.packets {
		if srcMAC == "" && p.SrcMAC != "" {
			srcMAC = p.SrcMAC
		}
		if dstMAC == "" && p.DstMAC != "" {
			dstMAC = p.DstMAC
		}
	}
	protocol := st.key.Protocol
	if protocol != "TCP" && protocol != "UDP" && protocol != "ICMP" {
		return Window{}, fmt.Errorf("protocol %q is not a schema literal", protocol)
	}
	var transportMean float64
	for _, p := range st.packets {
		transportMean += float64(p.TransportBytes)
	}
	transportMean /= float64(len(st.packets))
	return Window{
		WindowID:       windowID(session, st.key, st.seq, start),
		TimestampStart: start.UTC(),
		TimestampEnd:   end.UTC(),
		PacketCount:    len(st.packets),
		Metadata: Metadata{
			TransportHeaderMean: transportMean,
			SrcIP:               st.key.SrcIP,
			DstIP:               st.key.DstIP,
			SrcMAC:              srcMAC,
			DstMAC:              dstMAC,
			SrcPort:             st.key.SrcPort,
			DstPort:             st.key.DstPort,
			DominantProtocol:    protocol,
		},
		Features: features,
	}, nil
}

func windowID(session string, key FlowKey, seq int, start time.Time) string {
	hash := fnv.New32a()
	_, _ = io.WriteString(hash, key.SrcIP)
	_, _ = io.WriteString(hash, ">")
	_, _ = io.WriteString(hash, key.DstIP)
	_, _ = io.WriteString(hash, "/")
	_, _ = io.WriteString(hash, key.Protocol)
	_, _ = io.WriteString(hash, "/")
	_, _ = io.WriteString(hash, strconv.Itoa(key.SrcPort))
	_, _ = io.WriteString(hash, ">")
	_, _ = io.WriteString(hash, strconv.Itoa(key.DstPort))
	_, _ = io.WriteString(hash, "@")
	_, _ = io.WriteString(hash, start.UTC().Format(time.RFC3339Nano))
	_, _ = io.WriteString(hash, "#")
	_, _ = io.WriteString(hash, strconv.Itoa(seq))
	prefix := session
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	return fmt.Sprintf("w%s-%08x-%06d", prefix, hash.Sum32(), seq)
}

func (a *Aggregator) isControl(p Packet) bool {
	if a.apiPort == 0 || p.Protocol != "TCP" {
		return false
	}
	if p.DstPort == a.apiPort && sameHost(p.DstIP, a.apiHost) {
		return true
	}
	if p.SrcPort == a.apiPort && sameHost(p.SrcIP, a.apiHost) {
		return true
	}
	return false
}

func sameHost(ip, host string) bool {
	if ip == host {
		return true
	}
	left := net.ParseIP(ip)
	right := net.ParseIP(host)
	return left != nil && right != nil && left.Equal(right)
}

func splitAPI(raw string) (string, int) {
	return hostPort(raw)
}
