package main

import (
	"errors"
	"math"
	"time"
)

const minFlowDuration = 1e-6

// Compute calculates the 18 sentinel-packet-approx22-v1 base features for one flow window.
//
//	flow_duration = max(latest_timestamp - earliest_timestamp, 1e-6) seconds
//	Rate          = N / flow_duration
//	Header_Length = mean network+transport header bytes
//	Duration      = mean IPv4 TTL or IPv6 hop limit
//	*_flag_number = TCP flag count / N
//	*_count       = raw TCP flag count in [0, N]
//	TCP, UDP, ICMP = protocol share
//	AVG, Std      = mean and population standard deviation of original wire lengths
func Compute(pkts []Packet) (Features18, error) {
	n := len(pkts)
	if n == 0 {
		return Features18{}, errors.New("empty window")
	}
	nf := float64(n)
	var (
		headerSum               float64
		ttlSum                  float64
		wireSum                 float64
		fin, syn, rst, psh, ack int
		tcp, udp, icmp          int
	)
	for _, p := range pkts {
		headerSum += float64(p.HeaderBytes)
		ttlSum += float64(p.TTL)
		wireSum += float64(p.WireBytes)
		switch p.Protocol {
		case "TCP":
			tcp++
			if p.TCPFlags&flagFIN != 0 {
				fin++
			}
			if p.TCPFlags&flagSYN != 0 {
				syn++
			}
			if p.TCPFlags&flagRST != 0 {
				rst++
			}
			if p.TCPFlags&flagPSH != 0 {
				psh++
			}
			if p.TCPFlags&flagACK != 0 {
				ack++
			}
		case "UDP":
			udp++
		case "ICMP":
			icmp++
		default:
			return Features18{}, errors.New("window contains an unsupported protocol")
		}
	}
	duration := eventSpanSeconds(pkts)
	avg := wireSum / nf
	var square float64
	for _, p := range pkts {
		delta := float64(p.WireBytes) - avg
		square += delta * delta
	}
	features := Features18{
		FlowDuration:  duration,
		Rate:          nf / duration,
		HeaderLength:  headerSum / nf,
		Duration:      ttlSum / nf,
		FinFlagNumber: float64(fin) / nf,
		SynFlagNumber: float64(syn) / nf,
		RstFlagNumber: float64(rst) / nf,
		PshFlagNumber: float64(psh) / nf,
		AckFlagNumber: float64(ack) / nf,
		AckCount:      float64(ack),
		SynCount:      float64(syn),
		FinCount:      float64(fin),
		RstCount:      float64(rst),
		TCP:           float64(tcp) / nf,
		UDP:           float64(udp) / nf,
		ICMP:          float64(icmp) / nf,
		AVG:           avg,
		Std:           math.Sqrt(square / nf),
	}
	if err := features.finite(); err != nil {
		return Features18{}, err
	}
	return features, nil
}

// eventSpanSeconds uses the earliest and latest event timestamps. Equal or
// missing timestamps use the 1e-6 second floor so Rate stays finite.
func eventSpanSeconds(pkts []Packet) float64 {
	var (
		minT, maxT time.Time
		seen       bool
	)
	for _, p := range pkts {
		if p.Timestamp.IsZero() {
			continue
		}
		if !seen || p.Timestamp.Before(minT) {
			minT = p.Timestamp
		}
		if !seen || p.Timestamp.After(maxT) {
			maxT = p.Timestamp
		}
		seen = true
	}
	if !seen {
		return minFlowDuration
	}
	span := maxT.Sub(minT).Seconds()
	if span < minFlowDuration {
		return minFlowDuration
	}
	return span
}

func (f Features18) finite() error {
	values := []float64{
		f.FlowDuration, f.Rate, f.HeaderLength, f.Duration,
		f.FinFlagNumber, f.SynFlagNumber, f.RstFlagNumber, f.PshFlagNumber, f.AckFlagNumber,
		f.AckCount, f.SynCount, f.FinCount, f.RstCount,
		f.TCP, f.UDP, f.ICMP, f.AVG, f.Std,
	}
	for _, value := range values {
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return errors.New("non-finite feature")
		}
	}
	return nil
}
