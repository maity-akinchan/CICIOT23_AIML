package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Config is the collector CLI. Defaults match docker-compose.yml.
// --stride exists because operators expect a window step, but the architecture
// blueprint does not define an overlapping stride. sentinel-packet-approx22-v1 is a
// tumbling window, so stride must equal window size (default 100).
type Config struct {
	Mode           string
	Iface          string
	PcapFile       string
	ReplaySpeed    float64
	APIURL         string
	CollectorID    string
	WindowSize     int
	Stride         int
	AuthToken      string
	ListInterfaces bool
}

func parseArgs(args []string) (Config, error) {
	return parseArgsOutput(args, io.Discard)
}

func parseArgsOutput(args []string, output io.Writer) (Config, error) {
	fs := flag.NewFlagSet("collector", flag.ContinueOnError)
	fs.SetOutput(output)
	cfg := Config{}
	fs.StringVar(&cfg.Mode, "mode", "live", `capture mode: "live" or "pcap"`)
	fs.StringVar(&cfg.Iface, "iface", "", "network interface for live capture (for example eth0)")
	fs.BoolVar(&cfg.ListInterfaces, "list-interfaces", false, "list live capture interfaces and exit")
	fs.StringVar(&cfg.PcapFile, "pcap-file", "", "path to a .pcap or .pcapng file when --mode pcap")
	fs.Float64Var(&cfg.ReplaySpeed, "replay-speed", 1, "PCAP replay multiplier; 1.0 is real time, 0 is as fast as possible")
	fs.StringVar(&cfg.APIURL, "api-url", defaultAPIURL, "backend window ingestion URL")
	fs.StringVar(&cfg.CollectorID, "collector-id", defaultCollectorID, "sensor identifier")
	fs.IntVar(&cfg.WindowSize, "window-size", defaultWindowSize, "packets per tumbling window")
	fs.IntVar(&cfg.Stride, "stride", defaultWindowSize, "step between windows; must equal --window-size (tumbling, no overlap)")
	fs.StringVar(&cfg.AuthToken, "auth-token", os.Getenv("SENTINEL_COLLECTOR_TOKEN"), "optional bearer token for the ingest request")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if cfg.ListInterfaces {
		return cfg, nil
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	switch c.Mode {
	case "live":
		if strings.TrimSpace(c.Iface) == "" {
			return errors.New("live mode requires --iface")
		}
	case "pcap":
		if strings.TrimSpace(c.PcapFile) == "" {
			return errors.New("pcap mode requires --pcap-file")
		}
	default:
		return fmt.Errorf(`--mode must be "live" or "pcap"`)
	}
	if c.ReplaySpeed < 0 {
		return errors.New("--replay-speed must be >= 0")
	}
	if strings.TrimSpace(c.CollectorID) == "" {
		return errors.New("--collector-id is required")
	}
	if c.WindowSize < minWindowPackets {
		return fmt.Errorf("--window-size must be >= %d", minWindowPackets)
	}
	if c.Stride == 0 {
		c.Stride = c.WindowSize
	}
	if c.Stride != c.WindowSize {
		return errors.New("--stride must equal --window-size: sentinel-packet-approx22-v1 uses non-overlapping tumbling windows (the architecture blueprint defines no overlapping stride; default 100)")
	}
	if c.WindowSize != defaultWindowSize {
		return fmt.Errorf("--window-size %d would define a new feature contract; sentinel-packet-approx22-v1 requires %d", c.WindowSize, defaultWindowSize)
	}
	u, err := url.Parse(c.APIURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("invalid --api-url %q", c.APIURL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid --api-url scheme %q", u.Scheme)
	}
	return nil
}

func (c Config) captureMode() string {
	if c.Mode == "pcap" {
		return "PCAP_REPLAY"
	}
	return "LIVE_INTERFACE"
}

func (c Config) sourceType() string {
	if c.Mode == "pcap" {
		return "pcap"
	}
	return "live"
}

func (c Config) healthURL() (string, error) {
	u, err := url.Parse(c.APIURL)
	if err != nil {
		return "", err
	}
	return u.Scheme + "://" + u.Host + "/health", nil
}

func (c Config) sourceRef(session, linkName string, stats *Stats) string {
	origin := c.Iface
	if c.Mode == "pcap" {
		origin = c.PcapFile
	}
	return fmt.Sprintf(
		"schema_version=%s;feature_contract_id=%s;extractor_version=%s;capture_session_id=%s;source_type=%s;origin=%s;link_type=%s;window_policy=tumbling_%dpkts_or_%.0fs_min%d;packets_captured=%d;packets_dropped=%d;packets_truncated=%d;windows_dropped=%d",
		schemaVersion,
		contractID,
		extractorVersion,
		session,
		c.sourceType(),
		origin,
		linkName,
		c.WindowSize,
		windowTimeoutSecond,
		minWindowPackets,
		stats.Captured.Load(),
		stats.DroppedQueue.Load(),
		stats.Truncated.Load(),
		stats.WindowsDropped.Load(),
	)
}

func hostPort(raw string) (string, int) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", 0
	}
	portText := u.Port()
	if portText == "" {
		return u.Hostname(), 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return u.Hostname(), 0
	}
	return u.Hostname(), port
}

func newSessionID() string {
	var buf [8]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return "session00"
	}
	return hex.EncodeToString(buf[:])
}
