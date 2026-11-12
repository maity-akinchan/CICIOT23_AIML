# 03 — GO PACKET COLLECTOR SPECIFICATION (`collector-go/`)
**Language & Runtime:** Go 1.22+  
**Primary Dependency:** `github.com/google/gopacket` (`pcap` and `layers` subpackages)  
**Responsibility:** High-speed packet capture from `.pcap` files or live network interfaces, 100-packet tumbling window aggregation, Track A metadata extraction, and Track B 18-feature computation.

---

## 1. CLI FLAGS & OPERATIONAL MODES
The binary compiled from `collector-go/cmd/collector/main.go` **MUST** support the following command-line flags:

```bash
./collector \
  --mode <pcap|live> \
  --pcap <path-to-file.pcap> \
  --iface <network-interface-name, e.g., eth0, docker0, any> \
  --api-url <http://localhost:8000/api/v1/ingest/windows> \
  --window-size 100 \
  --flush-timeout-ms 2000 \
  --batch-size 25 \
  --collector-id <string-identifier> \
  --bpf <optional-bpf-filter, default: "ip or ip6">
```

### 1.1 Execution Behavior by Mode
1. **`--mode pcap` (Offline File Analysis):**
   - Opens the file specified by `--pcap` via `pcap.OpenOffline(pcapPath)`.
   - Reads all packets sequentially at native speed.
   - Every `--window-size` (default `100`) valid IP packets, emits a `WindowPayload`.
   - At `EOF`, if the remaining buffer has $\ge 5$ packets, flushes that partial window so small PCAP files still produce predictions.
   - Ships batches of up to `--batch-size` windows via HTTP POST to `--api-url`, logs total windows shipped, and exits with code `0`.

2. **`--mode live` (Real-Time Interface Sniffing):**
   - Opens `--iface` via `pcap.OpenLive(iface, 65535, true, pcap.BlockForever)`.
   - Applies `--bpf` filter (default `"ip or ip6"` to ignore non-IP layer-2 noise that lacks TTL/IP headers).
   - Continuously reads packets. Whenever the active window reaches `100` packets **OR** `--flush-timeout-ms` (`2000ms`) elapses with $\ge 2$ packets in the buffer, flushes the window to the HTTP shipper channel.
   - Handles `SIGINT` / `SIGTERM` gracefully by flushing any in-flight batches before exiting.

---

## 2. PER-PACKET PARSING SPECIFICATION (`internal/parser/decoder.go`)

For every raw packet read from `gopacket.NewPacketSource`, extract a lightweight struct `ParsedPacket`:

```go
type ParsedPacket struct {
    Timestamp     time.Time
    WireLength    float64 // float64(pkt.Metadata().CaptureInfo.Length)
    HeaderLength  float64 // IP Header Length + Transport Header Length in bytes
    TTL           float64 // IPv4.TTL or IPv6.HopLimit (0-255)
    SrcMAC        string
    DstMAC        string
    SrcIP         string
    DstIP         string
    SrcPort       uint16
    DstPort       uint16
    IsTCP         bool
    IsUDP         bool
    IsICMP        bool
    FlagFIN       bool
    FlagSYN       bool
    FlagRST       bool
    FlagPSH       bool
    FlagACK       bool
}
```

### 2.1 Layer Extraction Rules
1. **Link Layer (`layers.LayerTypeEthernet`):**
   - Extract `SrcMAC = eth.SrcMAC.String()`, `DstMAC = eth.DstMAC.String()`.
   - If capturing on Linux `any` cooked socket (`LayerTypeLinuxSLL`) or Raw IP, fallback `SrcMAC = "00:00:00:00:00:00"`, `DstMAC = "00:00:00:00:00:00"`.
2. **Network Layer (`layers.LayerTypeIPv4` or `layers.LayerTypeIPv6`):**
   - If neither IPv4 nor IPv6 is present, **skip the packet**.
   - For **IPv4**:
     - `SrcIP = ip4.SrcIP.String()`, `DstIP = ip4.DstIP.String()`
     - `TTL = float64(ip4.TTL)`
     - `ipHeaderBytes = float64(ip4.IHL) * 4.0` (typically `20.0` bytes)
   - For **IPv6**:
     - `SrcIP = ip6.SrcIP.String()`, `DstIP = ip6.DstIP.String()`
     - `TTL = float64(ip6.HopLimit)`
     - `ipHeaderBytes = 40.0`
3. **Transport Layer:**
   - **`layers.LayerTypeTCP`**:
     - `IsTCP = true`
     - `SrcPort = uint16(tcp.SrcPort)`, `DstPort = uint16(tcp.DstPort)`
     - `transportHeaderBytes = float64(tcp.DataOffset) * 4.0` (typically `20.0`–`60.0` bytes)
     - Extract flags: `FlagFIN = tcp.FIN`, `FlagSYN = tcp.SYN`, `FlagRST = tcp.RST`, `FlagPSH = tcp.PSH`, `FlagACK = tcp.ACK`
   - **`layers.LayerTypeUDP`**:
     - `IsUDP = true`
     - `SrcPort = uint16(udp.SrcPort)`, `DstPort = uint16(udp.DstPort)`
     - `transportHeaderBytes = 8.0`
   - **`layers.LayerTypeICMPv4` or `layers.LayerTypeICMPv6`**:
     - `IsICMP = true`
     - `SrcPort = 0`, `DstPort = 0`
     - `transportHeaderBytes = 8.0`
   - **Other IP Protocols**:
     - `transportHeaderBytes = 0.0`
4. **Total Header Length for Packet $k$:**
   - `HeaderLength = ipHeaderBytes + transportHeaderBytes`
5. **Total Packet Wire Length for Packet $k$:**
   - `WireLength = float64(pkt.Metadata().Length)` (if `0`, fallback to `float64(len(pkt.Data()))`).

---

## 3. EXACT DETERMINISTIC EQUATIONS FOR THE 18 BASE FEATURES (`internal/window/math.go`)

Given a slice of $N$ packets $P = [p_1, p_2, \dots, p_N]$ where $N \ge 1$ (standard $N = 100$):

### 3.1 Timing & Rate Features
1. **`flow_duration`** (in seconds):
   $$
   \Delta t = p_N.\text{Timestamp.Sub}(p_1.\text{Timestamp}).\text{Seconds}()
   $$
   - **Clamping Rule:** If $\Delta t < 10^{-6}$ (e.g., all packets captured in the same microsecond burst or $N=1$), set:
     $$
     \text{flow\_duration} = 10^{-6}
     $$
2. **`Rate`** (packets per second):
   $$
   \text{Rate} = \frac{\text{float64}(N)}{\text{flow\_duration}}
   $$

### 3.2 Header & TTL Features
3. **`Header_Length`**:
   $$
   \text{Header\_Length} = \frac{1}{N} \sum_{k=1}^{N} p_k.\text{HeaderLength}
   $$
4. **`Duration`** (CICIoT2023's column name for mean TTL):
   $$
   \text{Duration} = \frac{1}{N} \sum_{k=1}^{N} p_k.\text{TTL}
   $$

### 3.3 TCP Flag Counts & Proportions
Let $\mathbb{I}(\cdot) \in \{0, 1\}$ be the indicator function:
5. **`ack_count`**:
   $$
   \text{ack\_count} = \sum_{k=1}^{N} \mathbb{I}(p_k.\text{FlagACK})
   $$
6. **`syn_count`**:
   $$
   \text{syn\_count} = \sum_{k=1}^{N} \mathbb{I}(p_k.\text{FlagSYN})
   $$
7. **`fin_count`**:
   $$
   \text{fin\_count} = \sum_{k=1}^{N} \mathbb{I}(p_k.\text{FlagFIN})
   $$
8. **`rst_count`**:
   $$
   \text{rst\_count} = \sum_{k=1}^{N} \mathbb{I}(p_k.\text{FlagRST})
   $$
9. **`fin_flag_number`**:
   $$
   \text{fin\_flag\_number} = \frac{\text{fin\_count}}{\text{float64}(N)}
   $$
10. **`syn_flag_number`**:
    $$
    \text{syn\_flag\_number} = \frac{\text{syn\_count}}{\text{float64}(N)}
    $$
11. **`rst_flag_number`**:
    $$
    \text{rst\_flag\_number} = \frac{\text{rst\_count}}{\text{float64}(N)}
    $$
12. **`psh_flag_number`**:
    $$
    \text{psh\_flag\_number} = \frac{1}{N} \sum_{k=1}^{N} \mathbb{I}(p_k.\text{FlagPSH})
    $$
13. **`ack_flag_number`**:
    $$
    \text{ack\_flag\_number} = \frac{\text{ack\_count}}{\text{float64}(N)}
    $$

### 3.4 Protocol Proportions
14. **`TCP`**:
    $$
    \text{TCP} = \frac{1}{N} \sum_{k=1}^{N} \mathbb{I}(p_k.\text{IsTCP})
    $$
15. **`UDP`**:
    $$
    \text{UDP} = \frac{1}{N} \sum_{k=1}^{N} \mathbb{I}(p_k.\text{IsUDP})
    $$
16. **`ICMP`**:
    $$
    \text{ICMP} = \frac{1}{N} \sum_{k=1}^{N} \mathbb{I}(p_k.\text{IsICMP})
    $$

### 3.5 Packet Length Statistics
17. **`AVG`**:
    $$
    \text{AVG} = \frac{1}{N} \sum_{k=1}^{N} p_k.\text{WireLength}
    $$
18. **`Std`** (Population Standard Deviation matching `numpy.std` / `dpkt` window extractor):
    $$
    \text{Std} = \sqrt{\frac{1}{N} \sum_{k=1}^{N} \left(p_k.\text{WireLength} - \text{AVG}\right)^2}
    $$

---

## 4. TRACK A METADATA AGGREGATION RULES (`internal/window/aggregator.go`)
Because a 100-packet window can contain packets from multiple hosts, `aggregator.go` determines the window's primary `metadata` object using **Majority Vote (Mode)**:
- **`src_ip` & `src_mac`:** The most frequent `SrcIP` in the 100-packet window, and its associated `SrcMAC`.
- **`dst_ip` & `dst_mac`:** The most frequent `DstIP` in the 100-packet window, and its associated `DstMAC`.
- **`src_port` & `dst_port`:** The most frequent `SrcPort` and `DstPort` in the window.
- **`dominant_protocol`:** `"TCP"` if $\text{TCP} \ge \text{UDP}$ and $\text{TCP} \ge \text{ICMP}$; else `"UDP"` if $\text{UDP} \ge \text{ICMP}$; else `"ICMP"`.
- **`device_vendor`:** Determined via a built-in OUI prefix map (`internal/parser/oui.go`) matching the first 3 octets of `src_mac` or `dst_mac` (e.g., `02:42:AC` $\rightarrow$ `"Docker Virtual IoT"`, `B8:27:EB` / `DC:A6:32` $\rightarrow$ `"Raspberry Pi Foundation"`, `24:FD:5B` $\rightarrow$ `"Smart Camera Corp"`, fallback $\rightarrow$ `"Generic IoT Endpoint"`).

---

## 5. HTTP SHIPPER & RETRY SPECIFICATION (`internal/shipper/http_shipper.go`)
- Uses an `http.Client` with `Timeout: 10 * time.Second`.
- Marshals `IngestBatchRequest` into JSON and sends `POST` to `--api-url` with header `Content-Type: application/json`.
- Implements 3-attempt exponential backoff (`200ms`, `500ms`, `1000ms`) on HTTP `5xx` or network connection errors.