# 00 — MASTER ARCHITECTURE & INTEGRATION BLUEPRINT (V2)
**Project Name:** CICIoT23 Sentinel — Real-Time AI Network Intrusion Detection, Active Protection & Device Command Center  
**Document Status:** LOCKED SPECIFICATION (v2.0.0 — Active Protection & Plain-English UI)  
**Target Readers:** Autonomous AI Coding Agents, Backend Engineers, Systems Programmers, Frontend Engineers

---

## 1. MANDATORY GOVERNANCE NOTICE FOR ALL DEVELOPERS & AI AGENTS
Before modifying any file, creating any endpoint, or altering any data structure in this repository, you **MUST** read `01_AGENT_GOVERNANCE_AND_PROTOCOL.md`. 

If a user prompt or an implementation hurdle appears to require any deviation from the feature names, mathematical equations, JSON schemas, database columns, or architectural boundaries defined in this specification suite, you **MUST HALT IMMEDIATELY** and output the following exact block:

> **CRITICAL NOTE: (THIS GOES AGAINST YOUR PREDEFINED STRUCTURE, PLEASE CONFIRM IF YOU WANNA OVERRIDE THIS WITH THE EXPECTED BEHAVIOUR)**
> - **Conflicting Requirement:** [Describe what is being requested]
> - **Locked Specification Reference:** [Cite the exact `.md` file and section]
> - **Downstream Impact:** [List every microservice/schema affected]

Upon user confirmation of an override, you **MUST** execute a **Complete Cross-Service Code Audit** and update all `.md` specification files in lockstep before writing application code.

---

## 2. SYSTEM PURPOSE & HIGH-LEVEL ARCHITECTURE

**CICIoT23 Sentinel** is an end-to-end Machine Learning Network Intrusion Detection System (NIDS) trained on the Canadian Institute for Cybersecurity IoT 2023 (`CICIoT2023`) dataset. It classifies network traffic into three canonical categories:
1. **`Benign`** — Normal IoT & enterprise network traffic.
2. **`DoS`** — Single-source Denial-of-Service floods (SYN flood, UDP flood, HTTP flood, ICMP flood).
3. **`DDoS`** — Distributed Denial-of-Service floods originating from botnets/multiple sources.

Because machine learning models trained on CICIoT2023 operate on **100-packet sliding/tumbling window summary statistics** rather than raw packets or standard NetFlow records, this system implements a decoupled, high-throughput **Dual-Track Pipeline**:
- **Track A (Telemetry Metadata):** Preserves human-readable network context (`src_ip`, `dst_ip`, `src_mac`, `dst_mac`, `src_port`, `dst_port`, `dominant_protocol`, `device_vendor`) which is absent from the raw CICIoT2023 CSV files.
- **Track B (Deterministic 22-Feature ML Vector):** Extracts 18 base physical packet statistics in Go (`collector-go`) and derives 4 non-linear interaction ratios in Python (`backend-fastapi`) for zero-leakage, cross-model inference.

### 2.1 Topology Diagram

```text
┌───────────────────────────────────────────────────────────────────────────────────┐
│                            1. TRAFFIC INGESTION SOURCES                           │
│   [A] React UI Drag-and-Drop (.pcap / .pcapng / .csv)                             │
│   [B] Live Network Interface Sniffing (eth0 / wlan0 / docker0)                    │
│   [C] Testbed Attack Simulator (hping3 SYN/UDP Floods against Docker Target)      │
└─────────────────────────────────────────┬─────────────────────────────────────────┘
                                          │ Raw Ethernet Frames / libpcap
                                          ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│               2. BIDIRECTIONAL GO ENDPOINT AGENT (collector-go/)                  │
│   • Built with google/gopacket (libpcap bindings) + Linux defense executor        │
│   • Tumbling window buffer: N = 100 packets (or 2000ms partial flush timeout)     │
│   • Extracts Track A Metadata + Computes Track B Base 18 Deterministic Features   │
│   • Ships batched JSON payloads via HTTP POST (/api/v1/ingest/windows)            │
│   • Registers device (POST /api/agents/register) & sends 5s Heartbeat             │
│     (POST /api/agents/heartbeat: uptime, CPU/RAM, blocked IPs, DNS, kill-switch)  │
│   • Listens on WS /ws/agent/{device_id} for BLOCK_IP, UNBLOCK_IP, SET_DNS,        │
│     and RESTRICT_INTERNET (Block All Internet except FastAPI control plane)       │
└─────────────────────────┬───────────────────────────────────▲─────────────────────┘
                          │ JSON over HTTP (Contract #1 & #4) │ WS Commands (Contract #5)
                          ▼                                   │
┌───────────────────────────────────────────────────────────────────────────────────┐
│              3. FASTAPI ML, AUTO-BLOCK & INCIDENT ENGINE (backend-fastapi/)       │
│   • Validates 18 Base Features -> Computes 4 Derived Ratio Features (= 22 Total)  │
│   • Hot-Swappable Model Registry (XGBoost, Balanced RF, Calibrated SVM, LogReg)   │
│   • Computes Local Explainability ("Why This Was Flagged" via Benign IQR Z-Score) │
│   • Stateful Incident Debouncer (5s Tumbling Window + 15s Cooldown per Target/Src)│
│   • Auto-Block Engine: When ON & confidence >= 90% across >= 10 windows in 5s,    │
│     dispatches BLOCK_IP (DoS) or rate-limit/restrict (DDoS) to the Go agent       │
│   • Serves Agent Binary Downloads & 1-line install script (curl | sudo bash)      │
│   • Persists Devices, Flows, Alerts, Incidents & Defense Actions to SQLite (WAL)  │
└───────────────────┬───────────────────────────────────────────┬───────────────────┘
                    │ REST API (/api/v1/* & /api/agents/*)      │ WebSocket (/ws/live)
                    │ (Contract #2)                             │ (Contract #3)
                    ▼                                           ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│               4. REACT PLAIN-ENGLISH COMMAND CENTER (frontend-react/)             │
│   • Page 1: Security Overview (KPI Bento, 60s Live Chart, Device Health Roster)   │
│   • Page 2: Live Network Traffic & PCAP Analyzer (Stream Table, Drag-and-Drop)    │
│   • Page 3: Attack Alerts (Severity Cards, "Why This Was Flagged" Pills)          │
│   • Page 4: Flow Explorer (Search/Filter Grid + 22-Feature Plain-English Drawer)  │
│   • Page 5: Model Performance (Confusion Matrix, Macro-F1, Feature Importance)    │
│   • Page 6: Attack History (Grouped Episodes, Resolve, CSV/JSON Report Export)    │
│   • Page 7: Connected Devices (Multi-Device Status, Firewall, DNS, Auto-Block,    │
│             and "Block All Internet" Red Kill-Switch Button)                      │
│   • Page 8: Add Device / Download Service (Platform Picker, Binary, 1-line curl)  │
└───────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. CANONICAL MONOREPO DIRECTORY STRUCTURE
No files or folders may be created outside this hierarchy without triggering the Override Protocol.

```text
ciciot23-sentinel/
├── 00_MASTER_ARCHITECTURE_AND_INTEGRATION.md
├── 01_AGENT_GOVERNANCE_AND_PROTOCOL.md
├── 02_ML_PIPELINE_AND_22_FEATURE_CONTRACT.md
├── 03_GO_PACKET_COLLECTOR_SPEC.md
├── 04_FASTAPI_BACKEND_AND_DB_SPEC.md
├── 05_REACT_SOC_DASHBOARD_UX_SPEC.md
├── README.md
├── docker-compose.yml
├── .env.example
│
├── ml/
│   ├── notebooks/
│   │   ├── ciciot23_22f_xgboost.ipynb
│   │   ├── ciciot23_22f_brf.ipynb
│   │   ├── ciciot23_22f_svm.ipynb
│   │   └── ciciot23_22f_logreg.ipynb
│   ├── sample_data/
│   │   └── test_sample_500.csv
│   └── artifacts/
│       ├── ciciot_22f_xgb.joblib
│       ├── ciciot_22f_brf.joblib
│       ├── ciciot_22f_svm.joblib
│       └── ciciot_22f_lr.joblib
│
├── collector-go/
│   ├── Dockerfile
│   ├── go.mod
│   ├── go.sum
│   ├── cmd/
│   │   └── collector/
│   │       └── main.go
│   └── internal/
│       ├── config/
│       │   └── config.go
│       ├── parser/
│       │   ├── decoder.go
│       │   └── oui.go
│       ├── window/
│       │   ├── aggregator.go
│       │   └── math.go
│       ├── shipper/
│       │   └── http_shipper.go
│       ├── agent/
│       │   ├── register.go
│       │   ├── heartbeat.go
│       │   ├── metrics.go
│       │   └── ws_client.go
│       └── defense/
│           ├── firewall.go
│           └── dns.go
│
├── backend-fastapi/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── models.py
│   │   ├── schemas.py
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── feature_adapter.py
│   │   │   ├── ml_registry.py
│   │   │   ├── explainability.py
│   │   │   ├── incident_debouncer.py
│   │   │   ├── auto_blocker.py
│   │   │   ├── agent_manager.py
│   │   │   ├── pcap_processor.py
│   │   │   ├── csv_replayer.py
│   │   │   └── ws_manager.py
│   │   └── routers/
│   │       ├── __init__.py
│   │       ├── ingest.py
│   │       ├── pcap.py
│   │       ├── replay.py
│   │       ├── flows.py
│   │       ├── alerts.py
│   │       ├── incidents.py
│   │       ├── devices.py
│   │       ├── agents.py
│   │       └── models_analytics.py
│   └── tests/
│       ├── test_feature_adapter.py
│       ├── test_incident_debouncer.py
│       ├── test_auto_blocker.py
│       └── test_ingest_api.py
│
├── frontend-react/
│   ├── Dockerfile
│   ├── package.json
│   ├── tsconfig.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   ├── index.html
│   └── src/
│       ├── main.tsx
│       ├── App.tsx
│       ├── api/
│       │   └── client.ts
│       ├── types/
│       │   └── sentinel.ts
│       ├── utils/
│       │   └── plainEnglish.ts
│       ├── context/
│       │   └── TelemetryContext.tsx
│       ├── hooks/
│       │   └── useSentinelSocket.ts
│       └── components/
│           ├── layout/
│           │   ├── TopCommandHeader.tsx
│           │   └── NavigationDock.tsx
│           ├── shared/
│           │   ├── ClassBadge.tsx
│           │   ├── SeverityBadge.tsx
│           │   ├── ConfidenceBar.tsx
│           │   └── FeatureDrawer.tsx
│           └── modules/
│               ├── OverviewDashboard.tsx
│               ├── LiveTrafficMonitor.tsx
│               ├── AttackAlertsView.tsx
│               ├── FlowExplorerView.tsx
│               ├── ModelAnalyticsView.tsx
│               ├── IncidentHistoryView.tsx
│               ├── ConnectedDevicesView.tsx
│               └── DownloadServiceView.tsx
│
└── testbed/
    ├── Dockerfile.iot-target
    ├── Dockerfile.attacker
    ├── benign_traffic_loop.sh
    └── trigger_dos_flood.sh
```

---

## 4. CROSS-SERVICE DATA CONTRACTS

### 4.1 Contract #1: Go Collector $\rightarrow$ FastAPI (`POST /api/v1/ingest/windows`)
The Go binary sends batches of 1 to 100 completed window objects. Every single key in `features_18` **MUST** match the exact case-sensitive string below:

```json
{
  "collector_id": "go-sensor-docker0",
  "capture_mode": "LIVE_INTERFACE",
  "source_ref": "docker0",
  "windows": [
    {
      "window_id": "550e8400-e29b-41d4-a716-446655440000",
      "timestamp_start": "2026-11-12T05:45:00.112000Z",
      "timestamp_end": "2026-11-12T05:45:00.121500Z",
      "packet_count": 100,
      "metadata": {
        "src_ip": "172.18.0.5",
        "dst_ip": "172.18.0.10",
        "src_mac": "02:42:ac:12:00:05",
        "dst_mac": "02:42:ac:12:00:0a",
        "src_port": 49812,
        "dst_port": 80,
        "dominant_protocol": "TCP",
        "device_vendor": "Raspberry Pi Foundation"
      },
      "features_18": {
        "flow_duration": 0.0095,
        "Rate": 10526.315789,
        "Header_Length": 40.0,
        "Duration": 64.0,
        "fin_flag_number": 0.0,
        "syn_flag_number": 1.0,
        "rst_flag_number": 0.0,
        "psh_flag_number": 0.0,
        "ack_flag_number": 0.0,
        "ack_count": 0.0,
        "syn_count": 100.0,
        "fin_count": 0.0,
        "rst_count": 0.0,
        "TCP": 1.0,
        "UDP": 0.0,
        "ICMP": 0.0,
        "AVG": 54.0,
        "Std": 0.0
      }
    }
  ]
}
```

### 4.2 Contract #2: FastAPI In-Memory Feature Expansion (`18 -> 22`)
Immediately upon receiving `features_18`, `backend-fastapi/app/services/feature_adapter.py` appends the 4 derived ratios in this exact order before invoking `.predict_proba()`:
1. `bytes_per_sec` $= \text{Rate} \times \text{AVG}$
2. `syn_ack_ratio` $= \frac{\text{syn\_count} + 1.0}{\text{ack\_count} + 1.0}$
3. `hdr_pkt_ratio` $= \frac{\text{Header\_Length}}{\text{AVG} + 10^{-5}}$
4. `pkt_cv` $= \frac{\text{Std}}{\text{AVG} + 10^{-5}}$

### 4.3 Contract #3: FastAPI $\rightarrow$ React WebSocket Frame (`WS /ws/live`)
Every processed batch is broadcast to all connected React clients using this exact envelope:

```json
{
  "event_type": "TELEMETRY_BATCH",
  "server_timestamp": "2026-11-12T05:45:00.135000Z",
  "active_model_id": "xgb",
  "kpis": {
    "total_flows": 14520,
    "benign_count": 11200,
    "dos_count": 2820,
    "ddos_count": 500,
    "attack_percentage": 22.86,
    "current_fps": 42.5,
    "active_incidents_count": 1
  },
  "flows": [
    {
      "id": 14520,
      "window_id": "550e8400-e29b-41d4-a716-446655440000",
      "timestamp": "2026-11-12T05:45:00.121500Z",
      "src_ip": "172.18.0.5",
      "dst_ip": "172.18.0.10",
      "src_mac": "02:42:ac:12:00:05",
      "dst_mac": "02:42:ac:12:00:0a",
      "src_port": 49812,
      "dst_port": 80,
      "protocol": "TCP",
      "packet_count": 100,
      "predicted_class": "DoS",
      "confidence": 0.9842,
      "probabilities": {
        "Benign": 0.0012,
        "DoS": 0.9842,
        "DDoS": 0.0146
      },
      "model_used": "XGBoost_GPU_CICIoT23_22F",
      "top_anomalies": [
        {
          "feature": "syn_flag_number",
          "value": 1.0,
          "benign_median": 0.0,
          "z_iqr": 142.8,
          "direction": "HIGH"
        },
        {
          "feature": "syn_ack_ratio",
          "value": 101.0,
          "benign_median": 0.02,
          "z_iqr": 98.4,
          "direction": "HIGH"
        },
        {
          "feature": "Rate",
          "value": 10526.32,
          "benign_median": 18.4,
          "z_iqr": 64.1,
          "direction": "HIGH"
        }
      ],
      "features_22": {
        "flow_duration": 0.0095,
        "Rate": 10526.315789,
        "Header_Length": 40.0,
        "Duration": 64.0,
        "fin_flag_number": 0.0,
        "syn_flag_number": 1.0,
        "rst_flag_number": 0.0,
        "psh_flag_number": 0.0,
        "ack_flag_number": 0.0,
        "ack_count": 0.0,
        "syn_count": 100.0,
        "fin_count": 0.0,
        "rst_count": 0.0,
        "TCP": 1.0,
        "UDP": 0.0,
        "ICMP": 0.0,
        "AVG": 54.0,
        "Std": 0.0,
        "bytes_per_sec": 568421.0526,
        "syn_ack_ratio": 101.0,
        "hdr_pkt_ratio": 0.74074,
        "pkt_cv": 0.0
      }
    }
  ],
  "new_alerts": [],
  "updated_incidents": []
}
```

### 4.4 Contract #4: Go Service $\rightarrow$ FastAPI Enrollment & Heartbeat
- **Enrollment (`POST /api/devices/register`):**
```json
{
  "device_id": "smart-camera-01",
  "device_name": "Smart Camera 01",
  "ip_address": "172.18.0.10",
  "mac_address": "02:42:ac:12:00:0a"
}
```
- **Heartbeat (`POST /api/devices/heartbeat` every 5 seconds):**
```json
{
  "device_id": "smart-camera-01",
  "device_name": "Smart Camera 01",
  "ip_address": "172.18.0.10",
  "mac_address": "02:42:ac:12:00:0a",
  "uptime_seconds": 3842,
  "internet_blocked": false,
  "auto_block_enabled": true,
  "current_dns": ["1.1.1.1"],
  "blocked_ips": ["172.18.0.50"]
}
```

### 4.5 Contract #5: FastAPI $\rightarrow$ Go Service Defense Commands (`WS /ws/agent/{device_id}`)
FastAPI dispatches real-time defense commands over a persistent WebSocket to the Go service:
```json
{
  "command_id": "cmd-8841a",
  "action": "BLOCK_IP",
  "payload": {
    "ip": "172.18.0.50",
    "reason": "AI Auto-Blocked 172.18.0.50 due to DoS attack"
  }
}
```
Supported `action` values: `"BLOCK_IP"`, `"UNBLOCK_IP"`, `"SET_DNS"`, `"BLOCK_ALL_INTERNET"`, `"RESTORE_INTERNET"`.

---

## 5. DOCKER-BASED MULTI-DEVICE FLEET ARCHITECTURE (`docker-compose.yml`)

- **Per-Device Container Topology:** Simulated IoT devices (`smart-camera-01`, `smart-thermostat-02`, `smart-plug-03`) run as lightweight Linux Docker containers (`alpine` + `iptables` + `iproute2` + `curl` + `nginx`) on a dedicated Docker bridge network (`sentinel-net`, `172.18.0.0/16`).
- **Required Container Capabilities:** Every simulated IoT device container in `docker-compose.yml` **MUST** include `cap_add: ["NET_ADMIN", "NET_RAW"]` so the Go service running inside the container has permission to sniff packets (`gopacket`), modify firewall rules (`iptables`), and update `/etc/resolv.conf` DNS settings without affecting the host laptop's Wi-Fi/network.
- **Attacker Container:** Includes an `attacker-node` container on `sentinel-net` pre-installed with `hping3` and `curl` to run live `DoS` and `DDoS` attack simulations against any connected device container.

| Service Name | Container Name | Host / Internal Port | Network (`sentinel-net`) | Capabilities & Role |
| :--- | :--- | :--- | :--- | :--- |
| `backend-fastapi` | `sentinel-api` | `8000:8000` | `172.18.0.2` | FastAPI REST + WebSocket + ML Inference + Auto-Block Engine |
| `frontend-react` | `sentinel-ui` | `5173:5173` | `172.18.0.3` | React Vite Plain-English Command Center (8 Pages) |
| `smart-camera-01` | `smart-camera-01` | `8081:80` | `172.18.0.10` | `cap_add: [NET_ADMIN, NET_RAW]` — Alpine + nginx + Go Agent |
| `smart-thermostat-02` | `smart-thermostat-02` | `8082:80` | `172.18.0.11` | `cap_add: [NET_ADMIN, NET_RAW]` — Alpine + nginx + Go Agent |
| `smart-plug-03` | `smart-plug-03` | `8083:80` | `172.18.0.12` | `cap_add: [NET_ADMIN, NET_RAW]` — Alpine + nginx + Go Agent |
| `attacker-node` | `attacker-node` | N/A | `172.18.0.50` | `cap_add: [NET_ADMIN, NET_RAW]` — `hping3` + `curl` DoS/DDoS simulator |

---

## 6. END-TO-END IMPLEMENTATION ORDER
Any developer or AI agent building this system **MUST** implement and verify components in this exact sequence:
1. **Step 1:** Verify/Generate `.joblib` artifacts in `ml/artifacts/` (or run `backend-fastapi`'s fallback synthetic bundle generator for CI testing).
2. **Step 2:** Build `backend-fastapi` (Database models $\rightarrow$ Feature Adapter $\rightarrow$ ML Registry $\rightarrow$ Incident Debouncer & Auto-Blocker $\rightarrow$ Agent Manager & REST/WS endpoints) and run `pytest`.
3. **Step 3:** Build `collector-go` (Packet decoder $\rightarrow$ 100-packet window aggregator $\rightarrow$ Exact 18-feature math $\rightarrow$ HTTP shipper $\rightarrow$ Agent registration, 5s heartbeat, & WS defense executor) and run `go test ./...`.
4. **Step 4:** Build `frontend-react` (TypeScript contracts $\rightarrow$ Plain-English label map $\rightarrow$ WebSocket context $\rightarrow$ 8 Plain-English Dashboard Pages) and verify `tsc --noEmit`.
5. **Step 5:** Assemble `docker-compose.yml` and `testbed/` scripts to verify live `hping3` DoS detection end-to-end.