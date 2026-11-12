# 04 — FASTAPI BACKEND, ML ENGINE & DATABASE SPECIFICATION (`backend-fastapi/`)
**Framework:** FastAPI + Uvicorn + SQLAlchemy 2.0 (SQLite WAL mode) + Pydantic v2  
**Python Version:** 3.11+

---

## 1. DATABASE SCHEMA (`app/models.py` & `app/database.py`)
Use SQLite at `sqlite:///./sentinel_soc.db` with `PRAGMA journal_mode=WAL;` enabled on connection startup so concurrent reads and high-speed writes never lock.

### 1.1 Table `devices`
Tracks every unique IoT endpoint observed in `src_ip` or `dst_ip` across PCAPs, live captures, or CSV replays.
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `Integer` | `PK, AutoIncrement` | Internal ID |
| `ip_address` | `String(64)` | `Unique, Index, Not Null` | IPv4 or IPv6 address |
| `mac_address` | `String(32)` | `Not Null` | Ethernet MAC address |
| `hostname` | `String(128)` | `Not Null` | Auto-assigned friendly name (e.g., `IoT-Cam-172.18.0.10`) |
| `vendor` | `String(128)` | `Not Null` | OUI Vendor string |
| `status` | `String(32)` | `Not Null, Default="HEALTHY"` | `"HEALTHY"`, `"UNDER_DOS"`, `"UNDER_DDOS"` |
| `total_flows_seen` | `Integer` | `Default=0` | Cumulative windows involving this device |
| `attack_flows_seen` | `Integer` | `Default=0` | Cumulative DoS/DDoS windows targeting/from this device |
| `last_seen` | `DateTime` | `Not Null` | UTC timestamp of latest window |

### 1.2 Table `flow_logs`
Stores classified 100-packet windows (powers Module 2 Live Stream & Module 4 Flow Explorer).
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `Integer` | `PK, AutoIncrement` | Flow record ID |
| `window_id` | `String(64)` | `Index, Not Null` | UUID from collector/replayer |
| `timestamp` | `DateTime` | `Index, Not Null` | Window end UTC timestamp |
| `capture_mode` | `String(32)` | `Not Null` | `"LIVE_INTERFACE"`, `"PCAP_UPLOAD"`, or `"CSV_REPLAY"` |
| `src_ip` | `String(64)` | `Index, Not Null` | Source IP |
| `dst_ip` | `String(64)` | `Index, Not Null` | Destination IP |
| `src_mac` | `String(32)` | `Not Null` | Source MAC |
| `dst_mac` | `String(32)` | `Not Null` | Destination MAC |
| `src_port` | `Integer` | `Not Null` | Source port |
| `dst_port` | `Integer` | `Not Null` | Destination port |
| `protocol` | `String(16)` | `Index, Not Null` | `"TCP"`, `"UDP"`, `"ICMP"` |
| `packet_count` | `Integer` | `Not Null` | Number of packets in window |
| `predicted_class` | `String(16)` | `Index, Not Null` | `"Benign"`, `"DoS"`, `"DDoS"` |
| `confidence` | `Float` | `Index, Not Null` | Top class probability $[0.0, 1.0]$ |
| `probabilities_json` | `Text` | `Not Null` | JSON dict `{"Benign": p0, "DoS": p1, "DDoS": p2}` |
| `model_used` | `String(64)` | `Not Null` | Model name that produced prediction |
| `top_anomalies_json` | `Text` | `Not Null` | JSON list of Top 3 IQR anomalous features |
| `features_22_json` | `Text` | `Not Null` | JSON dict of all 22 deterministic features |

### 1.3 Table `security_alerts`
Stores debounced security alerts (powers Module 3 Attack Detection & Alerts).
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `Integer` | `PK, AutoIncrement` | Alert ID |
| `incident_id` | `Integer` | `FK(incidents.id), Index` | Parent Incident ID |
| `timestamp` | `DateTime` | `Index, Not Null` | UTC detection timestamp |
| `attack_type` | `String(16)` | `Not Null` | `"DoS"` or `"DDoS"` |
| `severity` | `String(16)` | `Not Null` | `"HIGH"` (for DoS) or `"CRITICAL"` (for DDoS) |
| `src_ip` | `String(64)` | `Not Null` | Attacking IP (or `"Multiple Botnet Sources"` if DDoS) |
| `dst_ip` | `String(64)` | `Not Null` | Targeted IoT Device IP |
| `protocol` | `String(16)` | `Not Null` | Dominant attack protocol |
| `confidence` | `Float` | `Not Null` | Mean model confidence across triggering windows |
| `top_anomalies_json` | `Text` | `Not Null` | JSON array of Top 3 anomalous features |
| `acknowledged` | `Boolean` | `Default=False, Index` | Operator acknowledgement flag |

### 1.4 Table `incidents`
Stores aggregated attack episodes (powers Module 6 Incident History).
| Column | Type | Constraints | Description |
| :--- | :--- | :--- | :--- |
| `id` | `Integer` | `PK, AutoIncrement` | Incident Ticket ID |
| `title` | `String(256)` | `Not Null` | E.g., `"TCP DoS Flood targeting 172.18.0.10"` |
| `attack_category` | `String(16)` | `Not Null` | `"DoS"` or `"DDoS"` |
| `severity` | `String(16)` | `Not Null` | `"HIGH"` or `"CRITICAL"` |
| `target_ip` | `String(64)` | `Index, Not Null` | Victim device IP |
| `source_ips_json` | `Text` | `Not Null` | JSON list of unique attacking source IPs |
| `started_at` | `DateTime` | `Not Null` | Timestamp of first malicious window in episode |
| `last_seen_at` | `DateTime` | `Not Null` | Timestamp of latest malicious window in episode |
| `resolved_at` | `DateTime` | `Nullable` | Timestamp when marked resolved |
| `status` | `String(32)` | `Index, Default="ACTIVE"` | `"ACTIVE"` or `"RESOLVED"` |
| `affected_flows_count` | `Integer` | `Default=1` | Total malicious windows absorbed into this incident |
| `peak_rate_pps` | `Float` | `Default=0.0` | Maximum `Rate` observed during the incident |
| `model_used` | `String(64)` | `Not Null` | Active model during detection |

---

## 2. STATEFUL INCIDENT DEBOUNCER SPECIFICATION (`app/services/incident_debouncer.py`)

To prevent the "Alert Storm" bug (where a 5-second `hping3` flood generates 500 separate alerts and freezes the UI), `IncidentDebouncer` maintains an in-memory dictionary keyed by `(dst_ip, predicted_class)` for `"DoS"` and `"DDoS"` predictions:

### 2.1 Debouncing Rules
1. **Trigger Threshold:**
   - In `"LIVE_INTERFACE"` or `"CSV_REPLAY"` mode: When $\ge 3$ malicious windows of the same `predicted_class` target `dst_ip` within a `5.0`-second window (or immediately on $\ge 1$ malicious window in `"PCAP_UPLOAD"` mode so small PCAPs always trigger visible alerts), check if an `"ACTIVE"` incident already exists for `(dst_ip, predicted_class)` where `now - incident.last_seen_at <= 15.0` seconds.
2. **Existing Active Incident Found (Absorption):**
   - Increment `incident.affected_flows_count += count`.
   - Update `incident.last_seen_at = now`.
   - Update `incident.peak_rate_pps = max(incident.peak_rate_pps, window_rate)`.
   - Append `src_ip` to `incident.source_ips_json` if not already present.
   - **Do NOT create a duplicate `security_alerts` row** unless `affected_flows_count` crosses a power-of-10 milestone (`100`, `1000`), keeping the Alert feed clean and actionable.
3. **No Active Incident Found (New Incident + New Alert):**
   - Create a new `incidents` row with `status="ACTIVE"`.
   - Create a new `security_alerts` row linked via `incident_id`.
   - Update the target device's status in `devices` table to `"UNDER_DOS"` or `"UNDER_DDOS"`.
4. **Auto-Cooldown Recovery:**
   - If a device receives `10` consecutive `"Benign"` windows and `now - incident.last_seen_at > 15.0` seconds, update the device's `status` back to `"HEALTHY"`.

---

## 3. COMPLETE FASTAPI REST & WEBSOCKET ROUTES

All REST routes must be prefixed with `/api/v1` and enable CORS (`allow_origins=["*"]`).

### 3.1 Ingestion & Traffic Generation Routes
| Method | Path | Purpose |
| :--- | :--- | :--- |
| `POST` | `/api/v1/ingest/windows` | Accepts `IngestBatchRequest` from `collector-go`, computes 4 derived ratios, runs batch inference, updates DB + IncidentDebouncer, broadcasts over `/ws/live`, and returns summary counts. |
| `POST` | `/api/v1/pcap/upload` | Accepts `multipart/form-data` `.pcap`, `.pcapng`, or `.csv` file upload from React UI. If `.pcap`/`.pcapng`, invokes `collector-go --mode pcap` subprocess (or pure-Python `dpkt` fallback if Go binary isn't compiled yet in local dev) to extract windows and run full pipeline. Returns `{processed_windows, benign_count, dos_count, ddos_count, alerts_triggered}`. |
| `POST` | `/api/v1/replay/control` | Body: `{"action": "start" \| "stop", "speed_fps": 10}`. Starts or stops an async background task (`csv_replayer.py`) that streams rows from `ml/sample_data/test_sample_500.csv`, synthesizes realistic IoT device metadata (`172.18.0.10`–`172.18.0.18`), and feeds them through the exact ingestion pipeline. |
| `GET` | `/api/v1/replay/status` | Returns `{"is_running": bool, "speed_fps": int, "rows_streamed": int}`. |

### 3.2 SOC Dashboard Query & Action Routes
| Method | Path | Purpose |
| :--- | :--- | :--- |
| `GET` | `/api/v1/overview/summary` | Returns KPIs (`total_flows`, `benign_count`, `dos_count`, `ddos_count`, `attack_percentage`, `active_incidents_count`), recent 10 alerts, and protocol distribution (`TCP`, `UDP`, `ICMP` counts). |
| `GET` | `/api/v1/flows` | Query params: `limit=100`, `offset=0`, `predicted_class`, `protocol`, `ip_search`, `min_confidence`. Returns paginated `flow_logs` including `features_22` and `top_anomalies`. |
| `GET` | `/api/v1/alerts` | Query params: `acknowledged` (`true`/`false`/optional), `severity`, `limit=50`. Returns `security_alerts`. |
| `PATCH` | `/api/v1/alerts/{alert_id}/acknowledge` | Sets `acknowledged = True` on the alert and broadcasts update over WebSocket. |
| `GET` | `/api/v1/incidents` | Query params: `status` (`"ACTIVE"`/`"RESOLVED"`/optional). Returns all `incidents` ordered by `last_seen_at DESC`. |
| `PATCH` | `/api/v1/incidents/{incident_id}/resolve` | Sets `status = "RESOLVED"`, `resolved_at = utcnow()`, resets target device status to `"HEALTHY"`, and broadcasts update. |
| `GET` | `/api/v1/incidents/{incident_id}/export` | Query param: `format=json|csv`. Returns a downloadable incident forensic report containing incident metadata and all associated `security_alerts`. |
| `GET` | `/api/v1/devices` | Returns all discovered IoT devices in `devices` table ordered by `attack_flows_seen DESC`. |
| `POST` | `/api/v1/system/reset` | Clears `flow_logs`, `security_alerts`, and `incidents` tables for a fresh live demo run. |

### 3.3 Model Registry & Analytics Routes (Module 5)
| Method | Path | Purpose |
| :--- | :--- | :--- |
| `GET` | `/api/v1/models` | Returns list of all 4 available models (`xgb`, `brf`, `svm`, `lr`), which one is currently active, whether it is loaded from a real Kaggle `.joblib` or bootstrap fallback, and its summary `test_accuracy` and `test_macro_f1`. |
| `POST` | `/api/v1/models/select` | Body: `{"model_id": "xgb" \| "brf" \| "svm" \| "lr"}`. Hot-swaps the active inference model in memory immediately without restarting FastAPI. |
| `GET` | `/api/v1/models/{model_id}/analytics` | Returns full benchmark telemetry from the `.joblib` bundle: `test_accuracy`, `test_macro_f1`, `classes`, 3x3 `confusion_matrix`, per-class `classification_report`, and sorted 22-feature `feature_importances`. |

### 3.4 WebSocket Route
- `WS /ws/live`: Accepts persistent WebSocket connections from React. On initial connection, immediately sends a `"SNAPSHOT"` frame containing current KPIs and the latest 25 flows so the UI renders populated charts immediately.