# CICIoT23 Sentinel — Real-Time AI Network Intrusion Detection, Active Protection & Device Command Center

An end-to-end Machine Learning Network Intrusion Detection & Active Protection System built on the **CICIoT2023** dataset. It pairs a two-way **Go (`gopacket` + `iptables`)** endpoint service with a **FastAPI** multi-model inference & AI Auto-Block engine, a multi-device **Docker IoT fleet** (`smart-camera-01`, `smart-thermostat-02`, `smart-plug-03`), and an 8-page Plain-English **React** Command Center.

---

## Specification Suite (Read First)
All developers and AI coding agents **must** adhere strictly to the specification documents in `agents/`:
1. [`00_MASTER_ARCHITECTURE_AND_INTEGRATION.md`](./master_architecture_integration_blueprint.md) — End-to-end topology, Docker multi-device fleet (`sentinel-net` + `NET_ADMIN`/`NET_RAW`), directory structure, and JSON wire contracts.
2. [`01_AGENT_GOVERNANCE_AND_PROTOCOL.md`](./agent_governance_anti_drift_protocol.md) — Mandatory override protocol, Plain-English UI policy, anti-lockout firewall rules, and defensive engineering gates.
3. [`02_ML_PIPELINE_AND_22_FEATURE_CONTRACT.md`](./machine_learning_pipeline_22_feature_contract.md) — The locked 22-feature schema (18 base + 4 derived ratios), leakage prevention, and `.joblib` bundle spec.
4. [`03_GO_PACKET_COLLECTOR_SPEC.md`](./go_packet_collector_specification.md) — `gopacket` layer parsing, 100-packet window aggregation, 5s heartbeat, and `WS /ws/agent/{device_id}` firewall/DNS/kill-switch execution.
5. [`04_FASTAPI_BACKEND_AND_DB_SPEC.md`](./fastapi_backend_ml_engine_database_specification.md) — SQLite WAL database models (`devices`, `device_actions`, `flow_logs`, `security_alerts`, `incidents`), AI Auto-Block engine, `/api/devices/*` routes, and `/install.sh`.
6. [`05_REACT_SOC_DASHBOARD_UX_SPEC.md`](./react_soc_dashboard_ui_ux_specification.md) — Visual design tokens, Strict Plain-English UI vocabulary/feature labels, and functional specs for all 8 dashboard pages.

---

## Quickstart Guide

### 1. Place Trained Model Bundles
Drop your trained `.joblib` artifacts generated from the notebooks in `ml/notebooks/` into `ml/artifacts/`:
- `ml/artifacts/ciciot_22f_xgb.joblib`
- `ml/artifacts/ciciot_22f_brf.joblib`
- `ml/artifacts/ciciot_22f_svm.joblib`
- `ml/artifacts/ciciot_22f_lr.joblib`

*(Note: If you start the backend before copying your Kaggle `.joblib` files, FastAPI automatically builds physics-aligned bootstrap models so you can test the entire UI, PCAP uploader, and live `hping3` pipeline immediately.)*

### 2. Run with Docker Compose (Full Stack + Simulated Multi-Device IoT Fleet)
```bash
docker compose up --build
```
- **React Command Center:** `http://localhost:5173`
- **FastAPI Swagger Docs:** `http://localhost:8000/docs`
- **Simulated IoT Device Fleet (`sentinel-net`):**
  - `smart-camera-01` (`172.18.0.10`)
  - `smart-thermostat-02` (`172.18.0.11`)
  - `smart-plug-03` (`172.18.0.12`)
- **Attacker Container:** `attacker-node` (`172.18.0.50`)

### 3. Trigger a Live DoS Attack & Watch AI Auto-Block (`hping3` Showcase)
With the dashboard open at `http://localhost:5173`, trigger a live TCP SYN flood from `attacker-node` against `smart-camera-01`:
```bash
docker exec -it attacker-node sh /testbed/trigger_dos_flood.sh
```
Watch `collector-go` stream 100-packet windows in real time, FastAPI classify them as **`DoS`**, and—when **Auto-Block Attacks** is `ON`—automatically send `BLOCK_IP` over `WS /ws/agent/smart-camera-01` to drop the attacker's IP via `iptables` inside the container!