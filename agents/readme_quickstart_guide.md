# CICIoT23 Sentinel — Real-Time AI Network Intrusion Detection & SOC Command Center

An end-to-end Machine Learning Network Intrusion Detection System (NIDS) built on the **CICIoT2023** dataset. It pairs a high-speed **Go (`gopacket`)** 100-packet tumbling-window feature extractor with a **FastAPI** multi-model inference & incident engine and a **React** Security Operations Center (SOC) dashboard.

---

## Specification Suite (Read First)
All developers and AI coding agents **must** adhere strictly to the specification documents in the repository root:
1. [`00_MASTER_ARCHITECTURE_AND_INTEGRATION.md`](./00_MASTER_ARCHITECTURE_AND_INTEGRATION.md) — End-to-end topology, directory structure, and JSON wire contracts.
2. [`01_AGENT_GOVERNANCE_AND_PROTOCOL.md`](./01_AGENT_GOVERNANCE_AND_PROTOCOL.md) — Mandatory override protocol, code audit rules, and defensive engineering gates.
3. [`02_ML_PIPELINE_AND_22_FEATURE_CONTRACT.md`](./02_ML_PIPELINE_AND_22_FEATURE_CONTRACT.md) — The locked 22-feature schema (18 base + 4 derived ratios), leakage prevention, and `.joblib` bundle spec.
4. [`03_GO_PACKET_COLLECTOR_SPEC.md`](./03_GO_PACKET_COLLECTOR_SPEC.md) — `gopacket` layer parsing, 100-packet window aggregation, and exact Go mathematical formulas.
5. [`04_FASTAPI_BACKEND_AND_DB_SPEC.md`](./04_FASTAPI_BACKEND_AND_DB_SPEC.md) — SQLite WAL database models, Stateful Incident Debouncer, REST API endpoints, and WebSocket broadcasts.
6. [`05_REACT_SOC_DASHBOARD_UX_SPEC.md`](./05_REACT_SOC_DASHBOARD_UX_SPEC.md) — Visual design tokens, layout architecture, and functional specs for all 6 dashboard modules.

---

## Quickstart Guide

### 1. Place Trained Model Bundles
Drop your trained `.joblib` artifacts generated from the notebooks in `ml/notebooks/` into `ml/artifacts/`:
- `ml/artifacts/ciciot_22f_xgb.joblib`
- `ml/artifacts/ciciot_22f_brf.joblib`
- `ml/artifacts/ciciot_22f_svm.joblib`
- `ml/artifacts/ciciot_22f_lr.joblib`

*(Note: If you start the backend before copying your Kaggle `.joblib` files, FastAPI automatically builds physics-aligned bootstrap models so you can test the entire UI, PCAP uploader, and live `hping3` pipeline immediately.)*

### 2. Run with Docker Compose (Full Stack + Live IoT Target Testbed)
```bash
docker compose up --build
```
- **React SOC Dashboard:** `http://localhost:5173`
- **FastAPI Swagger Docs:** `http://localhost:8000/docs`
- **Simulated IoT Camera Target:** `172.18.0.10` (`smart-camera-01`)

### 3. Trigger a Live DoS Attack (`hping3` Showcase)
With the dashboard open at `http://localhost:5173`, trigger a live TCP SYN flood from the attacker container against the simulated IoT camera:
```bash
docker exec -it rogue-device-99 sh /testbed/trigger_dos_flood.sh
```
Watch `collector-go` capture the 100-packet windows in real time (`syn_flag_number = 1.0`, `syn_ack_ratio = 101.0`), FastAPI classify them as **`DoS`**, the Incident Debouncer open an active incident ticket, and the React dashboard highlight the anomalous features live.