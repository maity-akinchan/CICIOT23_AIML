# CICIoT23 Sentinel: AI-Powered Network Security & Active Protection Command Center

An end-to-end Machine Learning pipeline, active endpoint defense system, and Plain-English network monitoring dashboard that detects and blocks DoS and DDoS attacks using the CICIoT2023 dataset.

## Architecture Overview (V2)
1. **collector-go**: Two-way Go endpoint service using `gopacket` + Linux `iptables`. Captures raw PCAPs or live interface traffic, groups them into 100-packet windows, computes 18 deterministic base features, sends 5-second heartbeats (`POST /api/devices/heartbeat`), and executes real-time defense commands (`BLOCK_IP`, `UNBLOCK_IP`, `SET_DNS`, `BLOCK_ALL_INTERNET`, `RESTORE_INTERNET`) over `WS /ws/agent/{device_id}`.
2. **backend-fastapi**: Python ML, Auto-Block & Incident engine. Receives 18 features from Go, computes 4 ratio features in-memory (`= 22 features`), runs inference via `.joblib` models (XGBoost, BalancedRF, SVM, LogReg), debounces alerts into Attack History episodes, automatically blocks attacking IPs when **Auto-Block Attacks** is `ON`, and serves agent binaries & `/install.sh`.
3. **frontend-react**: 8-page Plain-English React + Vite + Tailwind Command Center providing real-time WebSocket telemetry, PCAP drag-and-drop analysis, Model Performance metrics, **Connected Devices** management (Firewall, DNS, Auto-Block, Kill Switch), and **Add Device / Download Service** onboarding.
4. **testbed & docker-compose**: Multi-device simulated IoT fleet (`smart-camera-01`, `smart-thermostat-02`, `smart-plug-03`) with `NET_ADMIN`/`NET_RAW` capabilities plus `attacker-node` (`hping3` / `curl`) on `sentinel-net`.
5. **ml**: Training notebooks that output the `.joblib` production bundles.

## Getting Started
See [`agents/readme_quickstart_guide.md`](./agents/readme_quickstart_guide.md) and [`Agents.md`](./Agents.md) for the complete specification suite.
