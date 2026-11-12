# CICIoT23 Sentinel: AI-Powered Network Security Command Center

An end-to-end Machine Learning pipeline and real-time network monitoring dashboard that detects DoS and DDoS attacks using the CICIoT2023 dataset.

## Architecture Overview
1. **collector-go**: High-speed packet sniffer using `gopacket`. Captures raw PCAPs or live interface traffic, groups them into 100-packet windows, and computes 18 deterministic features.
2. **backend-fastapi**: Python ML engine. Receives 18 features from Go, computes 4 ratio features in-memory, runs inference via `.joblib` models (BalancedRF, XGBoost, SVM, LogReg), and debounces alerts into stateful "Incidents".
3. **frontend-react**: React + Vite + Tailwind dashboard providing real-time WebSocket telemetry, PCAP upload capabilities, and ML performance analytics.
4. **ml**: Training notebooks that output the `.joblib` production bundles.

## Getting Started
(Refer to the individual `README.md` files in each sub-directory once implemented by the agent).
