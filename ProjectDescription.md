# Project Description & Specifications

## The Goal
Build an industry-grade ML engineering demonstration that takes trained CICIoT2023 models and deploys them into a real-time SOC (Security Operations Center) dashboard.

## The 22-Feature Contract (CRITICAL)
The system strictly relies on 22 features to differentiate Benign, DoS, and DDoS traffic. 
**Base 18 Features (Extracted by Go in 100-packet windows):**
1. `flow_duration` (seconds)
2. `Rate` (packets per second)
3. `Header_Length` (mean bytes)
4. `Duration` (mean TTL/HopLimit)
5. `fin_flag_number` (ratio 0-1)
6. `syn_flag_number` (ratio 0-1)
7. `rst_flag_number` (ratio 0-1)
8. `psh_flag_number` (ratio 0-1)
9. `ack_flag_number` (ratio 0-1)
10. `ack_count` (raw count)
11. `syn_count` (raw count)
12. `fin_count` (raw count)
13. `rst_count` (raw count)
14. `TCP` (ratio 0-1)
15. `UDP` (ratio 0-1)
16. `ICMP` (ratio 0-1)
17. `AVG` (mean packet size)
18. `Std` (std dev of packet size)

**4 Derived Features (Computed by FastAPI in-memory before prediction):**
19. `bytes_per_sec` = Rate * AVG
20. `syn_ack_ratio` = (syn_count + 1) / (ack_count + 1)
21. `hdr_pkt_ratio` = Header_Length / (AVG + 1e-5)
22. `pkt_cv` = Std / (AVG + 1e-5)

## Expected Pages (V2 Plain-English Command Center)
1. **Security Overview:** High-level KPIs, 60s live traffic chart, connected device health, and recent alerts.
2. **Live Network Traffic:** Streaming table of traffic windows with Model Confidence scores and PCAP drag-and-drop analyzer.
3. **Attack Alerts:** Debounced alerts highlighting **"Why This Was Flagged"** (top 3 anomalous features in Plain English).
4. **Flow Explorer:** Searchable grid mapping IPs/MACs to predictions with a 22-feature Plain-English slide-over drawer.
5. **Model Performance:** Renders static test-set benchmark stats from the `.joblib` bundle (Confusion Matrix, Macro-F1, Feature Importance).
6. **Attack History:** DoS/DDoS flows aggregated over time into distinct attack episodes with AI Auto-Block logs and CSV/JSON export.
7. **Connected Devices:** Multi-device status grid (`Normal`, `DoS Attack`, `DDoS Attack`, `Internet Blocked`) and control drawer (**Auto-Block Attacks**, **Block All Internet** kill switch, Firewall Rules, DNS Switcher, and Device Action History).
8. **Add Device / Download Service:** 3-step onboarding (`Generate Setup Key`, platform picker, binary download, and 1-line `curl | sh` installer with live connection indicator).
