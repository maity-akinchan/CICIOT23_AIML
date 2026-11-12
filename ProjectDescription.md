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

## Expected Modules
1. **Security Overview Dashboard:** High-level KPIs and recent alerts.
2. **Live Traffic Monitoring:** Streaming table of flows with confidence scores.
3. **Attack Detection & Alerts:** Stateful alerts highlighting the top 3 anomalous features.
4. **Network Flow Explorer:** Searchable grid mapping IPs/MACs to predicted classes.
5. **Model Performance Analytics:** Renders the static test-set benchmark stats from the .joblib file (Confusion Matrix, Macro-F1).
6. **Incident History:** DoS/DDoS flows aggregated over time into distinct incident tickets.
