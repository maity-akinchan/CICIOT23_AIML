# 05 — REACT SOC DASHBOARD UI/UX SPECIFICATION (`frontend-react/`)
**Stack:** React 18 + TypeScript + Vite + Tailwind CSS + Recharts + Lucide React Icons  
**Design Paradigm:** Atmospheric Minimalism & High-Craft Dark UI blended with Kinetic Typography & Neo-Brutalist Swiss Grids.

---

## 1. VISUAL DIRECTION, COLOR TOKENS & TYPOGRAPHY

### 1.1 Intentional Dark Mode Surface Palette
The dashboard defaults to an authoritative Carbon-Slate SOC theme designed for zero eye strain and instant semantic triage:
- **Primary Canvas Background:** `#090D16` (`bg-[#090D16]`)
- **Elevated Card / Panel Surface:** `#111827` (`bg-slate-900/90`) with `backdrop-blur-md`
- **Glass Floating HUD / Dock:** `rgba(17, 24, 39, 0.78)` with `1px solid rgba(255, 255, 255, 0.08)` border
- **Structural Grid Hairlines:** `#1E293B` (`border-slate-800`) — exposed `1px` Swiss grid cells
- **Primary Text:** `#F8FAFC` (`text-slate-50`)
- **Secondary Text:** `#94A3B8` (`text-slate-400`)
- **Muted / Technical Labels:** `#64748B` (`text-slate-500`)

### 1.2 Semantic Traffic & Threat Accent Tokens
Never mix decorative colors with semantic threat colors. Reserve these four accents strictly for classification and status:
1. **`Benign` / Healthy / Connected:** Emerald `#10B981` (`text-emerald-400`, badge `bg-emerald-500/10 border-emerald-500/30`)
2. **`DoS` / High Severity Warning:** Amber `#F59E0B` (`text-amber-400`, badge `bg-amber-500/10 border-amber-500/30`)
3. **`DDoS` / Critical Breach Alert:** Crimson `#EF4444` (`text-red-400`, badge `bg-red-500/10 border-red-500/30`)
4. **System Control / Active Model Accent:** Cyan-Indigo `#38BDF8` (`text-sky-400`, `border-sky-500/40`)

### 1.3 Typography & Scannable Hierarchy
- **UI & Headings (`font-sans`):** `'Inter'` or system geometric sans, tight tracking (`tracking-tight`).
- **All Telemetry, IPs, MACs, Feature Values, & Confidence Scores (`font-mono`):** `'JetBrains Mono'` or monospace with **mandatory `tabular-nums`** (`font-variant-numeric: tabular-nums`) so live-updating numbers never jitter horizontally.

---

## 2. GLOBAL CHROME & LAYOUT ARCHITECTURE

1. **Top Command Header (`TopCommandHeader.tsx`):**
   - **Left:** Shield/Radar pulse icon + `"CICIoT23 SENTINEL"` title + Live WebSocket connection pill (`CONNECTED · 42.5 flows/s` in Emerald or `RECONNECTING` in Amber).
   - **Center (Hot-Swap Model Selector):** Segmented pill bar allowing 1-click live switching between the 4 models:
     - `XGBoost (22F)` | `Balanced RF` | `Calibrated SVM` | `Logistic Reg`
   - **Right (Quick Actions):**
     - **`Simulate Replay` Toggle Button:** Starts/Stops the built-in CSV replay stream (`POST /api/v1/replay/control`) with a speed selector (`5 fps`, `15 fps`, `30 fps`).
     - **`Upload PCAP` Button:** Opens or scrolls to the drag-and-drop PCAP analyzer.
     - **`Reset SOC` Button:** Clears current session counters (`POST /api/v1/system/reset`).

2. **6-Module Navigation Bar (`NavigationDock.tsx`):**
   - Persistent horizontal tab bar (or floating dock) with live badge counters on Alerts and Incidents:
     1. `1. Security Overview`
     2. `2. Live Traffic & PCAP`
     3. `3. Attack Alerts` *(shows unacknowledged count badge)*
     4. `4. Flow Explorer`
     5. `5. Model Analytics`
     6. `6. Incident History` *(shows active incident count badge)*

---

## 3. FUNCTIONAL SPECIFICATIONS FOR ALL 6 MODULES

### Module 1: Security Overview Dashboard (`OverviewDashboard.tsx`)
- **Row 1 — 5-Card Swiss Bento KPI Strip:**
  1. **Total Flows Monitored:** Large tabular number + current `flows/sec` rate.
  2. **Benign Traffic:** Count + percentage of total in Emerald.
  3. **DoS Detections:** Count + percentage of total in Amber.
  4. **DDoS Detections:** Count + percentage of total in Crimson.
  5. **Attack Ratio:** Overall `(DoS + DDoS) / Total` percentage + progress bar.
- **Row 2 — Real-Time Telemetry Charts (2-Column Split):**
  - **Left (65% width):** **Live Traffic Classification Stream (Recharts Stacked AreaChart)** over a rolling 60-second window showing `Benign` (Emerald), `DoS` (Amber), and `DDoS` (Crimson) flows per second.
  - **Right (35% width):** **Monitored IoT Device Roster** showing discovered devices (`ip_address`, `vendor`, `mac_address`, `total_flows_seen`) and a real-time health badge (`HEALTHY`, `UNDER_DOS`, `UNDER_DDOS`).
- **Row 3 — Recent Security Alerts Feed:**
  - Compact table of the 6 most recent `security_alerts` with timestamp, severity badge, `src_ip -> dst_ip`, top anomalous feature pill, and quick `Acknowledge` button.

### Module 2: Live Traffic Monitoring & PCAP Analyzer (`LiveTrafficMonitor.tsx`)
- **Top Panel — Dual Ingestion Controls:**
  - **Drag-and-Drop PCAP / CSV Analyzer Zone:** Accepts `.pcap`, `.pcapng`, and `.csv` files. Displays upload progress and an immediate classification breakdown card (`Processed X windows: Y Benign, Z DoS, W DDoS`) upon completion.
  - **Live CLI Command Helper Card:** Copyable one-liner showing how to attach `collector-go` to a local interface or run `hping3` against the testbed target.
- **Middle Panel — Protocol Distribution & Live Rate Mini-Cards:**
  - Horizontal bar showing real-time `TCP %`, `UDP %`, and `ICMP %` split.
- **Bottom Panel — Live Incoming Flow Stream Table:**
  - Auto-scrolling (with a `"Pause Stream"` toggle button on hover) table of the latest 200 incoming windows:
    - Columns: `Timestamp` | `Source IP (MAC)` | `Target IP` | `Proto` | `Pkt Rate (pps)` | `Avg Size` | `SYN/ACK Ratio` | `Predicted Class` | `Confidence Bar` | `Inspect (22F)`

### Module 3: Attack Detection & Alerts (`AttackAlertsView.tsx`)
- **Filter Bar:** Filter by Severity (`ALL`, `CRITICAL (DDoS)`, `HIGH (DoS)`) and Status (`Unacknowledged`, `Acknowledged`, `All`) + `"Acknowledge All Visible"` bulk action.
- **Alert Cards Grid:**
  - Each alert card displays:
    - **Header:** Severity badge (`CRITICAL` or `HIGH`), Attack Type (`DDoS` or `DoS`), Detection Timestamp, and Parent Incident ID link.
    - **Endpoints:** `Attacker IP -> Target IoT IP` + Dominant Protocol pill.
    - **Local Explainability Strip ("Why the Model Flagged This Flow"):** Renders the **Top 3 Anomalous Features** from `top_anomalies`, showing:
      - `Feature Name`: `Observed Value` vs `Benign Median` + badge `[+98.4x IQR]`
    - **Footer:** Model confidence percentage + `"Acknowledge Alert"` button.

### Module 4: Network Flow Explorer (`FlowExplorerView.tsx`)
- **Multi-Faceted Search & Filter Toolbar:**
  - Search input for `src_ip`, `dst_ip`, or `src_mac`.
  - Dropdown filters for `Predicted Class` (`All`, `Benign`, `DoS`, `DDoS`), `Protocol` (`All`, `TCP`, `UDP`, `ICMP`), and `Minimum Confidence` slider (`0%` to `99%`).
- **Paginated Data Grid:**
  - Displays matching flows from `GET /api/v1/flows`.
- **Interactive 22-Feature Slide-Over Drawer (`FeatureDrawer.tsx`):**
  - Clicking **any** flow row in Module 2 or Module 4 opens a right-hand slide-over drawer displaying:
    - **Section A:** Full class probability distribution bars (`Benign %`, `DoS %`, `DDoS %`) and model used.
    - **Section B:** Top 3 IQR Anomalies for that specific window.
    - **Section C:** All **18 Base Features** and **4 Derived Ratio Features** rendered in a structured 2-column monospace table with units (`pps`, `bytes`, `sec`, `ratio`).

### Module 5: Model Performance Analytics (`ModelAnalyticsView.tsx`)
- **Model Comparison Selector:** Allows inspecting benchmark analytics for `XGBoost`, `Balanced Random Forest`, `Calibrated SVM`, and `Logistic Regression` side-by-side or individually (`GET /api/v1/models/{model_id}/analytics`).
- **Top Metric Strip:**
  - `Held-Out Test Accuracy`, `Macro-F1 Score`, `Benign Precision/Recall`, `DoS F1-Score`, `DDoS F1-Score`.
- **Visualizations (2-Column Grid):**
  - **Left:** **3x3 Interactive Confusion Matrix Heatmap** (`True Benign/DoS/DDoS` vs `Predicted Benign/DoS/DDoS`) with both raw sample counts and row-normalized recall percentages in every cell.
  - **Right:** **Top 22 Deterministic Feature Importance Horizontal Bar Chart** (Recharts `BarChart`), color-coding the **18 Base Features** in Sky Blue and the **4 Engineered Ratio Features** (`bytes_per_sec`, `syn_ack_ratio`, `hdr_pkt_ratio`, `pkt_cv`) in Emerald to highlight how ratio engineering improved tree splits.

### Module 6: Incident History & Forensic Export (`IncidentHistoryView.tsx`)
- **Status Filter:** `All Incidents` | `Active Threats` | `Resolved History`.
- **Incident Table / Timeline:**
  - Columns: `Incident ID` | `Status Badge (ACTIVE / RESOLVED)` | `Title & Category` | `Target IoT Device` | `Unique Attackers` | `Affected Windows (100-pkt)` | `Peak Rate (pps)` | `Start / Last Seen Time` | `Actions`.
- **Action Buttons per Incident:**
  - **`Resolve Incident`:** Calls `PATCH /api/v1/incidents/{id}/resolve` and updates badge to `RESOLVED`.
  - **`Export JSON` / `Export CSV`:** Triggers direct browser download from `GET /api/v1/incidents/{id}/export?format=json|csv`.