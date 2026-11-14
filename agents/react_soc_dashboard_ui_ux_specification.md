# 05 — REACT COMMAND CENTER UI/UX SPECIFICATION (`frontend-react/`)
**Stack:** React 18 + TypeScript + Vite + Tailwind CSS + Recharts + Lucide React Icons  
**Design Paradigm:** Atmospheric Minimalism & High-Craft Dark UI blended with Kinetic Typography & Neo-Brutalist Swiss Grids.  
**Specification Version:** `v2.0.0` (Active Protection, Connected Devices, Agent Onboarding & Strict Plain-English UI Policy)

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

### 1.4 STRICT PLAIN-ENGLISH UI POLICY (MANDATORY)
Never use overly complex, academic, or unnecessary cybersecurity/ML buzzwords anywhere in the React UI. Every label, button, tooltip, and status message must be immediately understandable to a regular developer or sysadmin at a glance.

#### Mandatory Vocabulary Replacements
| Forbidden Jargon / Academic Term | Mandatory Plain-English Replacement |
| :--- | :--- |
| Autonomous SOAR Mitigation | **Auto-Block Attacks** |
| Telemetry Ingestion & Flow Windows | **Live Network Traffic** |
| Endpoint Quarantine / Network Isolation | **Block All Internet (Kill Switch)** |
| IQR Z-Score Anomaly Attribution | **Why This Was Flagged** |
| Stateful Debounced Incidents | **Attack History** |
| Heuristic / Inference Confidence | **Model Confidence** |
| `HEALTHY` / `UNDER_DOS` / `UNDER_DDOS` (UI badges) | **Normal** / **DoS Attack** / **DDoS Attack** |

#### Mandatory Feature Name Translations (`src/utils/plainEnglish.ts`)
Whenever displaying any of the 22 features in the UI (in alerts, drawers, or feature importance charts), always show a friendly label next to or instead of the raw column name:
- `flow_duration` → **Duration (sec)**
- `Rate` → **Packet Rate (pkt/s)**
- `Header_Length` → **Header Size (bytes)**
- `Duration` → **TTL (Hop Count)**
- `syn_flag_number` / `syn_count` → **SYN Flags (New Connection Requests)**
- `ack_flag_number` / `ack_count` → **ACK Flags (Confirmed Packets)**
- `rst_flag_number` / `rst_count` → **RST Flags (Dropped Connections)**
- `fin_flag_number` / `fin_count` → **FIN Flags (Closed Connections)**
- `psh_flag_number` → **PSH Flags (Push Data)**
- `TCP` / `UDP` / `ICMP` → **TCP / UDP / ICMP Traffic Share**
- `AVG` → **Average Packet Size**
- `Std` → **Packet Size Spread**
- `bytes_per_sec` → **Traffic Speed (Bytes/s)**
- `syn_ack_ratio` → **SYN-to-ACK Ratio (Unfinished Connections)**
- `hdr_pkt_ratio` → **Header-to-Packet Ratio**
- `pkt_cv` → **Packet Size Variation**

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

2. **8-Page Navigation Bar (`NavigationDock.tsx`):**
   - Persistent horizontal tab bar (or floating dock) with live badge counters on Alerts, Attack History, and Connected Devices:
     1. `1. Security Overview`
     2. `2. Live Network Traffic`
     3. `3. Attack Alerts` *(shows unacknowledged count badge)*
     4. `4. Flow Explorer`
     5. `5. Model Performance`
     6. `6. Attack History` *(shows active attack count badge)*
     7. `7. Connected Devices` *(shows online device count badge)*
     8. `8. Add Device`

---

## 3. FUNCTIONAL SPECIFICATIONS FOR ALL 8 PAGES

### Module 1: Security Overview Dashboard (`OverviewDashboard.tsx`)
- **Row 1 — 5-Card Swiss Bento KPI Strip:**
  1. **Total Flows Monitored:** Large tabular number + current `flows/sec` rate.
  2. **Benign Traffic:** Count + percentage of total in Emerald.
  3. **DoS Detections:** Count + percentage of total in Amber.
  4. **DDoS Detections:** Count + percentage of total in Crimson.
  5. **Attack Ratio:** Overall `(DoS + DDoS) / Total` percentage + progress bar.
- **Row 2 — Real-Time Telemetry Charts (2-Column Split):**
  - **Left (65% width):** **Live Traffic Classification Stream (Recharts Stacked AreaChart)** over a rolling 60-second window showing `Benign` (Emerald), `DoS` (Amber), and `DDoS` (Crimson) flows per second.
  - **Right (35% width):** **Connected Device Health** showing discovered/connected devices (`device_name`, `ip_address`, `vendor`, `total_flows_seen`) and a plain-English health badge (`Normal`, `DoS Attack`, `DDoS Attack`).
- **Row 3 — Recent Attack Alerts Feed:**
  - Compact table of the 6 most recent `security_alerts` with timestamp, severity badge, `src_ip -> dst_ip`, top **"Why This Was Flagged"** pill, and quick `Acknowledge` button.

### Page 2: Live Network Traffic & PCAP Analyzer (`LiveTrafficMonitor.tsx`)
- **Top Panel — Dual Ingestion Controls:**
  - **Drag-and-Drop PCAP / CSV Analyzer Zone:** Accepts `.pcap`, `.pcapng`, and `.csv` files. Displays upload progress and an immediate classification breakdown card (`Processed X traffic windows: Y Normal, Z DoS, W DDoS`) upon completion.
  - **Live CLI Command Helper Card:** Copyable one-liner showing how to attach `collector-go` to a local interface or run `hping3` against the testbed target.
- **Middle Panel — Protocol Distribution & Live Rate Mini-Cards:**
  - Horizontal bar showing real-time `TCP %`, `UDP %`, and `ICMP %` split.
- **Bottom Panel — Live Incoming Traffic Table:**
  - Auto-scrolling (with a `"Pause Stream"` toggle button on hover) table of the latest 200 incoming traffic windows:
    - Columns: `Timestamp` | `Source IP (MAC)` | `Target IP` | `Proto` | `Packet Rate (pps)` | `Avg Size` | `SYN-to-ACK Ratio` | `Prediction` | `Model Confidence` | `Inspect (22F)`

### Page 3: Attack Alerts (`AttackAlertsView.tsx`)
- **Filter Bar:** Filter by Severity (`ALL`, `CRITICAL (DDoS)`, `HIGH (DoS)`) and Status (`Unacknowledged`, `Acknowledged`, `All`) + `"Acknowledge All Visible"` bulk action.
- **Alert Cards Grid:**
  - Each alert card displays:
    - **Header:** Severity badge (`CRITICAL` or `HIGH`), Attack Type (`DDoS` or `DoS`), Detection Timestamp, and Attack History ID link.
    - **Endpoints:** `Attacker IP -> Target Device IP` + Dominant Protocol pill.
    - **Why This Was Flagged:** Renders the **Top 3 Anomalous Features** from `top_anomalies` using Plain-English feature labels, showing:
      - `Plain-English Feature Label`: `Observed Value` vs `Normal Median` + badge `[+98.4x normal]`
    - **Footer:** **Model Confidence** percentage + `"Acknowledge Alert"` button.

### Page 4: Flow Explorer (`FlowExplorerView.tsx`)
- **Multi-Faceted Search & Filter Toolbar:**
  - Search input for `src_ip`, `dst_ip`, or `src_mac`.
  - Dropdown filters for `Prediction` (`All`, `Benign`, `DoS`, `DDoS`), `Protocol` (`All`, `TCP`, `UDP`, `ICMP`), and `Minimum Model Confidence` slider (`0%` to `99%`).
- **Paginated Data Grid:**
  - Displays matching flows from `GET /api/v1/flows`.
- **Interactive 22-Feature Slide-Over Drawer (`FeatureDrawer.tsx`):**
  - Clicking **any** flow row in Page 2 or Page 4 opens a right-hand slide-over drawer displaying:
    - **Section A:** Full class probability distribution bars (`Normal %`, `DoS %`, `DDoS %`) and model used.
    - **Section B:** **Why This Was Flagged** (Top 3 anomalous features for that specific window in Plain English).
    - **Section C:** All **18 Base Features** and **4 Derived Ratio Features** rendered in a structured 2-column table with **Plain-English labels** and units (`packets/sec`, `bytes`, `sec`, `ratio`).

### Page 5: Model Performance (`ModelAnalyticsView.tsx`)
- **Model Comparison Selector:** Allows inspecting benchmark analytics for `XGBoost`, `Balanced Random Forest`, `Calibrated SVM`, and `Logistic Regression` side-by-side or individually (`GET /api/v1/models/{model_id}/analytics`).
- **Top Metric Strip:**
  - `Held-Out Test Accuracy`, `Macro-F1 Score`, `Benign Precision/Recall`, `DoS F1-Score`, `DDoS F1-Score`.
- **Visualizations (2-Column Grid):**
  - **Left:** **3x3 Interactive Confusion Matrix Heatmap** (`True Normal/DoS/DDoS` vs `Predicted Normal/DoS/DDoS`) with both raw sample counts and row-normalized recall percentages in every cell.
  - **Right:** **Top 22 Feature Importance Horizontal Bar Chart** (Recharts `BarChart`) using Plain-English feature labels, color-coding the **18 Base Features** in Sky Blue and the **4 Derived Ratio Features** in Emerald.

### Page 6: Attack History & Forensic Export (`IncidentHistoryView.tsx`)
- **Status Filter:** `All Attacks` | `Active Attacks` | `Resolved History`.
- **Attack History Table / Timeline:**
  - Columns: `Attack ID` | `Status Badge (ACTIVE / RESOLVED)` | `Title & Category` | `Target Device` | `Unique Attackers` | `Affected Windows (100-pkt)` | `Peak Rate (pps)` | `Start / Last Seen Time` | `Actions`.
  - Also displays **Auto-Block Actions** taken during each attack episode (e.g., `"Auto-blocked 172.18.0.50"`).
- **Action Buttons per Attack:**
  - **`Mark Resolved`:** Calls `PATCH /api/v1/incidents/{id}/resolve` and updates badge to `RESOLVED`.
  - **`Export JSON` / `Export CSV`:** Triggers direct browser download from `GET /api/v1/incidents/{id}/export?format=json|csv`.

### Page 7: Connected Devices (`ConnectedDevicesView.tsx`)
- **Device Cards Grid:**
  - Displays every monitored device with its **Name**, **ID**, **IP/MAC**, **Online/Offline dot**, **Live Uptime** (e.g., `2h 14m 30s`), and **Current Status badge** (`Normal` in green, `DoS Attack` in amber, `DDoS Attack` in red, or `Internet Blocked` in purple).
- **Device Control Drawer / Panel (opens when clicking a device):**
  - **Auto-Block Attacks Toggle:** Simple switch (`ON` / `OFF`) — *"Allow AI to automatically block attacking IPs on this device"* (`POST /api/devices/{device_id}/action`).
  - **Emergency Kill Switch:** High-contrast button **"Block All Internet"** (toggles to **"Restore Internet"** when active) — cuts off all traffic to/from the device while keeping dashboard control alive (`BLOCK_ALL_INTERNET` / `RESTORE_INTERNET`).
  - **Firewall Rules Manager:** List of currently blocked IPs on this device with a 1-click **"Unblock"** button (`UNBLOCK_IP`), plus an input box to manually **"Block IP Address"** (`BLOCK_IP`).
  - **DNS Switcher:** Quick selector (`Cloudflare 1.1.1.1`, `Quad9 Safe DNS 9.9.9.9`, `Google 8.8.8.8`, or `Custom DNS IP`) with an **"Apply DNS"** button (`SET_DNS`).
  - **Device Attack & Action History:** Clean timeline (`GET /api/devices/{device_id}/history`) showing past DoS/DDoS attacks on this device and what actions the AI or admin took (e.g., *"AI Auto-Blocked 172.18.0.50 due to DoS attack — 2 mins ago"*).

### Page 8: Add Device / Download Service (`DownloadServiceView.tsx`)
- **Step 1 — Name Your Device:** Input field (e.g., `smart-camera-01`) and button **"Generate Setup Key"** (`POST /api/devices/register`).
- **Step 2 — Pick Your Platform:** Cards for `Docker Container`, `Linux (x86_64)`, and `Raspberry Pi / ARM64`.
- **Step 3 — Connect in 1 Click:**
  - Button to **"Download Service Binary"** directly (`GET /api/downloads/agent/{arch}`).
  - Copyable **1-Line Quick Start Command** (`curl -sSL http://<server>:8000/install.sh | sh -s -- --name="My-Device" --token="<token>"`) to paste inside a terminal or Docker container, plus a live indicator showing **"Waiting for device connection... Connected!"** as soon as the first heartbeat arrives.