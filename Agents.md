# INSTRUCTIONS & GOVERNANCE FOR AI CODING AGENTS (`Agents.md`)

**Applies To:** All Autonomous & Interactive AI Coding Agents (Antigravity, Cursor, Claude Code, GitHub Copilot, Windsurf, Devin, OpenHands, etc.).

You are an expert Full-Stack Systems Engineer and Machine Learning Engineer building the **CICIoT23 Sentinel** real-time AI Network Intrusion Detection System (NIDS) and SOC Command Center.

---

## 1. MANDATORY SOURCE OF TRUTH (`agents/` DIRECTORY)

All AI coding agents **MUST** read and strictly adhere to the specification documents inside the [`agents/`](./agents/) directory before creating, modifying, or refactoring any code.

> **PRIORITY RULE:** The specification files in [`agents/`](./agents/) have **strictly higher priority** than [`ProjectDescription.md`](./ProjectDescription.md), [`README.md`](./README.md), or this summary file. Whenever a detail in a root file appears abbreviated or differs in naming from [`agents/`](./agents/), the [`agents/`](./agents/) specification governs.

### Required Reading Order in `agents/`

| Order | Specification File | Scope & Authority |
| :--- | :--- | :--- |
| **00** | [`agents/master_architecture_integration_blueprint.md`](./agents/master_architecture_integration_blueprint.md) | End-to-end Dual-Track architecture, monorepo layout, JSON wire contracts (`POST /api/v1/ingest/windows`, `WS /ws/live`), Docker networking (`172.18.0.0/16`), and step-by-step build sequence. |
| **01** | [`agents/agent_governance_anti_drift_protocol.md`](./agents/agent_governance_anti_drift_protocol.md) | **NON-NEGOTIABLE:** Zero architectural improvisation rules, Mandatory Override & Escalation warning block, Schema Parity Lock, synthetic 100-packet SYN flood math test gate, Self-Healing Bootstrap model fallback, NaN/div-by-zero firewall, and bounded ring buffers. |
| **02** | [`agents/machine_learning_pipeline_22_feature_contract.md`](./agents/machine_learning_pipeline_22_feature_contract.md) | The locked 22-feature contract (18 Go base features + 4 Python derived ratios), exact casing/ordering (`0..21`), `.joblib` artifact schema (`xgb`, `brf`, `svm`, `lr`), and Top-3 Benign IQR Z-Score local explainability formula. |
| **03** | [`agents/go_packet_collector_specification.md`](./agents/go_packet_collector_specification.md) | `collector-go` CLI flags (`--mode pcap\|live`), `gopacket` L2/L3/L4 parsing rules, exact float64 equations for the 18 base features, majority-vote Track A metadata aggregation, OUI lookup, and HTTP batch shipper with backoff. |
| **04** | [`agents/fastapi_backend_ml_engine_database_specification.md`](./agents/fastapi_backend_ml_engine_database_specification.md) | `backend-fastapi` SQLite WAL database schema (`devices`, `flow_logs`, `security_alerts`, `incidents`), stateful `IncidentDebouncer` (5s window / 15s cooldown), `/api/v1/*` REST routes, and `WS /ws/live` streaming protocol. |
| **05** | [`agents/react_soc_dashboard_ui_ux_specification.md`](./agents/react_soc_dashboard_ui_ux_specification.md) | `frontend-react` Carbon-Slate dark UI tokens (`#090D16`), tabular monospace typography, global command header, navigation dock, and functional requirements for all 6 SOC modules. |
| **06** | [`agents/readme_quickstart_guide.md`](./agents/readme_quickstart_guide.md) | `.joblib` placement (`ml/artifacts/`), Docker Compose startup, and live `hping3` DoS verification workflow. |

---

## 2. STRICT ANTI-DRIFT & NO-BOILERPLATE GUARDRAILS

Per [`agents/agent_governance_anti_drift_protocol.md`](./agents/agent_governance_anti_drift_protocol.md):

1. **ZERO BOILERPLATE / NO UNIMPLEMENTED STUBS RULE (CRITICAL):**
   - **NEVER** populate code files (`.py`, `.go`, `.ts`, `.tsx`, `.sh`) with half-implemented boilerplate, dummy return stubs, comment-only skeletons, `pass` / `TODO` placeholders, or no-op handlers (`onClick={() => {}}`).
   - Leaving boilerplate in a file creates false positives where subsequent passes assume a file is already implemented and ignore it.
   - A file must either remain completely untouched until its implementation milestone is reached, or be **100% fully implemented, wired, and verified** according to its specification in [`agents/`](./agents/).

2. **NO FEATURE HALLUCINATION OR REORDERING:**
   - The Go collector (`collector-go/`) **MUST ONLY** extract the **18 base features** in 100-packet windows (`flow_duration`, `Rate`, `Header_Length`, `Duration`, `fin_flag_number`, `syn_flag_number`, `rst_flag_number`, `psh_flag_number`, `ack_flag_number`, `ack_count`, `syn_count`, `fin_count`, `rst_count`, `TCP`, `UDP`, `ICMP`, `AVG`, `Std`).
   - The Python backend (`backend-fastapi/`) **MUST ONLY** compute the **4 derived ratio features** (`bytes_per_sec`, `syn_ack_ratio`, `hdr_pkt_ratio`, `pkt_cv`).
   - **NEVER** add leaked or unstable CICIoT2023 columns (`IAT`, `Number`, `Weight`, `Covariance`, `Radius`, `Variance`, `Magnitue`).
   - **PRESERVE EXACT CASE SENSITIVITY** across Go JSON tags, Python Pydantic/DataFrame columns, and TypeScript interfaces.

3. **MANDATORY OVERRIDE WARNING BLOCK:**
   If a user prompt, missing dependency, or runtime issue tempts you to deviate from any specification in `agents/`, you **MUST STOP** before editing code and output:
   ```text
   CRITICAL NOTE: (THIS GOES AGAINST YOUR PREDEFINED STRUCTURE, PLEASE CONFIRM IF YOU WANNA OVERRIDE THIS WITH THE EXPECTED BEHAVIOUR)
   - Proposed Deviation: <Exact description of what is changing>
   - Violated Specification: <File name in agents/ and Section number>
   - Reason / Trigger: <Why this deviation is being considered>
   - Blast Radius: <List all files across Go, Python, and React that will break if not updated simultaneously>
   ```

4. **SELF-HEALING BOOTSTRAP MODELS:**
   `backend-fastapi` must never crash on startup if `ml/artifacts/ciciot_22f_*.joblib` files are missing; it must build deterministic physics-aligned bootstrap bundles and flag `"is_bootstrap_model": true`.

5. **STATEFUL INCIDENT DEBOUNCING:**
   Never fire one alert per malicious window. Group DoS/DDoS windows via the stateful `IncidentDebouncer` (5-second window, 15-second cooldown per `(dst_ip, predicted_class)`).

6. **DIVISION-BY-ZERO & NaN FIREWALL:**
   Clamp `flow_duration` to `>= 1e-6` in Go, use `+ 1e-5` denominators for ratios in Python, impute any `NaN`/`inf` via `impute_medians`, and never serialize `NaN` or `Infinity` in JSON.

7. **BOUNDED BUFFERS:**
   Cap Go shipper channels (`256` windows) and React live state ring buffers (`200` flows max, `60` chart data points max).

---

## 3. MODULE & FILE MAPPING REFERENCE

When implementing each module end-to-end (with zero boilerplate stubs), follow the authoritative specifications in `agents/`:

- **Go Collector (`collector-go/`):** Governed by [`agents/go_packet_collector_specification.md`](./agents/go_packet_collector_specification.md)
  - `main.go` — CLI entrypoint & operational mode flags (`pcap` / `live`)
  - `internal/parser/packet.go` — `gopacket` L2/L3/L4 packet decoding & OUI vendor lookup
  - `internal/window/aggregator.go` — 100-packet tumbling window buffer, Track A majority-vote metadata, and Track B 18 base feature calculations
  - `internal/shipper/client.go` — Batched HTTP POST client (`/api/v1/ingest/windows`) with exponential retry backoff
- **FastAPI Backend (`backend-fastapi/`):** Governed by [`agents/fastapi_backend_ml_engine_database_specification.md`](./agents/fastapi_backend_ml_engine_database_specification.md) & [`agents/machine_learning_pipeline_22_feature_contract.md`](./agents/machine_learning_pipeline_22_feature_contract.md)
  - `app/main.py`, `app/config.py`, `app/database.py`, `app/schemas.py` — FastAPI app, settings, SQLite WAL engine/models, and 18/22-feature Pydantic contracts
  - `app/services/inference.py` — 18->22 feature adapter, `.joblib` model registry (`xgb`, `brf`, `svm`, `lr`) with bootstrap fallback, and IQR Z-score explainability
  - `app/services/incident_manager.py` — Stateful `IncidentDebouncer`
  - `app/services/pcap_runner.py` — Offline `.pcap`/`.pcapng` processor & `.csv` replay task
  - `app/services/ws_manager.py` — `WS /ws/live` WebSocket broadcast manager
  - `app/routers/ingest.py`, `pcap.py`, `incidents.py`, `analytics.py` — `/api/v1/*` REST API routers
- **React SOC Frontend (`frontend-react/`):** Governed by [`agents/react_soc_dashboard_ui_ux_specification.md`](./agents/react_soc_dashboard_ui_ux_specification.md)
  - `src/types/telemetry.ts` — Locked 22-feature TypeScript interfaces & WebSocket/REST payloads
  - `src/hooks/useLiveTelemetry.ts` — WebSocket client hook with 200-flow & 60-second ring buffers
  - `src/components/layout/TopStatusBar.tsx` & `GlassDock.tsx` — Global command bar & 6-module navigation dock
  - `src/components/modules/*` — All 6 SOC dashboard modules (`OverviewBento`, `LiveTrafficView`, `AttackAlertsPanel`, `FlowExplorerTable`, `ModelAnalyticsView`, `IncidentHistoryView`)
- **Testbed & Orchestration (`docker-compose.yml`, `testbed/`):** Governed by [`agents/master_architecture_integration_blueprint.md`](./agents/master_architecture_integration_blueprint.md) & [`agents/readme_quickstart_guide.md`](./agents/readme_quickstart_guide.md)

Execute implementation step-by-step per [`agents/master_architecture_integration_blueprint.md`](./agents/master_architecture_integration_blueprint.md) Section 6. Ask the user which module (`backend-fastapi`, `collector-go`, or `frontend-react`) they want implemented first.
