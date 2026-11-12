# 01 — AGENT GOVERNANCE, QUALITY GATES & ANTI-DRIFT PROTOCOL
**Applies To:** All AI Coding Assistants (Cursor, Claude Code, GitHub Copilot, Windsurf, Devin, OpenHands, etc.) and Human Contributors.

---

## 1. THE GOLDEN RULE: ZERO ARCHITECTURAL IMPROVISATION
Autonomous coding agents frequently fail on multi-service ML systems because they "simplify" feature extraction, invent new JSON field names, drop features they find inconvenient to calculate, or replace real algorithms with dummy mocks.

**In this repository, improvisation is strictly forbidden.**
1. You **MUST NOT** change any of the 22 feature names or their mathematical equations.
2. You **MUST NOT** move the 4 derived ratio calculations into Go, nor move the 18 base packet calculations into Python (except inside `csv_replayer.py` where the 18 base features are already present in the CSV).
3. You **MUST NOT** emit one security alert per window without passing through the stateful `IncidentDebouncer`.
4. You **MUST NOT** use random number generators (`math/rand` or `random.uniform`) to fake ML predictions or packet features in production code.
5. You **MUST NOT** write boilerplate stubs, dummy return values, `TODO` / `pass` placeholders, or comment-only skeletons into code files. A code file must either remain untouched until its implementation phase or be 100% fully implemented end-to-end.

---

## 2. MANDATORY OVERRIDE & ESCALATION PROTOCOL

If a user prompt, a missing dependency, or a runtime bug tempts you to alter any specification in files `00` through `05`, you **MUST STOP** before editing any code file and output the following exact warning block in chat:

```text
CRITICAL NOTE: (THIS GOES AGAINST YOUR PREDEFINED STRUCTURE, PLEASE CONFIRM IF YOU WANNA OVERRIDE THIS WITH THE EXPECTED BEHAVIOUR)
- Proposed Deviation: <Exact description of what is changing>
- Violated Specification: <File name and Section number, e.g., 03_GO_PACKET_COLLECTOR_SPEC.md Section 3.2>
- Reason / Trigger: <Why this deviation is being considered>
- Blast Radius: <List all files across Go, Python, and React that will break if not updated simultaneously>
```

### 2.1 Actions Required After User Confirms an Override
If and only if the user replies with explicit confirmation to override the specification:
1. **Step 1 — Documentation First:** Update the relevant `.md` files (`00` through `05`) FIRST so the markdown documentation remains the single source of truth.
2. **Step 2 — Complete Code Audit (Non-Negotiable):** Before writing the new code, perform a full audit across `collector-go/`, `backend-fastapi/`, and `frontend-react/` to identify every struct, Pydantic model, SQLAlchemy table, and TypeScript interface affected by the change.
3. **Step 3 — Atomic Update:** Update all affected layers in a single cohesive pass and run the verification test suite.

---

## 3. AGENTIC CODING QUALITY TACTICS (DEFENSIVE ENGINEERING)

To prevent subtle drift across long coding sessions, every agent must enforce these seven engineering tactics:

### Tactic 1: Schema Parity Lock
The 18 base feature names and 22 total feature names exist in three places:
- Go: `collector-go/internal/window/aggregator.go` (`Features18` struct JSON tags)
- Python: `backend-fastapi/app/schemas.py` (`Features18Payload` & `Features22Payload`)
- TypeScript: `frontend-react/src/types/sentinel.ts` (`Features22` interface)

**Rule:** Never rename a field in one language without grepping for that exact string across the entire repository. Notice that CICIoT2023 has legacy capitalization (`flow_duration` is lowercase, `Rate` and `Header_Length` are capitalized, `AVG` and `Std` are mixed). **Preserve the exact CICIoT2023 casing everywhere.**

### Tactic 2: Deterministic Math Unit Test Gate
Before connecting `collector-go` to `backend-fastapi`, you must write and pass a unit test in both Go (`aggregator_test.go`) and Python (`test_feature_adapter.py`) using a synthetic 100-packet SYN flood fixture:
- 100 TCP packets, each 54 bytes total length, 40 bytes IP+TCP header, TTL=64, `SYN=1`, `ACK=0`, spaced `0.0001s` apart (`flow_duration = 0.0099s`).
- Both tests must assert the exact same floating-point values (within $\epsilon = 10^{-5}$).

### Tactic 3: Self-Healing Bootstrap Artifact Mode
If the user has not yet copied the 4 trained `.joblib` files from Kaggle into `ml/artifacts/`, `backend-fastapi` **MUST NOT** crash on startup.
- Instead, `ml_registry.py` must check if `ml/artifacts/ciciot_22f_xgb.joblib` exists.
- If missing, it must run a deterministic bootstrap builder (`build_bootstrap_bundles()`) that trains lightweight, valid scikit-learn/XGBoost pipelines on 300 rows of synthetic Benign/DoS/DDoS physics-aligned vectors (or `ml/sample_data/test_sample_500.csv` if present) and saves valid `.joblib` bundles in the exact production schema.
- It must also set `"is_bootstrap_model": true` in `/api/v1/models` so the UI displays a clear banner: `"Running Bootstrap Demo Models — Drop Kaggle .joblib files into ml/artifacts/ for Full Benchmark Weights"`.

### Tactic 4: Strict Division-by-Zero & NaN Firewall
Network captures frequently contain bursts where all 100 packets share the exact same microsecond timestamp (`flow_duration == 0.0`) or empty payloads (`AVG == 0.0`).
- In Go: If `flow_duration <= 1e-6`, clamp `flow_duration = 1e-6` before computing `Rate = float64(N) / flow_duration`.
- In Python: Replace `np.inf`, `-np.inf`, and `np.nan` with the bundle's `impute_medians` dictionary before calling `model.predict_proba()`.
- JSON serialization in FastAPI **MUST NEVER** emit `NaN` or `Infinity` (which breaks browser `JSON.parse()`).

### Tactic 5: Bounded Memory & Ring Buffers
- **Go Collector:** Channel buffers between packet decoding and HTTP shipping must be bounded (`capacity = 256` windows) with non-blocking drop metrics so a slow backend never causes an Out-Of-Memory (OOM) crash in Go.
- **React Frontend:** The live flow stream array in React state must be capped at a rolling ring buffer of **200 flows max**, and the live traffic chart buffer must be capped at **60 data points** (1 per second). Never `.push()` unboundedly in a WebSocket listener.

### Tactic 6: Zero Placeholder UI Components
Every button, filter, tab, and modal specified in `05_REACT_SOC_DASHBOARD_UX_SPEC.md` must be wired to a real state handler or FastAPI endpoint. Do not render buttons with `onClick={() => {}}` or `"TODO: Coming Soon"` placeholders.

### Tactic 7: Pre-Commit Audit Checklist
At the end of every implementation milestone, the agent must run and report the output of:
1. `cd collector-go && go test -v ./...`
2. `cd backend-fastapi && pytest -v`
3. `cd frontend-react && npm run build` (verifying zero TypeScript or Vite bundling errors)