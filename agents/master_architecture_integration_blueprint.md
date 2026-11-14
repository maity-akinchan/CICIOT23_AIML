# Architecture and delivery plan — v3

**Goal:** demonstrate that a trained model is deployed in a useful application,
with evidence that its inputs and evaluation support the claims made.
**Status:** target design; the [audit](project_audit.md) records current gaps.

## 1. Core scope

The assessed application uses the supplied XGBoost artifact, FastAPI, a small
React dashboard and persisted inference sessions. Start with three views:
model/evaluation, input/predictions, and alerts/session history. A second trained
model is useful as a comparison, but four deployed algorithms are not required.

Go is a later capture/transport implementation, not a prerequisite for validating
ML. A Python reference extractor may establish the PCAP contract first. Both
implementations must agree before either is used with a model trained for it.

Firewall control, DNS changes, kill switches, binary installers, fleets of
managed endpoints and eight separate pages are optional extensions. Existing
implementations remain experimental until their tests and controls pass.

## 2. Two input contracts, with different evidence

| Contract | Model/input source | Permitted claim |
| --- | --- | --- |
| `ciciot23-csv22-v1` | Existing XGBoost artifact and compatible pre-extracted dataset feature rows | Deployment of a dataset-trained classifier; saved benchmark plus independently evaluated rows when available |
| `sentinel-pcap22-v2` (candidate) | Labeled PCAPs, shared extractor, new compatible trained artifact | PCAP/lab-live inference after extraction, evaluation and integration gates pass |

These proposed contract IDs are not currently fields in the uploaded artifact.
Bind the legacy ID to its SHA-256 in an external manifest; do not modify the
historical model. A successful numerical prediction is not a compatibility check.
The existing CSV artifact is **not approved for the candidate PCAP contract**.

Two routes can establish real-capture support:

1. Recover the exact source CSV extractor, its version, grouping/window policy
   and preprocessing; reproduce it on reference PCAPs and establish parity with
   training rows. This requires evidence, not guessed formulas.
2. Recommended if that provenance cannot be recovered: extract labeled raw
   captures with one explicit, label-independent policy and retrain. Preserve
   the old CSV experiment as a baseline. Split capture sessions before windows.

CSV replay is an application demo, not a live packet-capture demonstration.
Neither a synthetic traffic fixture nor a visually plausible dashboard bridges
this distinction.

## 3. Data path and ownership

```text
CSV rows + source manifest ───────────────┐
                                         ├─ contract validation ─ trained model
PCAP/live ─ approved shared extractor ────┘                        │
                           session + observation identity         ▼
                                                     predictions + provenance
                                                               │
                                                      database + UI stream
                                                               │
                                                  observe-only alert grouping
```

The extractor owns base measurements and packet metadata. A shared preprocessor
owns the four ratios, numeric policy and exact feature order. The serving
registry owns immutable artifact identities and supported contracts. Evaluation
owns ground-truth labels; they never enter the feature vector or production
prediction request. A source manifest owns session/label provenance.

## 4. Identity and wire-contract requirements

Existing `/api/v1/ingest/windows` is a legacy prototype. A versioned successor
must carry `schema_version`, `feature_contract_id`, `extractor_version`,
`capture_session_id`, `collector_id`, `capture_mode`, and stable `window_id`.
Only authenticated collectors can submit live observations. The server binds a
session to its contract and model hash; it does not trust a client's `LIVE_INTERFACE`
string as authority. CSV rows use row IDs and nullable packet metadata, not fake
endpoints or a fictional `packet_count=100`.

Use the existing case-sensitive 18/22 names for the legacy CSV artifact. In a
PCAP contract, specify grouping key, window start/end, UTC event time, receipt
time, packet counts, truncation/unsupported-packet diagnostics and metadata
origin. Source and destination must describe an observed pair. Never assemble
unrelated majority-vote endpoints and treat them as one communicating flow.

Predictions include session/observation ID, model ID/hash, contract ID,
preprocessing version, class probabilities with explicit class order, prediction,
input-validation status, source mode, timestamp and inference duration. Ground
truth, if present in an evaluation run, is stored separately. Choose one public
name for the score (`confidence` in the target API, labeled **Model score** in
UI) and serialize it consistently across REST and WebSocket transports.

Current REST and WS shapes differ; migration requires contract tests. Additive
fields can retain existing paths. Breaking ingestion/response changes must use
a new API version or an explicit compatibility adapter. Do not claim v1 already
implements this design.

## 5. Delivery milestones and gates

| Stage | Work | Exit evidence |
| --- | --- | --- |
| M0: evidence | Preserve notebook/model, add provenance manifest, audit source extractor and obtain real labeled evaluation rows | Hashes, dataset/split facts, unresolved assumptions documented |
| M1: trained-model serving | Remove implicit bootstrap substitution from normal mode; shared preprocessing; golden-row tests; model/evaluation API | Offline and API predictions agree for exported rows; missing/mismatched artifacts fail explicitly |
| M2: useful application | Three dashboard views, CSV upload, persisted sessions, honest metadata, retries and reset fixed | Browser flow from upload through predictions, inspection and report export; no false live claims |
| M3: capture experiment | Reference extractor, capture-grouped splits, retraining or proven legacy parity; independent lab captures | Matching training/serving contract, reproducible held-out metrics and failure cases |
| M4: live demonstration | Capture collector, target-interface visibility, bounded queues, same extractor contract, timestamped lab scenarios | Benign and attack runs with measured false positives, missed events, delay, throughput and packet drops |
| M5: optional protection | Authentication, verified endpoint attribution, command ledger/ACK/reconciliation and sandbox tests | Commands cannot be driven by replay/bootstrap/unsupported data; execution success independently confirmed |

M3 and M4 are required for a credible real-packet/live application claim. M1/M2
alone establish that a trained model has been integrated into software.
Do not spend the remaining project time on M5 while M0/M3 remain unresolved.

## 6. Deployment

Use one backend worker while state is in memory. Bind development services to
localhost; authenticated collector access over the isolated lab network is a
separate configuration. Pin a tested dependency set and build images ahead of
the demonstration. Avoid `pip install`, `apt-get` and `--reload` at demo startup.
The present Compose file is scaffolding, not a validated launch path.

For live capture, observe the target's actual interface/network namespace and
exclude the collector's own API/control traffic where appropriate. Name services
through Compose DNS rather than scattering fixed backend IPs through scripts.
Retain data/artifacts in mounted storage; record hardware and software versions
with timing results. No public firewall-management endpoint is needed for M1–M4.
