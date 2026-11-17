> Implementation update (2026-11-16): `sentinel_ml.contract` and
> `sentinel_ml.capture` are the executable specification for new retraining.
> See [training instructions](../ml/training/README.md) and
> [extractor recovery evidence](../ml/provenance/README.md). This update supersedes
> the candidate-policy details below where they differ. The implemented subset is
> classic Ethernet PCAP, unfragmented IPv4 TCP/UDP/ICMP only; other formats reject.
> Training and application share exactly the same extractor and matrix builder.
> New bundles require the contract hash and passing golden-row verification.
> No implicit bootstrap, imputation, legacy-model conversion or auto-blocking.
> The historical notebook is `_legacy`; the main notebook is the corrected retraining workflow.

# FastAPI serving and persistence — v3

**Status:** target design. The prototype implements parts of these paths but has
known defects listed in [the audit](project_audit.md). Core scope is model-backed
analysis; managed-device protection is optional.

## 1. Service boundaries

Use FastAPI/Pydantic for HTTP validation, an inference service for shared
preprocessing and prediction, a registry for artifact validation/selection,
a persistence service for transactions, and session-scoped ingestion/incident
services. Upload/replay must call the service layer rather than import a private
function from another router. Settings belong in `app/config.py`; keep DB/model
paths, allowed origins, limits and operating mode explicit and testable.

Provide an app factory with lifespan-owned services for isolated tests and clean
shutdown. Avoid global WebSocket registries shared across app instances. Use one
worker until live connections and session state are externalized or made durable.

## 2. Model availability and provenance gate

- Load the supplied real XGBoost bundle; advertise other slots as unavailable
  until their actual trained bundles are present. Never silently train a fallback
  classifier during normal startup.
- Test-mode synthetic bundles are explicit, isolated and excluded from benchmark
  comparisons, assessed demonstrations and all device actions.
- Keep `/health` for liveness and expose readiness by capability: model loaded,
  artifact identity, allowed contracts/input modes and unavailable reason.
  A CSV-ready model is not automatically PCAP/live-ready.
- Validate the incoming contract and provenance before inference. Legacy CSV
  experiments may produce predictions with their limitations displayed. The
  proposed packet vectors require a compatible trained artifact or verified
  legacy-extractor parity; otherwise return an explicit compatibility error.
- Select one immutable model handle for a whole upload/replay session. A model
  switch starts a new session/revision; an awaited broadcast must not cause half
  an uploaded file to use a different model.
- Persist artifact SHA-256, contract and preprocessing versions with every
  prediction. Current `model_used` display names alone are insufficient.

## 3. Input and preprocessing validation

Apply the shared, versioned preprocessing described in the ML specification.
Validate class/probability correspondence, finite results and expected feature
count/order. Do not silently truncate class arrays or replace corrupt results
with zero. Reject invalid legacy inputs when no trained imputation policy exists.
Numeric constraints must match the selected contract, not generic guesses based
on feature names. Validate addresses, modes, lengths and timestamps separately.

Keep source metadata honest. Dataset CSV rows lack packet-count/endpoints unless
provided by a verified source manifest; these fields remain nullable and tagged
`dataset` rather than becoming discovered devices. Protocol derived from feature
shares must be marked derived and permit mixed/unknown; do not default UDP to TCP.

Ground-truth labels are accepted only by an evaluation workflow and stored
separately from prediction inputs. Import the notebook's `label` column explicitly;
legacy fixtures may use `attack_class`, with a documented adapter. Never turn a
predicted class into a label for accuracy reporting or retraining.

## 4. Persistence and identity

SQLite WAL is adequate for a single-process project demo with bounded writes;
it is not a guarantee against locks. Use short transactions, busy timeout,
foreign keys, constraints, indexes and explicit migration/version management.

Logical records required by the target:

| Record | Identity and purpose |
| --- | --- |
| Analysis session | Source kind, source hash/manifest, capture/sensor identity, contract, chosen model hash, lifecycle, counts and errors |
| Observation | Stable `(session_id, collector_id, window_id)` uniqueness, event and receipt time, measured features/metadata and validation flags |
| Prediction | Observation reference plus model/preprocessor identity, class scores, prediction, latency and descriptive baseline deviations |
| Evaluation run | Separate true labels, split provenance, metrics and exact evaluated observation IDs |
| Incident/alert | Session-scoped observations, target and predicted category, lifecycle and acknowledgement |
| Registered device | Enrolment identity, separate heartbeat clock and observed-traffic clock; never inferred merely from an arbitrary CSV IP |
| Optional command | Stable command ID, authorization/evidence, dispatch/ACK lifecycle and reconciliation |

Existing `flow_logs`, `devices`, `incidents`, `security_alerts` and `device_actions`
need migrations to represent these identities. Enforce required non-null fields;
current `mapped_column` declarations without `nullable=False` do not enforce the
old table specification. Return the existing result for duplicate observation
retries; count it once and do not duplicate incident/command effects.

Normalize timezone-aware event times to UTC before storage. Never remove an
offset with `replace(tzinfo=None)` before conversion. Keep receipt time separate
from capture time; historical PCAPs must not overwrite live device heartbeat state.

## 5. Ingestion, uploads and replay

Preserve current API paths when compatible; version breaking nullable metadata,
identity and response-shape changes as described in the architecture document.

| Path family | Target behavior |
| --- | --- |
| `/api/v1/predict/batch` | Pure inference with explicit artifact/contract; no device actions or silent session mutation |
| `/api/v1/ingest/windows` | Legacy adapter until a versioned, authenticated, idempotent ingestion contract replaces it |
| `/api/v1/pcap/upload` | Bounded CSV/PCAP upload with contract check, explicit session/progress/error accounting |
| `/api/v1/replay/control`, `/replay/status` | Start/stop a session with pinned model, speed, rows read, failures and terminal status |
| `/api/v1/models`, `/models/select`, `/models/{id}/analytics` | Real model availability and metric provenance, not four fabricated available choices |
| `/api/v1/overview/summary`, `/flows`, `/alerts`, `/incidents` | Session/source filters, pagination and canonical serializations |
| `/api/v1/system/reset` | Stop/quiesce the chosen session and clear its data/state atomically; preserve device/control audit records |
| `/ws/live` | Consistent snapshot/event schemas, sequence/session identifiers, bounded client queues and reconnect behavior |

For small uploads, validate/stage all rows before publishing results. For larger
jobs, expose explicit partial-job states, committed/rejected counts and a resume
policy. A generic 422 after publishing the first 100 rows is not an acceptable
all-or-nothing result. Catch parser errors and close files on every path.

Perform parsing/inference in a bounded worker executor, not inline on the event
loop. Serialize session state updates through a single writer/lock. Database
commit precedes an event enqueue; a disconnected UI must not turn committed
inference into a failed request that gets retried and double-counted. Slow
WebSocket clients have a timeout/drop/reconnect policy. Broadcast work must not
hold database transactions or delay the ingest acknowledgement indefinitely.

Replay timestamps and speed affect presentation only. Incident analytics use
source event time in that session; speeding replay must not invent a higher
attack rate. If dataset rows lack meaningful times, mark simulated timing and do
not use it for measured live detection latency. Background failures are retained
as a failed job/status and cancelled tasks are awaited at shutdown.

## 6. Incident lifecycle and reset

Scope state by session, sensor/observation domain, target and class. Never merge
an uploaded capture, CSV replay and live feed just because they share an IP.
The former three-windows/five-seconds and fifteen-second cooldown are candidate
presentation settings; evaluate their precision and delay rather than treating
them as statistically justified thresholds.

Absorb observations once, maintain source lists from actual attribution and
resolve/close stale episodes through a defined event-time lifecycle. Resolve and
reset clear corresponding pending state. Reset also clears benign counters,
auto-block queues and cooldowns for that session, and cannot race a replay task.
Expiry and global capacity limits apply to keys as well as individual queues.
After restart, reconstruct state or start an explicitly new session; do not imply
continuous incident history if the necessary state was lost.

Device health describes recent observed traffic; offline status is based on
heartbeats. A quiet period is not proof that a device is secure. Status labels
must keep classification, connection and command-execution states distinct.

## 7. Authentication and optional actions

Default target behavior is observe-only and `auto_block_enabled=false`.
Before a lab network deployment, require operator authorization for registration,
model changes, uploads/replay, reset, incident mutation and manual actions;
authenticate collectors and read/WebSocket access as appropriate to exposure.
Use a simple scoped bearer/session scheme suitable for the project; wildcard
CORS is not authentication. Restrict origins to configured dashboard locations.

Do not enable auto-block until every condition is satisfied: explicitly enabled
lab device, authenticated live source, compatible real trained artifact, recent
validated observation, reliable endpoint attribution, validated threshold and
policy, reachable control channel and protected management addresses.
CSV replay, offline captures, synthetic models, unsupported inputs and pure
prediction calls never issue actions. An average class score of .85 is not a
calibrated risk threshold and cannot override these gates.

Persist a command before dispatch and correlate its ACK to device/command ID.
Track `PENDING`, `DISPATCHED`, `SUCCEEDED`, `FAILED`, `TIMED_OUT`, or `SIMULATED`
with reason/timestamps. Reconcile with authenticated heartbeats; do not count a
sent command as successful. Use idempotent command execution and bounded retries.
The current ACK handler only broadcasts arbitrary messages and is insufficient.

## 8. Definition of done

The core demo needs golden-row model parity, deterministic feature tests,
contract rejection, retry idempotency, source isolation, UTC normalization,
malformed-upload recovery, lifecycle/reset tests, bounded/concurrent processing,
model-unavailable tests and one complete browser flow. Model accuracy requires
independent labeled data in addition to these software tests. Optional control
features require their own authorization and command-state acceptance tests.
