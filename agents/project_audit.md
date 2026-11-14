# Project audit: training to real application

**Date:** 2026-11-15 (Asia/Kolkata).
**Scope:** current local checkout, including the backend added in the preceding
implementation, supplied notebook/model, original v2 plans and repository fixtures.
**Change in this review:** documentation and agent-plan revision only. The
findings below remain code/data work; v3 documentation does not implement them.

## Assessment

The project can make a defensible AIML demonstration, but the previous plan
prioritized a large SOC/endpoint-control product before proving that deployment
measurements match training inputs. The most important next task is establishing
that contract, not adding more management features.

The supplied XGBoost model can demonstrate deployment of a CSV-trained classifier.
The current hand-defined PCAP extractor cannot yet justify a real-packet accuracy
claim with that model. Matching 22 column names is not sufficient.

## Evidence inspected

- Original `Agents.md`, all seven `agents/` specifications, README, project
  description, Compose, backend code/tests, Go/UI files and sample CSV.
- `ml/notebooks/ciciot23_training.ipynb`, including saved outputs. Cell references
  below are zero-based JSON cell indices, not displayed execution counts.
- `ml/artifacts/ciciot_22f_xgb.joblib`, SHA-256:
  `e1dde2fe2a759684208021934ad3edff2be2dfa29977fac9a246ba9665da233e`.
- Isolated TestClient probes using a temporary SQLite database, synthetic rows
  and in-memory packet records. No real firewall commands or live attacks ran.

The artifact contains recorded test accuracy **89.3683%**, macro-F1 **90.1576%**,
and DoS F1 **78.5802%** over 629,421 test rows. The majority-class accuracy derived
from that stored confusion matrix is **70.6594%**. These are historical experiment
results and a derived baseline, not a new evaluation or verified live accuracy.
Both `windowing_policy_confirmed` and `capture_group_split_verified` are false.

## Findings and fixes, in priority order

### F01 — Critical: training and packet feature semantics disagree

**Evidence:** artifact `benign_baseline` gives `Header_Length` median 509331.0625,
`hdr_pkt_ratio` median 1008.9702, and `rst_count` median 641.2. The old ML/Go specs
and `app/services/pcap_runner.py::aggregate` define mean header bytes, a ratio
bounded by 1, and a raw count bounded by 100 in a full window. A median RST count
above 100 cannot arise from that definition. This proves a contract conflict,
without identifying the true source-extractor formulas.

**Impact:** confident outputs on a different measurement distribution can make
a convincing demo scientifically misleading. A shared column order or synthetic
math test cannot establish the missing compatibility.

**Fix:** preserve the old artifact for compatible feature CSVs. Recover and
verify the original extractor, or retrain on labeled PCAP features produced by a
single documented extractor used for training and live inference. Bind each
artifact to a contract/hash and reject unsupported input modes. Do not rescale
or clip columns by guesswork to force matching predictions.

**Acceptance:** golden source-PCAP/training-row parity if reusing the artifact;
otherwise a new capture-derived artifact, capture-grouped evaluation and matching
reference/serving extraction tests.

### F02 — High: held-out test labels affect training-data curation

**Evidence:** notebook cell 5 concatenates train/validation/test feature hashes
and labels to find conflicts, then removes those hashes from all three splits.
This lets test labels influence training inclusion and excludes ambiguous test
cases. Cells 0/7 and the artifact acknowledge no capture/session split guarantee.
The model-selection rule itself correctly uses validation scores; this finding
is about data curation and group independence, not an accusation of test-based
hyperparameter selection.

**Fix:** preserve the uploaded notebook; make a revised experiment with training-
only conflict rules and predetermined holdout exclusions. Split raw capture
sessions before windows; use grouped folds. Report original and filtered class
counts and any deduplication effects. Do not quantify score inflation without
rerunning a valid experiment.

**Acceptance:** immutable split manifest, no final-test labels used in fitting or
curation, capture-level separation checks and final evaluation performed after
model/threshold selection.

### F03 — High: topology and attack subtype are overclaimed

**Evidence:** the 22 features do not include source cardinality. The isolated
single-source, 100-SYN feature fixture returns `DDoS` with score approximately
0.9999988 from the real artifact. This is an out-of-contract synthetic probe,
not an accuracy test or proof the model is generally wrong. It does show that a
high score cannot certify distributed origins.

Independently voting source/destination in `pcap_runner.aggregate` also fabricates
pairs: 45 A→X, 35 B→Y and 20 B→Z packets produce B→X even though B never sent to X.
Using this metadata to block a source or identify a victim is unsound.

**Fix:** emphasize attack-versus-benign detection; report DoS/DDoS subtype as a
learned class, and observed source diversity separately. Use an observed pair or
explicit aggregate scope; choose the grouping policy before training. Do not claim
that packet-size variance proves a botnet or that a high softmax score proves
correctness on unseen distributions.

### F04 — High: the demonstration data and telemetry are not honest enough

**Evidence:** `ml/sample_data/test_sample_500.csv` has **7 rows**, not 500, with no
verified dataset manifest. It uses `attack_class`; notebook cell 16 exports a
different file, `ciciot23_test_smoke_sample.csv`, with `label`. `csv_windows`
discards labels, invents endpoint addresses, defaults packet count to 100 and
protocol to TCP. Both pure-UDP rows in the repository fixture are reported as TCP.
The backend then creates device records from that metadata.

**Fix:** obtain/export the real held-out sample and expected predictions; retain
source hash and label provenance. Mark test fixtures as fixtures. Keep unknown
packet metadata null, distinguish replay from live input, and store evaluation
labels separately. Add an explicit label-column adapter. Derive protocol only
when its meaning is justified, and label it as derived.

**Acceptance:** a replay cannot appear as a newly discovered live network,
and benchmark reports identify actual data/labels and evaluated row counts.

### F05 — High: synthetic fallback models can replace the scientific subject

**Evidence:** `InferenceEngine.load` trains missing model slots automatically;
`/models` returns synthetic `brf`, `svm`, and `lr` alongside the supplied XGBoost.
They are flagged bootstrap, which is helpful, but are selectable. The action
engine does not inspect bootstrap/model-compatibility status. If XGBoost is
missing, health can still report a loaded synthetic model.

**Fix:** normally serve the real artifact only. Missing optional models are
unavailable, with a reason. Allow synthetic models only by explicit test-mode
configuration, never for benchmark comparisons or device changes. Preserve
immutable artifact identity on every prediction and stream frame.

### F06 — High: authorization and action confirmation are incomplete

**Evidence:** operator registration/actions, reset and ingest routes have no
operator/collector authorization. Isolated requests without credentials registered
a device and changed its `AUTO_BLOCK` setting (both HTTP 200). Heartbeat/agent
WebSocket token checks exist, but do not authorize the operator routes. Device
auto-block defaults to true. Client-supplied source mode and IPs can enter the
action path without validated capture provenance.

`devices.agent` broadcasts arbitrary ACK messages without correlating a persisted
command ID or validating execution status. `device_actions` stores no command ID
or execution lifecycle. Auto-block action text says “Auto-Blocked” at send time.

**Fix:** default observe-only; require scoped credentials and validated source/
model contracts. Defer blocking until attribution is reliable. Use a persistent
command ledger, authorized dispatch, ACK correlation, idempotency, timeout/failure
states and heartbeat reconciliation. Keep replay/test input incapable of actions.
For the project, a read-only alert application already demonstrates ML deployment.

### F07 — High: retries and post-commit failures corrupt counts

**Evidence:** `Flow.window_id` is indexed but not unique. Two identical ingest
requests with the same collector/window ID both returned 200 and created **2**
records. `ingest._predict` commits rows before awaiting action dispatch and UI
broadcast, so a downstream failure can fail the request after data is committed.

**Fix:** stable session/collector/window identity plus a database uniqueness
constraint; idempotent ingestion returns prior results. Stage downstream events
in an outbox/queue after the transaction. A disconnected browser or agent must
not change the persistence outcome or induce double-counting on retries.

### F08 — High: sessions, timestamps and reset have inconsistent state

**Evidence:** incident buffers key only `(dst_ip, class)`; source/session/model
identity is not persisted. UTC offsets are discarded with `replace(tzinfo=None)`.
The input `2026-01-01T05:30:00+05:30` was stored as `05:30` instead of midnight UTC.
Reset clears the pending incident queue but retains benign counters and
AutoBlocker queues; a seeded-state reset probe confirmed both persist. It does
not quiesce replay. Old active incidents may stay ACTIVE while new ones are opened
after their cooldown; resolve does not consistently reset related buffers.

**Fix:** scope observations, device telemetry and incident state to sessions;
normalize event time and keep receipt/heartbeat time separate. Define late-event,
cooldown and restart semantics. Stop or synchronize producers before a session
reset and clear all associated in-memory state atomically. Keep control audits.

### F09 — High: upload failure, model selection and asynchronous work are fragile

**Evidence:** a CSV with 100 valid rows followed by an invalid row returned 422
but left **100 committed predictions**. Upload code commits each batch without a
job/partial-result contract. It also re-reads the active model on each batch;
a model switch between awaits can change models within one file. CPU parsing,
prediction and synchronous DB work execute on the async request path, and socket
broadcasts are awaited serially without timeouts.

**Fix:** validate/stage small files before publication, or implement explicit
partial jobs with counts and recovery. Pin model and contract per job. Use a
bounded executor for heavy work, a serialized state/writer path and bounded
client queues/timeouts. Expose background task failures and orderly cancellation.
Measure latency with realistic capture/ingest load.

### F10 — Medium: capture support is narrower than implied

**Evidence:** the dpkt fallback uses `len(raw)` instead of original wire length,
does not account for IPv6 extension-header length in the feature, omits a live
2-second flush policy, and treats unrecognized IP protocols as TCP on all-zero
protocol-share ties. The old Go design specifies different partial-window rules.

**Fix:** explicitly advertise supported link/protocol types, handle or reject
truncation/extensions/fragments, preserve original packet lengths, and share one
window policy across training/offline/live paths. Test unsupported and partial
cases, not just a clean 100-packet Ethernet SYN example.

### F11 — Medium: probabilities and “explanations” need qualified presentation

**Evidence:** `InferenceEngine._anomalies` ranks weighted distance from benign
medians, not local contributions to the XGBoost decision. The old UI calls this
“Why This Was Flagged.” Probability/class compatibility is permissively defaulted
and bounded with `min(...)`, and missing imputation metadata defaults to zeros,
although training dropped nonfinite values. Serving/training numeric preprocessing
also differs (float64 versus notebook float32 stages and clipping).

**Fix:** shared preprocessing and golden-row equality tests; strict class/encoder
and probability-shape validation; no invented missing-value policy. Label the IQR
result **Deviation from training baseline**. Add TreeSHAP only if useful and
tested. Evaluate calibration before presenting scores as confidence in correctness.

### F12 — Medium: scope, completeness and reproducibility are overstated

**Evidence:** Go source files, React entry points and most components are empty;
`app/config.py` is empty. The Compose file installs dependencies at startup, uses
reload, does not match the old advertised fleet, and cannot run the empty collector.
Some SQL fields lack the non-null constraints promised by the old specification.
Per-key deques are bounded but key dictionaries have no global expiry/capacity.
The existing four tests are narrow smoke tests, not a complete backend, security,
concurrency, UI or model-accuracy suite.

**Fix:** prioritize one real model and a complete three-view read-only application.
Pin a tested environment, add provenance/migrations/constraints, finish one capture
path and measure its errors. Add global state bounds and regression tests for
F07–F11. Keep Go, fleet management and protection extensions out of the critical
path until the ML validation and actual application flow work.

## Recommended next implementation order

1. **Establish evidence and boundaries:** obtain real exported evaluation rows,
   preserve historical artifacts, add contract/source manifests, remove implicit
   bootstrap substitution from normal operation and disable unsupported PCAP/live
   claims and network-changing actions.
2. **Make serving correct:** shared preprocessor and golden predictions; strict
   artifact validation; session identity, retry idempotency, atomic jobs, UTC and
   reset fixes; regression tests.
3. **Finish the application:** CSV analysis, prediction inspection, real metric
   provenance and exports through three tested UI views. Clearly label replay.
4. **Prove the real-world path:** recover original extraction parity or create a
   new raw-capture training experiment; use capture-grouped splits and independent
   lab sessions, then integrate live capture using the same extractor contract.
5. **Extend only after evidence:** optional model comparisons, Go optimization
   and sandboxed response controls, with separate validation.

## What changed in this review

`AGENTS.md` is the canonical entry point and `Agents.md` a compatibility pointer.
All seven specification files were rewritten around this evidence-first scope.
README and ProjectDescription were aligned to current status. The notebook,
model and application code were preserved. v3 introduces target contracts and
gates; it does **not** claim the prototype now enforces them.

## Verification and limits

The existing four backend tests were rerun. Additional isolated probes confirmed
F03/F04 and F06–F09 as described above. Test databases were temporary; no live
network changes occurred. Raw dataset/capture provenance and the notebook's actual
held-out sample were not available, so no independent accuracy benchmark or new
training run was performed. The unfinished Go/UI paths were inspected, not
certified as buildable or usable. Documentation links, artifact preservation and
consistency with the revised scope were checked.
