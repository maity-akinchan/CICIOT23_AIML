# Engineering and evidence rules — v3

**Status:** target policy, revised 2026-11-15 for the AIML demonstration.
This replaces v2's blanket override prompt, mandatory synthetic model fallback,
and requirement to build an eight-page protection platform before validating ML.

## 1. What counts as evidence

| Claim | Required evidence |
| --- | --- |
| We trained this model | Notebook/training code, dataset version and split manifest, saved model hash and training configuration |
| It achieves a stated score | Evaluation on identified labels and split, class counts, confusion matrix, metric definition, evaluation code and artifact hash |
| This API serves the trained model | Golden-row predictions matching the notebook export, matching class/probability order, immutable model identity in responses |
| It analyzes captures correctly | Extractor parity fixtures plus held-out labeled captures processed end to end |
| It works on live traffic | Independent lab sessions with the same extractor and model, measured false alarms, detection delay, throughput and packet drops |
| It blocked an address | Authorized command, correlated successful acknowledgement and observed device state; a sent message is insufficient |

A synthetic SYN fixture proves an equation or transport path. It cannot validate
CICIoT2023 feature semantics, real-world generalization or classifier accuracy.
A model probability is not evidence that an input belongs to the training domain.

## 2. Source of truth and changes

The model artifact and its training provenance define the existing experiment.
Specifications define the next implementation. When they conflict, surface the
mismatch; never alter feature values just to make the prediction look convincing.
Do not carry forward unsupported claims that certain columns guarantee leakage,
that dropping columns removes all leakage, or that another language cannot
reproduce a statistic. Cite verified extractor/data evidence or label a hypothesis.

New feature/window/grouping semantics need a new contract ID and a separately
validated artifact. Preserve legacy CSV behavior for reference. Breaking API or
storage changes need migration tests and a versioned contract. Do not silently
relabel old results using a new model's identity.

## 3. Tests that matter

- Training/serving parity: preprocessing, dtype, class decoding, `predict_proba`
  column order, representative exported rows and boundary/invalid values.
- Capture parity: independently verified PCAP fixtures, supported link types,
  packet lengths, IPv6 extensions, fragments, partial windows and timestamps.
- Inference correctness: true labels kept separate from predictions, held-out
  results by class and capture; no threshold tuning on the final test set.
- Ingestion: retries, duplicate IDs, concurrent requests, atomic failure, model
  switches, invalid sources/contracts and unavailable artifacts.
- Incident state: source/session isolation, late events, cooldown, reset,
  interruption/restart and bounded state across many distinct endpoints.
- Optional control plane: missing/wrong credentials, authorization scope,
  stale/disconnected agents, timeout/failure/duplicate acknowledgements and
  protection of the management connection.
- UI: live/replay labels, actual API shapes, stale/empty/error states and a
  measured end-to-end demo. A successful bundle build alone is insufficient.

Run `python -m pytest -v` from `backend-fastapi`, `go test ./...` when the Go
component is implemented and its toolchain exists, and `npm ci && npm run build`
when the UI is implemented. Documentation-only revisions require link/contract
consistency checks, not unrelated code churn. Record commands and limitations.

## 4. Honest application behavior

Missing trained model: expose unavailable status and reject its inference requests
with 503. Keep health/diagnostics available. Test-only synthetic estimators require
an explicit opt-in and must never appear as trained comparisons or drive actions.
Invalid capture contract: reject or show diagnostics, never silently predict.
Unknown/OOD traffic: report unsupported input or uncertainty where detected;
softmax scores alone do not provide reliable out-of-distribution detection.

## 5. Practical implementation discipline

Use bounded worker queues and state-key TTLs; a deque capacity alone does not
bound a dictionary with arbitrarily many keys. Avoid CPU inference and large file
parsing on the ASGI event loop. Serialize SQLite writes and use migrations,
constraints, transactions and idempotency. WAL improves concurrency but does not
remove writer contention. Isolate tests in temporary databases and simulated
sockets. Never enable a real firewall change merely to verify a unit test.

Prefer one working, observable inference path to a large scaffold. Record known
remaining work explicitly. User approval of this redesign is already present;
there is no mandatory all-caps confirmation ceremony for ordinary fixes.
