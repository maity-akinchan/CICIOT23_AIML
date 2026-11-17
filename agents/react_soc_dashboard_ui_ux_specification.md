> Retraining update (2026-11-16): the new notebook and FastAPI use the shared
> `sentinel_ml` package. See [training and API instructions](../ml/training/README.md).
> Supported trained-model IDs are `xgb`, `rf`, `lr`; they are unavailable until
> the corrected capture-based training completes. The legacy artifact is not
> loaded into this new measurement contract. Observe-only controls are enforced.

# AIML demonstration dashboard — v3

**Status:** target UI. The current React app entry points and components are
largely empty; existing files do not establish a working dashboard.

## 1. Core three-view experience

### Model and evaluation

Show the active trained artifact, version/hash, supported input contract/modes
and training provenance. Display the supplied XGBoost benchmark as **Saved
training-run evaluation**, with dataset/split caveats and class support. A newly
executed evaluation appears separately with its actual source and timestamp.

Show macro-F1, class precision/recall, confusion matrix and a majority-class
baseline. Report attack-versus-benign results and DoS/DDoS subtype results
separately. Accuracy on attack-heavy data must not stand alone. Missing trained
models are unavailable; optional comparison cards must not substitute synthetic
estimators for the user's trained models.

Include an experiment narrative: problem, dataset, preprocessing, split, model
choice, deployment path, results and limitations. The audience should be able to
identify which evidence supports the live demonstration.

### Analyze traffic and inspect predictions

Offer CSV feature analysis first. PCAP/live options show their compatibility
status and are enabled only with an approved extractor/model contract. Display
session source as **Dataset CSV**, **Recorded capture**, **Live capture**, or
**Synthetic software test** throughout results and exports.

Each prediction row shows observation ID, event time when known, actual endpoints
when available, class, **Model score**, model version and input status. Unknown
metadata remains unknown. CSV replay must not create a fake connected-device
roster. Show partial/failed uploads clearly, including how many rows were accepted
or rejected. Starting a new session preserves the previous session's model identity.

The inspector shows all 22 values with contract-appropriate units, the complete
class distribution and **Deviation from training baseline**. The current IQR
heuristic is not a model attribution; do not label it “why the model decided.”
If SHAP is later implemented, label it as model contributions, not causality.

### Alerts, sessions and demo evidence

Show session-filtered predictions and grouped alerts, source attribution quality,
acknowledgement/history and report export. A DDoS class prediction must not be
rendered as a verified botnet or fabricated count of attackers. Observed source
counts are separate telemetry.

Display the lab scenario's true labels only when supplied by the evaluation
manifest, separately from predictions. Show false alarms, missed attacks and
latency results. Prediction counts alone are not an accuracy report.

## 2. Useful behavior before visual polish

A complete slice is: choose real model → upload verified rows → see predictions
→ inspect input/probabilities → compare against separately recorded labels →
export a report with artifact and source identity.

Test that path in a browser. Cover loading, empty, invalid-file, missing-model,
unsupported-contract, stale/live-disconnected, partial-failure and reconnect
states. A socket being connected does not prove that new data is arriving.
Never display invented packets/sec or a zero score for an unavailable metric.

Keep the existing dark palette if useful; visual style is subordinate to clear
provenance and correct behavior. Use plain language while retaining exact raw
feature names in inspection/export. Scientific caveats belong next to the
relevant result, not hidden in a separate documentation page.

## 3. API and stream integration

Generate or validate TypeScript types against the versioned backend contract.
Resolve prototype `confidence_score` versus `confidence` differences explicitly.
Snapshot and update frames need compatible shapes, session IDs and sequence IDs.
Deduplicate reconnect updates by observation ID. Bound the visible feed (for
example 200 rows) and chart history (for example 60 points), and use pagination
for persisted history. Distinguish packet rate, observation rate and replay speed.

Measure total detection delay including packet-window formation, queueing,
inference and UI delivery; HTTP request latency alone is not real-time latency.
Keep read-only inspection responsive during uploads.

## 4. Deferred features

The old eight-page dock, fleet onboarding, agent download, DNS settings, manual
firewall rules, automatic blocking and kill switch are optional M5 extensions.
They must not delay model/extractor validation. If shown later, actions require
authorized users and status based on confirmed execution. **Requested**, **Sent**,
**Succeeded**, **Failed**, **Timed out**, and **Simulated** are distinct states.
