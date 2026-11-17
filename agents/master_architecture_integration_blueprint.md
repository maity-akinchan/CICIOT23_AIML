# Go + FastAPI architecture

Current decision (2026-11-17): use the existing supplied XGBoost artifact without
retraining. Preserve contributor Go code. The user explicitly authorizes approximate
packet measurements despite unverified parity with Kaggle. Do not substitute models,
fabricate compatibility, or enable firewall actions. The implementation scope is
Go + FastAPI; UI implementation is deferred.

PCAP/live interface -> Go directed-flow windows -> HTTP base measurements ->
FastAPI approximate adapter -> CSV preprocessing -> 22-feature DataFrame -> supplied
XGBoost -> persisted predictions, WebSocket updates, downloadable feature CSV.

The intermediate DataFrame is the exact model-input table; CSV export serializes
that table. No CSV reload is needed between feature construction and prediction.
`GET /api/v1/features/export?capture_session_id=...` returns the 22 inputs in order.

Go sends `sentinel-packet-approx22-v1`, its hash, collector/session identity,
windows and measured `transport_header_mean`. The adapter replaces Header_Length
with that mean. Raw counts remain per window, not guessed cumulative statistics.
The model's original dataset and this measurement contract remain distinct.

Historical artifacts and source provenance are preserved. CSV-only retraining is
optional and uses only himadri07/ciciot2023. No PCAP training is required.
