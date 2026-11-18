Current revision (2026-11-18): the user authorizes retraining and feature changes
to reduce false positives. Earlier fixed-model restrictions below are superseded.
Use the supplied Kaggle CSVs as the training source. Report benign false-positive
rate and attack recall, and validate packet compatibility independently. Never
claim low live false-positive rates from a CSV validation result alone.

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

Current integration update: React PCAP upload is in scope. Upload classic PCAPs,
show session-specific Benign/DoS/DDoS windows and preserve model provenance.
HTTP APIs require operator bearer credentials; collectors have ingestion-only
credentials. Set SENTINEL_OPERATOR_TOKEN and SENTINEL_COLLECTOR_TOKEN externally.
SENTINEL_AUTH_DISABLED=1 is only for explicit isolated development/tests.
Downloads are built by scripts/build-collectors.sh and installed by
scripts/setup-collector.sh. Cross-compiled binaries support replay only; Linux
live capture needs a native CGO/libpcap build. Use HTTPS outside localhost.
