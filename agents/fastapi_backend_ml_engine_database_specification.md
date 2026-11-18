Current revision (2026-11-18): the user authorizes retraining and feature changes
to reduce false positives. Earlier fixed-model restrictions below are superseded.
Use the supplied Kaggle CSVs as the training source. Report benign false-positive
rate and attack recall, and validate packet compatibility independently. Never
claim low live false-positive rates from a CSV validation result alone.

# FastAPI model and collector integration

Current decision (2026-11-17): use the existing supplied XGBoost artifact without
retraining. Preserve contributor Go code. The user explicitly authorizes approximate
packet measurements despite unverified parity with Kaggle. Do not substitute models,
fabricate compatibility, or enable firewall actions. The implementation scope is
Go + FastAPI; UI implementation is deferred.

Default MODEL_DIR is ml/artifacts, loading the supplied ciciot_22f_xgb.joblib.
Missing optional rf/lr files are unavailable. No retraining or synthetic fallback.
The checksum-identified historical bundle retains its encoder, class order and
saved metrics. All other supported artifacts require contract/golden verification.

/health advertises readiness and accepted packet approximation identity/hash.
POST /api/v1/ingest/windows accepts the Go envelope and explicitly adapts measured
transport_header_mean to Header_Length. Four ratios are shared with CSV training.
POST /api/v1/pcap/upload uses the Python reference for supported classic Ethernet
IPv4 PCAP files. Both paths use the real saved XGBoost classifier.
POST /api/v1/csv/upload accepts original CSV feature tables; labels are not inputs.
GET /api/v1/features/export?capture_session_id=... returns the model's 22 inputs.
Existing overview/flows/alerts/incidents/model analytics and WS /ws/live remain.

Persist artifact hash, session, input representation, 22 values and probabilities.
Approximate packet response fields include input_representation and a warning.
UTC normalization, duplicate rejection, bounded uploads and serialized ingestion
are required. Export carries an approximation header. Auto-block and manual device
actions remain disabled. Current operator APIs are a local prototype, not a secure
public service; authentication/deployment hardening remains separate work.

Current integration update: React PCAP upload is in scope. Upload classic PCAPs,
show session-specific Benign/DoS/DDoS windows and preserve model provenance.
HTTP APIs require operator bearer credentials; collectors have ingestion-only
credentials. Set SENTINEL_OPERATOR_TOKEN and SENTINEL_COLLECTOR_TOKEN externally.
SENTINEL_AUTH_DISABLED=1 is only for explicit isolated development/tests.
Downloads are built by scripts/build-collectors.sh and installed by
scripts/setup-collector.sh. Cross-compiled binaries support replay only; Linux
live capture needs a native CGO/libpcap build. Use HTTPS outside localhost.

Completion update: Linux live builds use scripts/build-live-service.sh; install
with scripts/install-monitoring-service.sh. Service tokens are hashed, expiring,
revocable and bound to collector_id. Monitoring service is live-only; PCAP analysis
and Analysis history remain separate. Alerts use persisted server records and
acknowledgement endpoints. Capture history stores metadata and original model
identity but never raw packets. See agents/remaining_components.md for validation
limits and README for deployment, credential rotation and uninstall instructions.

Simplified deployment: scripts/setup-server.sh builds/runs deploy/compose.yml,
including the live binary and same-origin HTTPS website. Device setup is served
from /api/v1/install.sh and uses one-use, 15-minute enrollment codes. Credentials
are generated on redemption and stored root-only by the installer. Keep probes
and synthetic browser traffic removed. PCAP upload has no fixed size/window cap;
use disk spooling, bounded batches, atomic persistence and paginated results.
The browser must send multipart PCAP, never parse it as CSV or silently zero data.

PCAP upload reads records in timestamp order before window aggregation. Captures
already in order use a streaming pass. Unordered captures use a temporary disk
index of record offsets, ordered by seconds, fractional timestamp and file offset,
preserving packet order for equal timestamps. Original timestamps and lengths
are retained. Large unordered files require extra temporary disk and processing.

PCAP extraction and inference stage batches in a private temporary file before
taking the shared ingestion lock and opening the final database transaction.
Malformed captures publish no results. Device lookups are cached within each
persistence batch. Credential database access runs in a worker thread so SQLite
writer waits do not block the event loop. Large uploads still need temporary disk
and time for sorting, inference and final atomic persistence.
