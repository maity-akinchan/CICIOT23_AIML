# Project instructions

Current decision (2026-11-17): use the existing supplied XGBoost artifact without
retraining. Preserve contributor Go code. The user explicitly authorizes approximate
packet measurements despite unverified parity with Kaggle. Do not substitute models,
fabricate compatibility, or enable firewall actions. The implementation scope includes
Go, FastAPI and the responsive React workspace.

Read agents/master_architecture_integration_blueprint.md, the ML and component
specifications, and agents/agent_governance_anti_drift_protocol.md before editing.
The v3 capture-first and later CSV-only restrictions are superseded by this
explicitly authorized approximation prototype. Preserve the source model and
legacy notebook. Retain contributors' collector functionality and tests.

Use shared preprocessing; preserve exact feature casing/order. Do not rename an
approximate packet measurement as verified Kaggle extraction. Source model scores
and dataset-cleaning caveats remain historical facts. Default to observe-only.

Use ml/artifacts/ciciot_22f_xgb.joblib now. Retraining on the given Kaggle CSVs is
optional, not a prerequisite. Do not request or train from new datasets.

Run Python tests and actual Go tests when changing this boundary; prefer
cross-process verification against the supplied model. Document unsupported
formats and validation limits accurately. The UI is part of the active scope.

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
