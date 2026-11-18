Current revision (2026-11-18): the user authorizes retraining and feature changes
to reduce false positives. Earlier fixed-model restrictions below are superseded.
Use the supplied Kaggle CSVs as the training source. Report benign false-positive
rate and attack recall, and validate packet compatibility independently. Never
claim low live false-positive rates from a CSV validation result alone.

# Contributor Go collector integration

Current decision (2026-11-17): use the existing supplied XGBoost artifact without
retraining. Preserve contributor Go code. The user explicitly authorizes approximate
packet measurements despite unverified parity with Kaggle. Do not substitute models,
fabricate compatibility, or enable firewall actions. The implementation scope is
Go + FastAPI; UI implementation is deferred.

Keep the contributor implementation and tests. New fields extend its wire envelope:
feature_contract_id, contract_hash, capture_session_id, collector_id, capture_mode,
source_ref, windows. Contract constants must agree with sentinel_ml/approximation.py.

The contributor's original 18 measurements remain intact on the wire. Metadata
additionally includes transport_header_mean, measured in decode/aggregation from
actual transport headers. FastAPI uses it in the explicit approximate-model adapter.
Do not subtract assumed IP header lengths after aggregation.

Stable window IDs survive retries. Backend hashes session/sensor/window identity
and deduplicates storage. Health advertises model readiness, allowed contracts,
contract hash and modes. Mismatch stops shipping. Keep bounded queues, packet-drop
statistics and source/session provenance. PCAP replay and live capture remain distinct.

Offline builds need no CGO. Live Linux builds require CGO and libpcap headers/runtime.
The contributor supports additional protocols/link types beyond the Python PCAP
upload subset; cross-language parity is currently tested for Ethernet/IPv4/TCP.
Do not claim all supported Go formats have been independently parity-verified.
See ../collector-go/README.md for build, tests and runtime commands.

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
