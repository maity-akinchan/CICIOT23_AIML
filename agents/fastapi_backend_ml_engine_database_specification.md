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
