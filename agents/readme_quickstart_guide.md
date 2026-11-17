# Quickstart

Current decision (2026-11-17): use the existing supplied XGBoost artifact without
retraining. Preserve contributor Go code. The user explicitly authorizes approximate
packet measurements despite unverified parity with Kaggle. Do not substitute models,
fabricate compatibility, or enable firewall actions. The implementation scope is
Go + FastAPI; UI implementation is deferred.

See root README.md and collector-go/README.md for exact local commands.
Install the shared Python package with pip install -e . -r backend-fastapi/requirements.txt.
Start one backend worker at 127.0.0.1:8000; default model is the supplied XGBoost.
Build collector-go, run --mode pcap --pcap-file FILE --replay-speed 0 and point
--api-url to /api/v1/ingest/windows. Inspect /health, /api/v1/flows and /docs.
Export the stored session through /api/v1/features/export.

The backend tests use temporary databases. Set SENTINEL_GO to run the actual
collector-to-HTTP-to-XGBoost test. Live capture requires Linux/libpcap and suitable
capture privileges; tests do not generate attacks or change host firewall rules.
Full Compose/frontend behavior remains outside the verified local backend/Go flow.
