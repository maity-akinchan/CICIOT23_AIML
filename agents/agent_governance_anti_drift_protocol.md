# Engineering and evidence rules

Current decision (2026-11-17): use the existing supplied XGBoost artifact without
retraining. Preserve contributor Go code. The user explicitly authorizes approximate
packet measurements despite unverified parity with Kaggle. Do not substitute models,
fabricate compatibility, or enable firewall actions. The implementation scope is
Go + FastAPI; UI implementation is deferred.

Preserve existing work and Git history. Incremental integration fixes are authorized.
The historical XGBoost adapter is checksum identified; other artifacts must pass
versioned contract and golden-reference checks. Never train fallback models at startup.

Packet predictions must be tagged packet_approximation and expose the compatibility
warning. Probabilities are model outputs, not validated live-accuracy evidence.
No arbitrary multipliers, quantile matching, or edits to historical benchmark scores.
Existing training-cleaning caveats remain documented in the legacy notebook/audit.

Run root pytest with SENTINEL_GO set to a real Go executable for cross-process tests.
Run collector-go go test ./... with CGO_ENABLED=0 and with CGO_ENABLED=1/libpcap.
Synthetic fixtures verify integration only. Actual model weights are used in the
Go/HTTP integration test. Observe-only actions remain disabled.
