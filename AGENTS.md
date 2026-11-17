# Project instructions

Current decision (2026-11-17): use the existing supplied XGBoost artifact without
retraining. Preserve contributor Go code. The user explicitly authorizes approximate
packet measurements despite unverified parity with Kaggle. Do not substitute models,
fabricate compatibility, or enable firewall actions. The implementation scope is
Go + FastAPI; UI implementation is deferred.

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
formats and validation limits accurately. The UI is deferred in the active scope.
