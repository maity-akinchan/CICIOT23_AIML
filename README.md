# CICIoT23 Sentinel

An AIML project demonstrating how a trained CICIoT2023 classifier can be served
through FastAPI and used in a traffic-analysis application.

**Current status:** the uploaded XGBoost model and training notebook are present;
the backend has partial functionality and known defects. The Go collector and
React app entry points are empty. The full-stack live demonstration is not yet
implemented or validated.

The key outstanding scientific issue is feature compatibility: the supplied
model was trained on pre-extracted CSV rows whose measurements differ from the
proposed 100-packet extractor. Identical feature names do not establish parity.
Use the existing artifact for compatible dataset features; verify the original
extractor or retrain with a shared capture extractor before claiming live accuracy.

## Review and plan

- [Evidence-based project audit and prioritized fixes](agents/project_audit.md)
- [Architecture and milestones](agents/master_architecture_integration_blueprint.md)
- [Training, evaluation and feature contracts](agents/machine_learning_pipeline_22_feature_contract.md)
- [Current quickstart](agents/readme_quickstart_guide.md)
- [Coding-agent instructions](AGENTS.md)

The v3 plan prioritizes one real model, correct inference, three useful dashboard
views, and independent capture evaluation. Fleet management, firewall/DNS changes
and automatic blocking are optional later extensions. The specifications describe
target behavior; the prototype does not yet enforce all of their gates.

## Supplied experiment

Notebook: `ml/notebooks/ciciot23_training.ipynb`.
Model: `ml/artifacts/ciciot_22f_xgb.joblib`.

The bundle records test accuracy **89.37%** and macro-F1 **90.16%** on its cleaned
CSV test split. These are saved training-run results, not newly measured live
performance. The notebook explicitly leaves packet-window provenance and capture-
group independence unverified. Other trained model bundles were not supplied.
The repository's `test_sample_500.csv` has seven fixture rows, not a verified
500-row held-out test set.

See the quickstart for local backend inspection and the steps required for an
honest dataset-replay, PCAP and live demonstration. Do not treat the current
Compose file as a working one-command full-stack deployment.
