# CICIoT23 Sentinel — Go + FastAPI prototype

The supplied trained XGBoost is used directly; retraining is optional. The active
path is PCAP/live capture -> contributor Go collector -> FastAPI approximate adapter
-> 22-feature CSV/DataFrame -> XGBoost -> stored predictions/WebSocket updates.

Packet measurements are explicitly approximate representations of the original
Kaggle training inputs. Outputs identify that limitation. The original artifact,
encoder and historical metrics are preserved; no synthetic model substitutes or
arbitrary scaling are used. Device/firewall actions are disabled.

See [build/run instructions](collector-go/README.md), [current architecture](agents/master_architecture_integration_blueprint.md),
and [model/measurement definitions](agents/machine_learning_pipeline_22_feature_contract.md).
Backend docs: http://127.0.0.1:8000/docs. Default model path:
ml/artifacts/ciciot_22f_xgb.joblib. MODEL_DIR overrides its directory;
DATABASE_URL overrides SQLite storage. Use one backend worker.

POST /api/v1/pcap/upload accepts classic Ethernet/IPv4 TCP/UDP/ICMP PCAPs.
The Go collector supports more formats; parity is tested on the supported reference
fixture, not every protocol. POST /api/v1/csv/upload accepts original feature CSVs.
GET /api/v1/features/export?capture_session_id=ID exports all 22 values fed to the
model, in order. DataFrame prediction avoids unnecessary disk round trips.

Run python -m pytest -q; set SENTINEL_GO to a real Go executable to include the
cross-process test. Run go test ./... in collector-go as well. No full React UI
or end-to-end Compose demonstration is claimed yet. Operator APIs should run in
an isolated local environment pending authentication hardening.

The original notebook is ciciot23_training_legacy.ipynb. The main notebook remains
an optional CSV-only retraining workflow using himadri07/ciciot2023. Its data is
not required to start the supplied model. See ml/provenance for recovered
supplementary extractor evidence and unresolved original CSV measurement parity.

PCAPs are inference/test inputs only. The PCAP-first training pipeline and model
contract have been removed; optional training uses the given Kaggle CSVs only.
Raw captures are ignored by Git and are not included in the repository.
