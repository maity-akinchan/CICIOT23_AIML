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

Server access requires separately generated operator and collector secrets:
`export SENTINEL_OPERATOR_TOKEN=$(openssl rand -hex 32)` and
`export SENTINEL_COLLECTOR_TOKEN=$(openssl rand -hex 32)`.
Keep these secrets outside Git. The UI validates the operator token against the server and keeps it
in tab session storage. Its existing workspace/profile forms are local profile
setup, not account authentication. Collectors read SENTINEL_COLLECTOR_TOKEN from
the environment. Use HTTPS via a reverse proxy for remote connections.

Build downloadable binaries with `scripts/build-collectors.sh` (Go required).
Authenticated downloads are listed at `/api/v1/downloads/collectors`.
Run `bash scripts/setup-collector.sh https://your-server` on Linux/macOS to
install a checksum-verified replay collector. The script prompts for an operator
download token; run the installed collector with the separate collector token.
Cross-platform builds support PCAP replay. Native Linux live builds require
CGO/libpcap. Build output is generated under dist and excluded from Git.
For isolated development/tests only, set SENTINEL_AUTH_DISABLED=1 explicitly.

The responsive React workspace has focused pages for Overview, PCAP analysis,
Live traffic, Flow explorer, Attack alerts, Monitoring service, System console and Workspace settings.
PCAP uploads show only that file's predictions. The feature inspector opens on
selection. Mobile/tablet navigation uses an expandable menu; wide tables scroll
within their panels. Collector binaries download through authenticated requests.
