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

### Live monitoring deployment

Linux AMD64/ARM64 builds are supported. Install `libpcap-dev` on the build host,
then run `scripts/build-live-service.sh` using Go. It generates
`dist/collectors/sentinel-service-linux-ARCH` and `LIVE-SHA256SUMS`, served through
the authenticated download endpoints. Native CI builds are configured in
`.github/workflows/service-build.yml`; copy the resulting artifacts into the
server's `dist/collectors` directory (combine checksum lines if publishing both
architectures). Generated binaries are not committed to Git. Target machines
need a compatible Linux/libc version and libpcap runtime; build for the target
Linux distribution when needed. Live downloads are separate from replay builds.

In **Monitoring service**, issue a token for a unique service ID. Tokens are
shown once, SHA-256 hashed at rest, expire after 30 days by default, and can be
revoked independently. Rotation: issue replacement, update the device environment,
restart its service, then revoke the former token. Shared collector environment
credentials remain for compatibility; use device-bound credentials for installed
services. Operator credentials cannot be substituted for a device-bound installer
verification.

On the monitored Linux/systemd host, from the checkout:

```bash
sudo bash scripts/install-monitoring-service.sh https://server.example eth0 office-sensor
```

The installer prompts for the operator download token and device-bound service
token, verifies SHA-256, checks the interface/runtime, verifies credential binding,
installs `/usr/local/bin/sentinel-service`, writes a root-only environment file,
and enables `sentinel-monitor.service`. Capture permissions are limited to the
service's network capabilities. Use `systemctl status sentinel-monitor` and
`journalctl -u sentinel-monitor` for diagnosis. To remove it, disable/stop the unit,
remove its unit file, executable and `/etc/sentinel`, then daemon-reload. Never
install this unit on the backend host unless that is the intended monitored host.
Linux installation is implemented; macOS/Windows live services are not supported.

Analysis history and alert acknowledgements now persist in SQLite. Capture history
stores filename, hash, size, model identity and class counts, not raw capture bytes.
Existing captures uploaded before this schema update have no metadata history row;
their retained flows remain accessible through the flow endpoint.

Validate real captures without retraining:

```bash
python scripts/validate-captures.py labeled-captures.json --server https://server.example
```

Set SENTINEL_OPERATOR_TOKEN in the environment. The manifest contains objects
with `path` and `expected` (`Benign`, `DoS`, or `DDoS`). The report gives class counts
and expected-class window fraction; mixed captures need window-level ground truth.
No real capture validation result is claimed until supplied files have been run.
