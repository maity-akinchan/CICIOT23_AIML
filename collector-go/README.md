# Collector + FastAPI

From the repository root:

```sh
python -m pip install -e . -r backend-fastapi/requirements.txt
cd backend-fastapi
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In another terminal:

```sh
cd collector-go
CGO_ENABLED=0 go build -o collector .
./collector --mode pcap --pcap-file /path/to/file.pcap --replay-speed 0 --api-url http://127.0.0.1:8000/api/v1/ingest/windows
```

On Linux, the CGO-disabled binary supports offline capture only. For live Linux capture,
install libpcap development headers (for example libpcap-dev on Debian), then
build with CGO_ENABLED=1 and run with capture privileges:

```sh
CGO_ENABLED=1 go build -o collector .
sudo ./collector --mode live --iface eth0 --api-url http://127.0.0.1:8000/api/v1/ingest/windows
```

For live capture on Windows, install Npcap and run PowerShell from `collector-go`.
Use the listed adapter ID for the Wi-Fi, Ethernet, or loopback interface that carries
the traffic you want to monitor. Run PowerShell as Administrator if required by your
Npcap installation.

    go build -o collector.exe .
    .\collector.exe --list-interfaces
    .\collector.exe --mode live --iface '<adapter ID from the list>' --collector-id windows-pc --api-url http://127.0.0.1:8000/api/v1/ingest/windows

Set `SENTINEL_COLLECTOR_TOKEN` in the collector shell if the server requires it.
In the dashboard, a protected server asks for its separate operator access token.
Under **Connected devices**, check emitted windows and accepted batches alongside
captured packet counts. A directed flow needs at least five packets within two
seconds before it is classified. **Flow explorer** can read persisted windows
over HTTP while the live WebSocket is disconnected.

No device/firewall commands are executed. Live mode captures actual traffic;
model accuracy on that traffic is unverified. Windows ship as packet approximations
with measured transport-header metadata. Raw collector statistics are retained;
FastAPI constructs the 22-feature model matrix and uses the supplied XGBoost.

Read /health before starting; invalid contract hashes and missing models stop
shipping. Query /api/v1/flows for capture_session_id, then download
/api/v1/features/export?capture_session_id=ID. This is the exact 22-value input
matrix serialized as CSV, not a claim that packet semantics reproduce Kaggle.

Tests: go test ./... (libpcap for CGO builds) or CGO_ENABLED=0 go test ./....
From the repository root run:
SENTINEL_GO=/absolute/path/to/go python -m pytest -q
The cross-process test builds a real collector, starts a temporary backend, ships
synthetic PCAP packets into the actual supplied model, and verifies stored/exported
inputs against the Python reference path. It does not measure model accuracy.
