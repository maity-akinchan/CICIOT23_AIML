# Completion status — 2026-11-17

Implemented: native Linux live-service build, authenticated live downloads,
Linux/systemd installer with checksum and credential-binding verification,
protected credential environment, automatic startup/restart, per-service hashed
expiring/revocable credentials and rotation workflow, persisted alert polling and
acknowledgements, capture metadata/history with pagination and reopening results.
The contributor WebSocket buffer remains; its missing public broadcast interface
and a missing datetime import in ingestion were fixed after integration testing.

Validation still needing deployment/user data:
- Actual labeled benign/DoS/DDoS PCAP evaluation. Use scripts/validate-captures.py;
  report agreement honestly without changing model weights or adjusting outputs.
- Install/restart the systemd unit on the intended monitored Linux machine.
  This workspace is not running a systemd-managed deployment. Installer syntax
  and native binary build are checked; do not claim host installation was tested.
- CI builds ARM64 on a native ARM runner. Only AMD64 is built in this workspace.
  Publish CI artifacts to the backend's dist/collectors directory. Do not claim
  ARM64 or other OS live deployment was exercised locally.

Scope: Linux live monitoring. Windows/macOS live capture backends and background
service installers are not implemented and are not offered on the service page.
Shared operator bootstrap credentials remain; this is not a multi-user account
system. Service credentials are independently scoped, bound and revocable.
Device/firewall actions intentionally remain disabled in observe-only mode.

Simplified setup update: server setup is now scripts/setup-server.sh with Docker
Compose, same-origin HTTPS, model health checks and automatic native live binary
building. Device enrollment uses a one-use 15-minute setup code; its installer
handles dependencies, credential creation, interface choice and systemd startup.
A real 36 MB PCAP, malformed rollback, 513-window batch boundary and enrollment
reuse are tested. The full packaged build was attempted but hit the workspace's
Docker-storage limit; HTTPS issuance and target-device systemd installation are
not claimed as verified. Docker/Compose and a reachable DNS hostname are server
prerequisites. The existing manual workflows remain for local development.
