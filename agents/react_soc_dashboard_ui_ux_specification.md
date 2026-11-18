Current revision (2026-11-18): the user authorizes retraining and feature changes
to reduce false positives. Earlier fixed-model restrictions below are superseded.
Use the supplied Kaggle CSVs as the training source. Report benign false-positive
rate and attack recall, and validate packet compatibility independently. Never
claim low live false-positive rates from a CSV validation result alone.

# Responsive detection workspace

The user authorizes a full UI revamp while retaining the dark indigo visual style.
The active pages are Overview, PCAP analysis, Live traffic, Flow explorer,
Attack alerts, Collector setup and Workspace settings. Keep each workflow focused.
PCAP results must be scoped to the uploaded session. Empty, loading, error and
zero-window outcomes must remain explicit. Keep model provenance in flow objects.

Desktop navigation uses a sidebar. Tablets/phones use an expandable menu with
an overlay; selecting a page closes it. Use at least 44px primary controls,
visible keyboard focus, readable contrast and local horizontal table scrolling.
Feature inspection opens only on selection. Do not force an inspector into every
page or mix setup commands with upload analysis. Honor reduced-motion preferences.

Use real backend responses. Download buttons use authenticated blob requests.
Never put credentials into download URLs or render fake service verification.
Maintain the supplied XGBoost and shared preprocessing. Packet representations
remain approximate and observe-only. Original contributor source/history remains.

Product naming: Monitoring service (never Go service), System console for server
status and developer diagnostics. Keep the landing page short and free of server
status, model details and probe controls. Remove browser simulations/probes.
The monitoring service page contains installation/live connection only: no capture
uploads, replay instructions or simulator commands. Only offer live-capable builds
there; current generated replay builds are not live-capable downloads.

Completion update: Linux live builds use scripts/build-live-service.sh; install
with scripts/install-monitoring-service.sh. Service tokens are hashed, expiring,
revocable and bound to collector_id. Monitoring service is live-only; PCAP analysis
and Analysis history remain separate. Alerts use persisted server records and
acknowledgement endpoints. Capture history stores metadata and original model
identity but never raw packets. See agents/remaining_components.md for validation
limits and README for deployment, credential rotation and uninstall instructions.

Simplified deployment: scripts/setup-server.sh builds/runs deploy/compose.yml,
including the live binary and same-origin HTTPS website. Device setup is served
from /api/v1/install.sh and uses one-use, 15-minute enrollment codes. Credentials
are generated on redemption and stored root-only by the installer. Keep probes
and synthetic browser traffic removed. PCAP upload has no fixed size/window cap;
use disk spooling, bounded batches, atomic persistence and paginated results.
The browser must send multipart PCAP, never parse it as CSV or silently zero data.
