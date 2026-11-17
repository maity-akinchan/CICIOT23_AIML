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
