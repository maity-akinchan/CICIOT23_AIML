# Remaining implementation and validation

Checked against the current local implementation on 2026-11-17.

1. Live monitoring distributions: generated cross-platform binaries use CGO=0
   and cannot capture a network interface. Linux capture source exists and its
   tests build with libpcap. Package live-capable releases with runtime dependency
   checks before offering them on Monitoring service. Current replay downloads
   remain available through the operator API, not as live service downloads.
2. Background service installation: setup script downloads/checksums/installs an
   executable only. It does not register systemd, launchd or a Windows service,
   manage restarts, securely persist service credentials or configure interfaces.
3. Credential management: current operator/collector authentication uses separate
   environment-provided shared secrets. No account provisioning, per-device token
   issuance/revocation, password recovery or audit trail is implemented.
4. Alert persistence: the UI derives alerts from received flow predictions and
   acknowledges them locally. Wire the persisted backend alert list and acknowledge
   endpoint to make acknowledgements survive refresh and agree across clients.
5. Observation history: current telemetry view keeps a bounded recent feed and
   initial snapshot. Add paginated server history/session listing for older uploads
   and observations after reload. Individual upload results are scoped correctly
   while that analysis page is open; a permanent upload-history screen is absent.
6. Attack evidence: actual labeled benign/DoS/DDoS PCAP validation has not been
   performed. Integration fixtures exercise the model pipeline but do not establish
   real attack accuracy under the approximate packet feature representation.

Device/firewall actions intentionally remain disabled in observe-only mode.
Those controls are not part of the active detection demonstration.
