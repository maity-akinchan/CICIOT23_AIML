# Current project audit — 2026-11-17

The demonstration uses the supplied CSV-trained XGBoost, without retraining.
Success means detecting DoS or DDoS in an uploaded attack PCAP and through Go
capture/replay feeding FastAPI. Integration tests are not attack-detection evidence;
a labeled representative attack capture is still needed to assess that outcome.

## Implemented and retained

- Contributor Go collector, HTTP shipping, readiness/contract checks and retry IDs.
- FastAPI packet upload, collector ingestion, CSV inference and 22-feature export.
- Shared CSV preprocessing, exact feature order and probability/class mapping.
- Original XGBoost checksum identity and original notebook as training evidence.
- Optional corrected notebook using only himadri07/ciciot2023 CSV splits.
- Extractor recovery evidence under ml/provenance, retained for traceability.

## Removed superseded approach

The PCAP-manifest training path, capture-trained model contract and synthetic
PCAP-training test experiment are removed. Packet fixtures now test inference
against the supplied model. No PCAP downloads or capture-based retraining are
required. Historical plans remain in Git history rather than active instructions.

## Remaining limitations

Packet features approximate the Kaggle measurements. Transport-header mean and
raw per-window RST count do not reproduce the large aggregated original CSV
values. Neither rescaling nor renaming columns establishes semantic equivalence.
Historical model scores do not measure accuracy on this packet approximation.
The recovered supplementary extractor has a different schema; see ml/provenance.

The original notebook used holdout-dependent cleaning; historical scores retain
that limitation. Optional CSV retraining does not use test labels to curate train,
keeps supplied splits and reports overlap; capture independence is unknown.

The Go/HTTP test uses the real model with a synthetic Ethernet/IPv4/TCP fixture.
Other protocol combinations and real-interface traffic still need validation.
FastAPI uploads support a restricted classic-PCAP subset and a 32 MiB limit.
Go can replay captures incrementally; neither path requires storing training PCAPs.

Device/firewall actions remain disabled. Authentication and public deployment
hardening are outstanding. The React UI and full Compose demonstration are deferred.
