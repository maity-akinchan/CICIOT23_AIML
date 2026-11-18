Current revision (2026-11-18): the user authorizes retraining and feature changes
to reduce false positives. Earlier fixed-model restrictions below are superseded.
Use the supplied Kaggle CSVs as the training source. Report benign false-positive
rate and attack recall, and validate packet compatibility independently. Never
claim low live false-positive rates from a CSV validation result alone.

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
FastAPI uploads support a restricted classic-PCAP subset with no fixed application file-size limit.
Go can replay captures incrementally; neither path requires storing training PCAPs.

Device/firewall actions remain disabled. Authentication and public deployment
hardening are outstanding. The React UI and full Compose demonstration are deferred.

## False-positive audit, 2026-11-18

Critical unresolved finding: original CSV measurement semantics differ from the
packet approximation. Header_Length, reset counts, flag aggregation, flow duration
and window grouping require evidence of parity. Dropping two columns alone cannot
establish compatibility. Existing model probabilities are overconfident on observed
normal traffic. Neither confidence nor CSV accuracy demonstrates live accuracy.

Training selection previously maximized macro-F1. It now selects attack thresholds
using validation benign rows, with an explicit empirical 0.1% false-positive budget,
then chooses maximum attack recall among usable candidates. The budget is a chosen
engineering starting point, not a measured live guarantee. Test labels never select
the threshold. Report final-test false positives and recall together. Validation
reuse introduces selection optimism; final independent testing remains essential.
Row overlap and unknown recording independence limit the strength of that result.

The original supplied model lacks this policy. Retraining is necessary to produce
policy-bearing artifacts. The workspace contains neither the three full Kaggle
splits nor labeled live captures. No new accuracy result has been established.

Runtime gaps remain. Sparse five-tuple flows below five packets produce no model
window, including rotating-source-port attack traffic. Capacity evictions and queue
loss can reduce coverage under load. Destination-level traffic aggregation needs a
separate validated measurement contract before use as model inputs. DDoS source
distribution cannot reliably be inferred from a single directed flow.

Operational gaps remain. Large uploads sort and stage on temporary disk; final
atomic persistence holds the SQLite writer. Progress, cancellation, background jobs
and concurrent live ingestion under sustained load need further work. New CSV model
bundles accept CSV inference only, pending packet adapter validation. The runtime
default is XGBoost even when a different candidate wins selection; deployment must
explicitly select the evaluated candidate.

Acceptance requires independently labeled benign and attack evaluation, false
positives per benign window and per hour, attack recall, missed-packet coverage,
and time to detection. High accuracy alone is insufficient on imbalanced data.
