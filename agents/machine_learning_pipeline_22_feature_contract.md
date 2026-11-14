# Model training, evaluation and feature contracts — v3

**Status:** authoritative target for the AIML experiment. The existing CSV
artifact and the candidate capture extractor are separate contracts.

## 1. Existing experiment: preserve and qualify

The uploaded notebook trains on pre-extracted CSVs from `himadri07/ciciot2023`,
keeps Benign/DoS/DDoS labels, and exports 22 ordered inputs. Its own metadata says
`windowing_policy_confirmed=false` and `capture_group_split_verified=false`.
The artifact is a valid experiment result; these flags limit deployment claims.

Evidence from `ml/artifacts/ciciot_22f_xgb.joblib`:

| Feature | Saved benign median | Conflict with the old proposed packet definition |
| --- | ---: | --- |
| `Header_Length` | 509331.0625 | Not compatible with a mean IP+transport header of ordinary packets |
| `hdr_pkt_ratio` | 1008.9702 | Cannot be a header-bytes / total-wire-bytes ratio bounded by 1 |
| `rst_count` | 641.2000 | Exceeds the maximum raw RST count in a 100-packet window |

These observations establish incompatibility with the old proposed semantics;
they do not establish what the original CSV extractor actually calculated.
Do not fix this by dividing a feature by an arbitrary constant or clipping it to
the proposed packet range. Recover the source extractor or train a new contract.

## 2. Legacy CSV contract: `ciciot23-csv22-v1`

The notebook names its feature engineering version `ciciot22f-v1`. The project
contract ID adds source provenance; it is an external manifest association for
the existing artifact, not a claim that the artifact already includes that ID.

Keep this exact order and casing:

```text
flow_duration, Rate, Header_Length, Duration,
fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number,
ack_flag_number, ack_count, syn_count, fin_count, rst_count,
TCP, UDP, ICMP, AVG, Std,
bytes_per_sec, syn_ack_ratio, hdr_pkt_ratio, pkt_cv
```

Preserve the notebook's four formulas:

```text
bytes_per_sec = Rate * AVG
syn_ack_ratio = (syn_count + 1.0) / (ack_count + 1.0)
hdr_pkt_ratio = Header_Length / (AVG + 1e-5)
pkt_cv = Std / (AVG + 1e-5)
```

Names and formulas alone do not define units of the legacy base measurements.
Do not enforce candidate PCAP bounds on CSV rows or label all CSV features with
unverified physical units. `Duration` is described as TTL in the notebook; it is
not elapsed flow duration.

Extract the preprocessing logic into one tested library for future training and
serving. The current notebook loads base values as float32, drops nonfinite base
rows, clips negative `flow_duration`/`Rate` to zero, computes ratios using float64
intermediates and converts the final matrix to float32. Reproduce these steps
and class decoding for legacy parity tests, including rounding boundary cases.
Do not invent zero imputation: the supplied artifact does not export fitted
`impute_medians`. Invalid inference inputs must be rejected unless an artifact
explicitly provides a trained missing-value policy. Imported precomputed ratios
must be checked or recomputed; labels and endpoint identifiers are not features.

## 3. Candidate capture contract: `sentinel-pcap22-v2`

This is a new experiment requiring compatible training data and an artifact.
The initial candidate below is intentionally explicit; any change creates a new
contract version, including a change to window size, key, byte unit or timeout.

- Group by capture session plus directed source IP, destination IP, protocol,
  source port and destination port. Specify ICMP grouping separately where ports
  do not exist. Evaluate whether this grouping supports the chosen task.
- Close a window after 100 valid packets or 2 seconds from its first packet.
  Close remaining windows at EOF. Windows with fewer than 5 packets are labeled
  `INSUFFICIENT_DATA` and counted in coverage, without a classifier prediction.
  Use exactly this policy for extraction, training, testing, replay and live input.
  These are initial experimental choices, not verified CICIoT2023 defaults.
- Record packet order, timestamps, drop/truncation counts and the exact supported
  link/IP protocols. Do not let ground-truth labels determine the window policy.
- Do not cross capture/session or train/test boundaries. Store the actual key and
  provenance with each feature vector. Never merge unrelated endpoint pairs for
  convenient attribution.

Candidate equations for N valid packets in one group:

| Features | Definition |
| --- | --- |
| `flow_duration`, `Rate` | `max(last_timestamp-first_timestamp, 1e-6)` seconds; `N / flow_duration` |
| `Header_Length` | Mean measured network plus transport header bytes; supported IPv6 extensions handled explicitly |
| `Duration` | Mean IPv4 TTL / IPv6 hop limit |
| `*_flag_number` | Count of that TCP flag divided by N |
| `ack_count`, `syn_count`, `fin_count`, `rst_count` | Raw integer counts, represented numerically, in `[0,N]` |
| `TCP`, `UDP`, `ICMP` | Shares of the supported packet protocols in the group |
| `AVG`, `Std` | Mean and population standard deviation of original wire lengths, not truncated captured bytes |
| Four ratios | Formulas in section 2, using these new base semantics |

The old model must not receive these vectors as if they were legacy CSV rows.
A Python reference implementation is acceptable. A Go implementation must pass
golden PCAP parity tests before replacing it. Retain any small/partial-window
coverage exclusions in the final metrics; do not hide difficult samples.

## 4. Evaluation design and notebook corrections

The notebook already has useful practices: explicit class mapping, fixed feature
order, validation-based model selection, train-only benign baselines, and SVM
calibration around the whole preprocessing pipeline. Preserve these practices.

Correct the following in a new training revision, keeping the supplied notebook
unchanged as the record of the existing experiment:

1. Split by capture/session/device/time before window extraction. Keep capture
   groups out of both training and evaluation folds. Exact row deduplication does
   not eliminate correlated-neighbor or same-capture leakage.
2. The current notebook's cell index 5 combines train, validation and **test
   labels** to remove conflicting feature hashes from all splits. That makes
   training curation depend on test outcomes and removes ambiguous test cases.
   Fit conflict-handling rules from training only; define any holdout exclusions
   in advance and report their effect separately. Do not assert the size of any
   score inflation without rerunning the experiment.
3. Report split counts before/after cleaning, per-class exclusions, group counts,
   duplicate overlap and original-frequency versus deduplicated evaluation.
   A changed class prevalence changes the meaning of accuracy and precision.
4. Fit scalers, imputers, resampling and feature selection using training data
   only. Choose hyperparameters, score thresholds and calibration using validation
   data or grouped inner folds. Freeze the final test set before iteration.
5. Include a majority-class baseline and a simple trained comparator on the same
   split. Compare models using macro-F1 and class precision/recall, not accuracy
   alone; state SVM subsampling if its training budget differs.
6. Save representative labeled held-out rows and their expected probability
   vectors for serving parity. The current seven-row repository fixture is not
   the notebook's exported 500-row smoke sample and has no verified provenance.
   The small smoke sample is still not a substitute for full evaluation.
7. Run independent lab sessions: realistic benign bursts, idle/low-rate traffic,
   controlled single-source and multi-source attacks, and mixed traffic. Label
   them from the scenario schedule/capture records, never from model predictions.
   Hold out entire sessions, ideally additional devices, from tuning.

## 5. Claims, uncertainty and metrics

The scope is three-class supervised classification of the selected traffic
families. It does not establish detection of every attack family or novel threats.
`is_anomaly` in the prototype means non-Benign prediction, not an independently
trained anomaly detector.

Make attack-versus-benign detection the primary operational question; retain
DoS/DDoS subtype classification as a secondary result. The sum of DoS and DDoS
probabilities can form an attack score, but calibrate its threshold on validation
data. Do not silently change this artifact into a binary model. A separately
trained binary model requires its own labels, metrics and artifact identity.

A DDoS label is a learned class prediction, not proof of multiple attackers.
Packet-size variance does not prove a botnet. Report observed distinct sources
as separate telemetry, with NAT/spoofing and observation-point limitations.

Report at least:

- Macro-F1, confusion matrix with class order, class precision/recall/support and
  attack-versus-benign confusion metrics on the same identified evaluation set.
- False-positive rate on benign windows and false alert episodes per benign hour.
- Detection delay from attack onset, missed episodes, p50/p95 inference latency,
  total windowing-plus-pipeline latency, throughput and packet drops.
- Performance by held-out session/protocol and coverage of rejected inputs.
  Confidence intervals should resample independent captures, not assume adjacent
  windows are independent observations.
- A calibration/reliability check before interpreting a score as a probability
  of correctness. Select targets and thresholds before final testing.

IQR deviation from benign baselines is a descriptive anomaly indicator, not a
local explanation of the tree's decision. Label it **Deviation from training
baseline**. TreeSHAP on the exact model/input can be an optional explanation of
model contributions; it is not a causal explanation of an attack.

## 6. Artifact and reproducibility manifest

Record artifact SHA-256, model ID/version, feature names/order, base extractor
contract/hash, preprocessing version, class/probability order, label encoder,
allowed input modes, dataset version/hashes, capture split manifests, training
seed/configuration, dependency lock, evaluation sample IDs and metric provenance.
Preserve `training_scope` caveats in the API/UI. Metadata lacking evidence stays
unknown rather than being filled in with reassuring defaults.

Validate feature count/names, estimator classes and probability dimensions at
load time. Map numeric class IDs through the saved encoder and verify its order
against probability columns. Read the uploaded `label_encoder`, `benign_baseline`,
`feature_importance` and nested `metrics.test` format explicitly.

Load only trusted local artifacts; joblib is executable serialization. Pin a
working serving environment, and prefer XGBoost's native JSON/UBJ plus a JSON
manifest for future releases. The notebook saves a native model, but that file
was not supplied here. Never overwrite the historical bundle during conversion.
