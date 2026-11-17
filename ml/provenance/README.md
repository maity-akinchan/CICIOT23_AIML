# Extractor recovery findings

The authors' [UNB dataset page](https://www.unb.ca/cic/datasets/iotdataset-2023.html)
identifies supplementary `pcap2csv` code and DPKT. A pinned mirror of those materials
was recovered from [bencorn/CIC-IoT-2023](https://huggingface.co/datasets/bencorn/CIC-IoT-2023/tree/dac6afc7c1f6242202abf6059932e4c4d166e662/Supplementary%2BMaterials/pcap2csv).
`recovered_sources.json` records immutable URLs and SHA-256 hashes. This is a
mirror, not proof of the exact source revision used for the Kaggle training rows.

The recovered `Feature_extraction.py` emits `Time_To_Live`, does not emit
`flow_duration`, hardcodes a ten-row summary, uses pandas sample standard
deviation and sums packet flags. It emits 39 columns after removing timestamps.
The supplied model instead requires `Duration`, `flow_duration`, and the released
CSV semantics. Therefore this recovered source cannot reproduce that model's
complete input vector. No field renaming or formula substitution is used to hide
this discrepancy.

The [original paper, section 4](https://www.mdpi.com/1424-8220/23/13/5941)
explains class-dependent aggregation (10 for benign and other small classes,
100 for DoS/DDoS and other high-volume classes). Unknown live labels cannot
select that aggregation policy. The Kaggle public metadata identifies dataset
7212034/version 1 (source version 11503210), with train/validation/test CSVs;
it does not provide the matching raw-capture row mapping or generating revision.

`reproduce_original.py` downloads the pinned source, checks every checksum and
runs the unmodified recovered extractor against a supplied PCAP. It is an
isolated historical reproduction tool, never an inference adapter. Install its
requirements separately. Its output schema must not be passed to the old model.

The retraining path uses `sentinel_ml.capture` and `sentinel_ml.contract` with
one explicit policy and independent capture-group splits. It establishes a new
measurement contract, without claiming the old CSV artifact is compatible.

## Reproduction executed

The unmodified pinned source was executed locally on a generated 100-packet
TCP SYN PCAP. It produced ten rows and 39 columns; the first two rows had
`Header_Length=20`, `Time_To_Live=64`, `syn_count=10`, and `Std=0`.
This verifies runnable recovered code on that fixture, not parity with the
released Kaggle rows or general live accuracy. The fixture can be regenerated
with the `capture` helper in `tests/test_pipeline.py`; the reproduction CLI
requires the separate dependencies in this directory.
