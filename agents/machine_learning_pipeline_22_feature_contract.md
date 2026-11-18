Current revision (2026-11-18): the user authorizes retraining and feature changes
to reduce false positives. Earlier fixed-model restrictions below are superseded.
Use the supplied Kaggle CSVs as the training source. Report benign false-positive
rate and attack recall, and validate packet compatibility independently. Never
claim low live false-positive rates from a CSV validation result alone.

# Feature and model contracts

Current decision (2026-11-17): use the existing supplied XGBoost artifact without
retraining. Preserve contributor Go code. The user explicitly authorizes approximate
packet measurements despite unverified parity with Kaggle. Do not substitute models,
fabricate compatibility, or enable firewall actions. The implementation scope is
Go + FastAPI; UI implementation is deferred.

Exact feature names/order: flow_duration, Rate, Header_Length, Duration,
fin_flag_number, syn_flag_number, rst_flag_number, psh_flag_number, ack_flag_number,
ack_count, syn_count, fin_count, rst_count, TCP, UDP, ICMP, AVG, Std,
bytes_per_sec, syn_ack_ratio, hdr_pkt_ratio, pkt_cv.

The executable packet approximation specification/hash is sentinel_ml/approximation.py.
Header_Length = mean measured transport header bytes (TCP options included);
rst_count = RST packet count in the current window. These do not reconstruct the
large cumulative/aggregated values seen in original CSV baselines. This limitation
is explicitly accepted for the prototype. No invented rescaling is performed.
Other inputs retain collector measurements: directed 5-tuple windows, 100 packets
or 2 seconds, minimum 5; duration floor 1e-6; Rate=N/duration; TTL mean; flag
counts/shares; protocol shares; original wire-size mean and population std.

Shared CSV engineering: Rate*AVG; (syn_count+1)/(ack_count+1);
Header_Length/(AVG+1e-5); Std/(AVG+1e-5). Base values round to float32 before
float64 ratio arithmetic; final matrix is ordered float32. sentinel_ml/csv_contract.py
validates numerical input; it does not impose guessed packet bounds on dataset rows.

The historical artifact SHA-256 is
e1dde2fe2a759684208021934ad3edff2be2dfa29977fac9a246ba9665da233e.
Its in-memory adapter identity is ciciot23-legacy22-v1. Its file is not rewritten.
Golden reference rows were not supplied for this artifact; the loader reports
that fact. Tests compare actual saved-model probability outputs to HTTP results.

The corrected CSV notebook is optional. Original notebook and trained model are
retained. Do not use test labels for training curation in future experiments.
