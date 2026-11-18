# Kaggle CSV XGBoost evaluation

Trained on himadri07/ciciot2023 version 1 using the repository CSV pipeline.
Full split files were downloaded from Kaggle on 2026-11-18. Original split
assignments were retained. Only training same-label duplicates were removed.

Validation selected the attack threshold under a 0.1% empirical benign
false-positive budget. Final test results were evaluated after freezing it.

- Benign false positives: 23 / 27,709 (0.0830%).
- Binary attack recall: 99.8798%.
- Three-class accuracy: 90.9744%.
- DoS class recall: 62.2307%.
- Train/test exact feature overlap: 293,660 distinct feature hashes.

These results apply to the supplied CSV splits. Recording independence is unknown.
Live and uploaded packet compatibility is unvalidated. FastAPI accepts CSV inputs
for this artifact and rejects the approximate packet contract. It is a separate
evaluation artifact and has not been selected as the default application model.

The report contains training counts, source hashes, policy and all test metrics.
The bundle passed loader golden checks and a 100-row real CSV FastAPI parity check.
