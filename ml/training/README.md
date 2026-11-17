# Retraining and backend verification

1. Install the repository package and backend dependencies in one environment:
   `python -m pip install -e . -r backend-fastapi/requirements.txt`.
2. Prepare `ml/training/capture_manifest.json`: a JSON array of objects containing
   `path`, `capture_group`, `split` (`train`, `validation`, `test`), and `label`
   (`Benign`, `DoS`, `DDoS`). Paths are relative to the manifest. Use independent
   lab recording sessions in each split, with all classes in each split. Segments
   from the same experiment must share a capture_group and split. Do not relabel
   mixed traffic by guessing; segment against the recorded scenario schedule.
3. Open `ml/notebooks/ciciot23_training.ipynb` from the repository root. It calls
   the shared extraction/training library and writes new bundles and a report
   under `ml/artifacts/retrained/`. The prior notebook is preserved as `_legacy`.
4. Run `python -m pytest -q` from the root. The suite trains small models on
   synthetic captures strictly for software verification, then compares all 22
   matrix values and probability columns through the actual API. These results
   are not scientific accuracy evidence. Real model golden checks run on load.
5. Start `cd backend-fastapi && uvicorn app.main:app --host 127.0.0.1 --port 8000`.
   `MODEL_DIR` overrides the default `ml/artifacts/retrained/` directory.
   `/api/v1/models` reports unavailable models honestly until retraining is done.

Every request to `/api/v1/predict/batch` or `/ingest/windows` needs
`feature_contract_id` and `contract_hash` from `sentinel_ml.contract`. Pure predict
requests do not persist or trigger actions. Ingest accepts the nested collector
window shape. PCAP upload uses the exact training extractor and validates the
whole bounded file before writing results. Raw CSV replay is intentionally
unsupported because it has no verified measurement provenance. Never send the
old Kaggle features with the new contract ID.

How mismatch prevention works:

- A single extractor defines grouping, duration, counts, window boundaries and
  packet units for both the training dataset builder and application adapter.
- A single matrix builder checks column order, numeric dtypes, finite values,
  count/share relationships and packet bounds, then computes four ratios and
  casts the final 22 features to float32. No string coercion or zero imputation.
- A model bundle carries the contract hash, feature order, encoder/class order,
  source hashes and validation reference rows/probabilities. The loader verifies
  these before accepting the estimator. Historical incompatible artifacts fail.
- HTTP uses strict numeric fields and explicit contract identity. Integration
  tests send the same rows through training, artifact reload and HTTP inference.

A declared contract cannot prove that an external client measured truthfully;
use the approved extractor. Model golden checks detect implementation/runtime
changes on the saved examples, not every possible numerical or distribution
shift. Add real independent capture evaluation before claiming live robustness.

Current supported capture subset is classic Ethernet PCAP with full,
unfragmented IPv4 TCP/UDP/ICMP and monotone timestamps. Unsupported formats fail
explicitly. There is no alternate approximate parser. At most 4096 active flow
keys are retained; insufficient windows (<5 packets) are counted by the dataset
builder. The API is observe-only. Device-management/security hardening and a UI
are outside this training-and-backend milestone.
