# Existing-model runtime (current decision)

The supplied trained XGBoost is now the runtime default. Retraining is optional.
Go packet ingestion and FastAPI PCAP upload use the explicitly accepted approximate
adapter. Earlier prohibitions on passing any packet approximation to this model
are superseded by the user's 2026-11-17 instruction. No exact Kaggle parity or
live accuracy is claimed. See ../../collector-go/README.md for the active commands.
MODEL_DIR defaults to ml/artifacts, not csv_retrained. Exact exported inputs are
available from /api/v1/features/export?capture_session_id=ID.

The following CSV training instructions remain optional future work. New-model
artifacts still require contract and golden checks; the historical model instead
uses its exact SHA-256 identity and original encoder. It has no supplied golden
training rows, and this absence is explicitly recorded.

# CSV-first Kaggle training and application

The only training source is `himadri07/ciciot2023`. No PCAPs or additional
recordings are required. This supersedes the earlier capture-first plan.

1. Open `ml/notebooks/ciciot23_training.ipynb` in a checkout of this repository.
2. Attach the given Kaggle dataset and set DATASET_ROOT to its directory.
   It must contain one train.csv, validation.csv and test.csv, anywhere below it.
3. Run the notebook. Training uses `sentinel_ml.csv_training` and the shared
   `sentinel_ml.csv_contract`. Exports go to `/kaggle/working/ciciot23_artifacts`.
4. Download the bundles and report. Place bundles under
   `ml/artifacts/csv_retrained/`, or set MODEL_DIR to their directory.
5. Install `pip install -e . -r backend-fastapi/requirements.txt` from the root.
   Run `cd backend-fastapi && uvicorn app.main:app --host 127.0.0.1 --port 8000`.
6. Upload dataset feature rows to `POST /api/v1/csv/upload` in `/docs`.
   Files need all original 18 base columns; other Kaggle columns and labels are
   excluded from prediction. No addresses or packet counts are invented.
   Upload at most 10,000 rows/32 MiB per request. Labels never enter the model.

## Preprocessing and evaluation

All models use 18 selected original CSV measurements and four engineered ratios:
Rate*AVG; (syn_count+1)/(ack_count+1); Header_Length/(AVG+1e-5);
Std/(AVG+1e-5). Base measurements round to float32 before float64 engineering;
output is ordered float32. Training and API call the identical matrix builder.
No packet-count or header-size assumptions are imposed on the original CSVs.
Invalid rows are excluded with counts during dataset preparation and rejected
at inference. No imputation, guessed rescaling, synthetic substitutes or clipping.

Only BenignTraffic, DoS-* and DDoS-* labels are retained. Provided splits remain
unchanged. Exact same-label training duplicates are removed using training only;
conflicting training labels remain. Cross-split feature overlap is reported,
not deleted using holdout labels. Recording independence cannot be established
from these CSVs. Select the model on validation macro-F1 and evaluate the selected
model on test once. Do not tune from final test results.

Artifacts include source hashes, preprocessing contract/hash, class order and
reference predictions. FastAPI checks the references on load. Tests compare all
22 matrix values and probabilities through CSV upload, including CSV measurements
that cannot satisfy a 100-packet model. Tests use synthetic fixtures solely for
software verification, not training evidence. Run `python -m pytest -q`.

## PCAP input: exact schema is not exact measurement parity

The original CSV extractor cannot currently be reproduced completely from the
supplied materials. The recovered supplementary revision outputs a different
schema, and the paper describes label-dependent aggregation. CSV-only training
cannot establish the generating state, file boundaries or exact packet formulas.
A scaler, quantile transform, column rename or matching histogram cannot recover
those missing semantics and is not used as a compatibility workaround.

`sentinel_ml.capture` is an inference-only approximation. The supplied historical
XGBoost accepts this representation through the explicit packet adapter, with a
compatibility warning. Go replay/live capture and FastAPI upload use this path.
New CSV-trained artifacts currently accept CSV inference only until their packet
adapter is separately validated. No PCAP training module or capture-trained model
contract is retained. The original notebook/model remain as training evidence.

## Revised false-positive objective

Retraining and feature changes are now authorized. The executable pipeline chooses
a validation attack-score threshold with at most 0.1% empirical benign false
positives, then selects the candidate with greatest attack recall. This replaces
the earlier macro-F1 selection instruction above. A candidate with zero detected
attacks is ineligible. The final test uses the frozen policy. Report keys are
selected_model, selection_rule and decision_policies. Serving uses the exported
policy through the shared decision module. Old bundles retain their original
decision behavior. This CSV objective does not certify packet compatibility.

The 0.1% budget is an initial engineering choice. Evaluate recall and final-test
false positives before deployment. Independent local benign traffic and known
attack intervals are needed to assess actual application performance.

The reader also accepts train.csv.gz, validation.csv.gz and test.csv.gz directly.
Use exactly one compressed or uncompressed file for each split. To train only
the requested XGBoost candidate, call
`train(DATASET_ROOT, OUTPUT_DIR, model_names=['xgb'])`.
