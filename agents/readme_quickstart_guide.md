> Retraining update (2026-11-16): the new notebook and FastAPI use the shared
> `sentinel_ml` package. See [training and API instructions](../ml/training/README.md).
> Supported trained-model IDs are `xgb`, `rf`, `lr`; they are unavailable until
> the corrected capture-based training completes. The legacy artifact is not
> loaded into this new measurement contract. Observe-only controls are enforced.

# Current quickstart and demonstration checklist — v3

**Review date:** 2026-11-15. This guide distinguishes working prototype checks
from future acceptance gates. Read [the audit](project_audit.md) first.

## 1. Available artifacts and implementation

- Uploaded notebook: `ml/notebooks/ciciot23_training.ipynb` (preserved).
- Uploaded XGBoost bundle: `ml/artifacts/ciciot_22f_xgb.joblib` (preserved).
- Other trained bundles: not supplied. The prototype currently generates
  synthetic fallbacks; v3 requires replacing this with unavailable status outside
  explicit test mode.
- `ml/sample_data/test_sample_500.csv`: seven rows, not the notebook's exported
  500-row test sample. No verified dataset provenance; use only as a fixture.
- FastAPI: partial implementation, with known data-integrity and authorization
  gaps. Go collector and React entry points: empty. Docker full-stack demonstration:
  not ready. A generic three-class smoke prediction does not close these gaps.

## 2. Inspect the current backend locally

From the repository root, with a compatible Python environment:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r backend-fastapi/requirements.txt
cd backend-fastapi
python -m pytest -v
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/docs` and inspect `/health`, `/api/v1/models` and
`/api/v1/models/xgb/analytics`. This runs the prototype, not the revised v3 design.
Do not expose the current unauthenticated mutation endpoints on a shared network.

`DATABASE_URL` overrides the prototype database location. Other production-style
settings and a locked tested dependency set still need implementation. The
artifact records Python 3.13.16, scikit-learn 1.6.1 and XGBoost 3.4.1; a different
runtime needs load and golden-prediction parity tests, not merely successful pip
installation. Training dependencies are not fully specified by serving requirements.

The current four pytest tests pass in the reviewed environment. They cover
selected synthetic extraction, inference, enrollment/dispatch and incident
behaviors. They do not establish live detection accuracy or complete integration.

## 3. Honest demonstration sequence

1. Show the notebook, dataset/split limitations and the exact model hash.
2. Use real exported held-out rows to prove notebook/API prediction parity.
   Request/export those rows from the training run; do not substitute the
   seven-row fixture and describe it as held-out evaluation.
3. Demonstrate CSV analysis in the completed dashboard, visibly marked dataset
   features. Show independent labels, errors and reproducible metric output.
4. For a real-packet claim, show extractor provenance/parity or the new capture-
   based training experiment, then run labeled recorded captures end to end.
5. Run held-out benign and attack lab sessions with the same approved extractor
   and model. Record false alerts, missed episodes, coverage and total latency.
6. Present limitations and failure cases. Optional sandbox actions come last;
   they are not necessary to demonstrate application of ML.

## 4. Before the final presentation

Use a clean checkout, pinned dependencies, prebuilt images, an identified real
artifact and a source manifest. Verify one-command startup only after the empty
collector/UI files are implemented. Re-run the browser flow and selected lab
scenarios on the actual demonstration machine. Keep recorded-capture replay as a
clearly labeled fallback if live capture is unavailable. Do not call `docker
compose up` a successful setup procedure until it has passed these checks.
