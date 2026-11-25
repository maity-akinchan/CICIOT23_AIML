"""Load CICIoT23 artifacts and validate their feature and probability contracts."""

import hashlib
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from . import csv_contract
from .contract import BASE, CLASSES, DERIVED, FEATURES

HISTORICAL_SHA256 = 'e1dde2fe2a759684208021934ad3edff2be2dfa29977fac9a246ba9665da233e'
LEGACY_CONTRACT = 'ciciot23-legacy22-v1'


def profile(bundle):
    if (bundle.get('contract_id') in (csv_contract.CONTRACT_ID, LEGACY_CONTRACT)
            and bundle.get('contract_hash') == csv_contract.CONTRACT_HASH):
        return csv_contract.matrix
    raise ValueError('Artifact measurement contract is incompatible')


def _verify_kaggle_export(bundle):
    engineering = bundle.get('feature_engineering', {})
    formulas = engineering.get('formulas', {})
    formula_order = [
        ''.join(formulas.get(name, '').split()).replace('+1.0)', '+1)')
        for name in DERIVED
    ]
    if (
        bundle.get('artifact_format_version') != 1
        or engineering.get('version') != 'ciciot22f-v1'
        or engineering.get('base_features') != list(BASE)
        or engineering.get('model_features') != list(FEATURES)
        or engineering.get('engineered_features') != list(DERIVED)
        or formula_order != csv_contract.SPEC['formulas']
    ):
        raise ValueError('Artifact measurement contract is incompatible')


def load(path):
    path = Path(path)
    with path.open('rb') as stream:
        sha256 = hashlib.sha256()
        while chunk := stream.read(1024 * 1024):
            sha256.update(chunk)
        digest = sha256.hexdigest()
        stream.seek(0)
        bundle = joblib.load(stream)

    bare_estimator = not isinstance(bundle, dict)
    if bare_estimator:
        bundle = {
            'model': bundle,
            'classes': list(getattr(bundle, 'classes_', ())),
            'feature_names': list(getattr(bundle, 'feature_names_in_', ())),
        }
    if 'model' not in bundle:
        raise ValueError('Missing estimator in artifact bundle')

    historical = digest == HISTORICAL_SHA256
    kaggle_export = not (historical or bare_estimator) and 'contract_id' not in bundle and 'contract_hash' not in bundle
    accepts_packet_approximation = historical or kaggle_export or bare_estimator
    if accepts_packet_approximation:
        if kaggle_export:
            _verify_kaggle_export(bundle)
        bundle.update(
            contract_id=LEGACY_CONTRACT if historical else csv_contract.CONTRACT_ID,
            contract_hash=csv_contract.CONTRACT_HASH,
            is_legacy=historical,
            parity_validation='not_available_for_historical_artifact' if historical else 'not_supplied',
        )

    preprocess = profile(bundle)
    if bundle.get('feature_names') != list(FEATURES):
        raise ValueError('Artifact feature order mismatch')
    model = bundle['model']
    if not callable(getattr(model, 'predict_proba', None)):
        raise ValueError('Estimator must support predict_proba')
    encoder = bundle.get('label_encoder')
    classes = list(encoder.inverse_transform(model.classes_.astype(int)) if encoder is not None else model.classes_)
    if classes != bundle.get('classes') or set(classes) != set(CLASSES) or len(classes) != len(CLASSES):
        raise ValueError('Class/probability order mismatch')
    if list(getattr(model, 'feature_names_in_', ())) != list(FEATURES):
        raise ValueError('Estimator input schema mismatch')

    if not accepts_packet_approximation:
        golden = preprocess(pd.DataFrame(bundle['golden_base'], columns=BASE))
        actual = _probabilities(model, golden)
        if not np.allclose(actual, bundle['golden_probabilities'], atol=1e-6, rtol=1e-6):
            raise ValueError('Golden prediction mismatch')
    elif not historical:
        # Check that the exported pipeline can score the shared input shape.
        # A schema smoke test does not establish training or packet parity.
        _probabilities(model, preprocess(pd.DataFrame([[0.0] * len(BASE)], columns=BASE)))

    bundle.update(
        model_id=path.stem,
        artifact_sha256=digest,
        accepts_packet_approximation=accepts_packet_approximation,
    )
    return bundle


def _probabilities(model, matrix):
    scores = np.asarray(model.predict_proba(matrix))
    if (scores.shape != (len(matrix), len(CLASSES)) or not np.isfinite(scores).all()
            or (scores < 0).any() or (scores > 1).any()
            or not np.allclose(scores.sum(axis=1), 1, atol=1e-5)):
        raise ValueError('Invalid probability output')
    return scores


def predict(bundle, base):
    matrix = profile(bundle)(base)
    return matrix, _probabilities(bundle['model'], matrix)
