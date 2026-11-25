import logging
from pathlib import Path

import numpy as np
import pandas as pd
from xgboost import DMatrix
from xgboost.core import XGBoostError

from app.schemas import ModelSignal, PredictionResult
from sentinel_ml.approximation import WARNING, adapt_payloads_to_base_df
from sentinel_ml.artifacts import load, predict
from sentinel_ml.contract import FEATURES
from sentinel_ml.decision import classify

logger = logging.getLogger(__name__)


class InferenceEngine:
    def __init__(self, artifact_path: Path):
        self.artifact_path = artifact_path
        self.bundle = None
        self.error = 'Model not loaded'

    @property
    def is_loaded(self):
        return self.bundle is not None

    @property
    def is_bootstrap_model(self):
        return False

    def load(self):
        self.bundle = load(self.artifact_path)
        self.error = None

    def _frame(self, payloads):
        from sentinel_ml.csv_contract import matrix
        return matrix(adapt_payloads_to_base_df(payloads))

    def explain(self, matrix, labels):
        """Rank signals that pushed the predicted class above Benign."""
        estimator = self.bundle['model']
        if not hasattr(estimator, 'get_booster'):
            return {}
        classes = self.bundle['classes']
        flagged = [i for i, label in enumerate(labels) if label in ('DoS', 'DDoS')]
        if not flagged:
            return {}
        features = matrix.iloc[flagged]
        try:
            values = estimator.get_booster().predict(
                DMatrix(features, nthread=1), pred_contribs=True, strict_shape=True
            )
        except (ValueError, XGBoostError):
            logger.exception('Could not calculate feature contributions')
            return {}
        benign_index = classes.index('Benign')
        explanations = {}
        for offset, i in enumerate(flagged):
            # The last term is the model bias and has no corresponding measurement.
            delta = values[offset, classes.index(labels[i]), :-1] - values[offset, benign_index, :-1]
            strongest = np.argsort(-delta, kind='stable')
            explanations[i] = [
                ModelSignal(feature=FEATURES[j], value=float(features.iloc[offset, j]),
                            model_contribution=float(delta[j]))
                for j in strongest[:3] if np.isfinite(delta[j]) and delta[j] > 0
            ]
        return explanations

    def restore_explanations(self, rows):
        """Explain older stored rows using only the identical model artifact."""
        if not self.is_loaded:
            return rows
        indices = [
            i for i, row in enumerate(rows)
            if row['artifact_sha256'] == self.bundle['artifact_sha256']
            and row['predicted_class'] in ('DoS', 'DDoS') and not row['top_anomalies']
            and all(name in row['features_22'] for name in FEATURES)
        ]
        for start in range(0, len(indices), 100):
            batch = indices[start:start + 100]
            matrix = pd.DataFrame([rows[i]['features_22'] for i in batch], columns=FEATURES, dtype='float32')
            for pos, signals in self.explain(matrix, [rows[i]['predicted_class'] for i in batch]).items():
                rows[batch[pos]]['top_anomalies'] = [signal.model_dump() for signal in signals]
        return rows

    def predict_batch(self, payloads):
        if self.bundle is None:
            raise RuntimeError(self.error)
        x, scores = predict(self.bundle, adapt_payloads_to_base_df(payloads))
        labels = classify(self.bundle['classes'], scores, self.bundle.get('decision_policy'))
        explanations = self.explain(x, labels)
        result = []
        for i, p in enumerate(payloads):
            probabilities = dict(zip(self.bundle['classes'], map(float, scores[i])))
            label = str(labels[i])
            unverified = p.input_representation == 'packet_approximation'
            result.append(PredictionResult(
                window_id=p.window_id, timestamp=p.timestamp, src_ip=p.src_ip, dst_ip=p.dst_ip,
                predicted_class=label, confidence_score=probabilities[label],
                is_anomaly=label != 'Benign' and not unverified, probabilities=probabilities,
                input_representation=p.input_representation, compatibility_warning=WARNING if unverified else None,
                model_used=self.bundle['model_id'], artifact_sha256=self.bundle['artifact_sha256'],
                features_22=x.iloc[i].astype(float).to_dict(), top_anomalies=explanations.get(i, []),
            ))
        return result
