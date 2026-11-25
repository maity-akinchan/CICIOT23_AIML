from pathlib import Path
import pandas as pd
from sentinel_ml.approximation import WARNING, adapt_payloads_to_base_df
from sentinel_ml.artifacts import load, predict
from sentinel_ml.decision import classify
from sentinel_ml.contract import BASE
from app.schemas import AnomalyExplanation, PredictionResult

class InferenceEngine:
    def __init__(self,artifact_path:Path):
        self.artifact_path=artifact_path
        self.bundle=None
        self.error='Model not loaded'
    @property
    def is_loaded(self):return self.bundle is not None
    @property
    def is_bootstrap_model(self):return False
    @property
    def model_id(self) -> str:
        return self.artifact_path.stem

    @property
    def accepts_packet_approximation(self) -> bool:
        return bool(self.bundle and self.bundle['accepts_packet_approximation'])

    def load(self):
        self.bundle=load(self.artifact_path)
        self.error=None
    def _frame(self,payloads):
        from sentinel_ml.csv_contract import matrix
        return matrix(adapt_payloads_to_base_df(payloads))
    def _explain(self, row_dict: dict, label: str) -> list[AnomalyExplanation]:
        if label == 'Benign' or not self.bundle:
            return []
        baseline = self.bundle.get('benign_baseline') or {}
        medians = self.bundle.get('benign_medians') or {}
        iqrs = self.bundle.get('benign_iqr') or {}
        candidates = []
        for feat, val in row_dict.items():
            if feat in baseline and isinstance(baseline[feat], dict):
                med = float(baseline[feat].get('median', 0.0))
                iqr = max(float(baseline[feat].get('iqr', 1.0)), 1.0)
            elif feat in medians:
                med = float(medians.get(feat, 0.0))
                iqr = max(float(iqrs.get(feat, 1.0)), 1.0)
            else:
                continue
            diff = float(val) - med
            z = abs(diff) / iqr
            if z > 1.5:
                candidates.append(AnomalyExplanation(
                    feature=feat,
                    value=float(val),
                    benign_median=med,
                    z_iqr=round(min(z, 999.9), 2),
                    direction='HIGH' if diff >= 0 else 'LOW',
                ))
        candidates.sort(key=lambda item: item.z_iqr, reverse=True)
        return candidates[:3]
    def predict_batch(self,payloads):
        if self.bundle is None:raise RuntimeError(self.error)
        base_df = adapt_payloads_to_base_df(payloads)
        x,scores=predict(self.bundle,base_df)
        labels=classify(self.bundle["classes"],scores,self.bundle.get("decision_policy"))
        result=[]
        for i,p in enumerate(payloads):
            probabilities=dict(zip(self.bundle['classes'],map(float,scores[i])))
            label=str(labels[i])
            unverified = p.input_representation == 'packet_approximation'
            f22 = x.iloc[i].astype(float).to_dict()
            result.append(PredictionResult(window_id=p.window_id,timestamp=p.timestamp,src_ip=p.src_ip,dst_ip=p.dst_ip,
                predicted_class=label,confidence_score=probabilities[label],is_anomaly=label!='Benign' and not unverified,probabilities=probabilities,
                input_representation=p.input_representation,
                compatibility_warning=WARNING if unverified else None,
                model_used=self.bundle['model_id'],artifact_sha256=self.bundle['artifact_sha256'],
                features_22=f22,top_anomalies=self._explain(f22, label)))
        return result
