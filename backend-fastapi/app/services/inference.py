from pathlib import Path
import pandas as pd
from sentinel_ml.approximation import WARNING
from sentinel_ml.artifacts import load, predict
from sentinel_ml.decision import classify
from sentinel_ml.contract import BASE
from app.schemas import PredictionResult

class InferenceEngine:
    def __init__(self,artifact_path:Path):
        self.artifact_path=artifact_path
        self.bundle=None
        self.error='Model not loaded'
    @property
    def is_loaded(self):return self.bundle is not None
    @property
    def is_bootstrap_model(self):return False
    def load(self):
        self.bundle=load(self.artifact_path)
        self.error=None
    def _frame(self,payloads):
        from sentinel_ml.csv_contract import matrix
        return matrix(pd.DataFrame([{k:getattr(p,k) for k in BASE} for p in payloads],columns=BASE))
    def predict_batch(self,payloads):
        if self.bundle is None:raise RuntimeError(self.error)
        x,scores=predict(self.bundle,pd.DataFrame([{k:getattr(p,k) for k in BASE} for p in payloads],columns=BASE))
        labels=classify(self.bundle["classes"],scores,self.bundle.get("decision_policy"))
        result=[]
        for i,p in enumerate(payloads):
            probabilities=dict(zip(self.bundle['classes'],map(float,scores[i])))
            label=str(labels[i])
            unverified = p.input_representation == 'packet_approximation'
            result.append(PredictionResult(window_id=p.window_id,timestamp=p.timestamp,src_ip=p.src_ip,dst_ip=p.dst_ip,
                predicted_class=label,confidence_score=probabilities[label],is_anomaly=label!='Benign' and not unverified,probabilities=probabilities,
                input_representation=p.input_representation,
                compatibility_warning=WARNING if unverified else None,
                model_used=self.bundle['model_id'],artifact_sha256=self.bundle['artifact_sha256'],
                features_22=x.iloc[i].astype(float).to_dict(),top_anomalies=[]))
        return result
