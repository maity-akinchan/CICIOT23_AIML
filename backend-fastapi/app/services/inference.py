from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from app.schemas import BASE_FEATURE_NAMES, FEATURE_NAMES, AnomalyExplanation, FlowWindowPayload, PredictionResult

logger = logging.getLogger(__name__)


def _bootstrap_model() -> dict[str, Any]:
    rows: list[list[float]] = []
    labels: list[str] = []
    for label, syn, ack, rate, avg, std in (
        ("Benign", 0.05, 0.40, 20.0, 500.0, 120.0),
        ("DoS", 1.0, 0.0, 10000.0, 54.0, 0.0),
        ("DDoS", 0.75, 0.05, 7000.0, 250.0, 180.0),
    ):
        for multiplier in range(1, 41):
            rows.append([0.01 * multiplier, rate * (1 + multiplier / 1000), 40.0, 64.0,
                         0.0, syn, 0.0, 0.0, ack, ack * 100, syn * 100, 0.0, 0.0,
                         1.0, 0.0, 0.0, avg, std])
            labels.append(label)
    frame = pd.DataFrame(rows, columns=BASE_FEATURE_NAMES)
    frame["bytes_per_sec"] = frame["Rate"] * frame["AVG"]
    frame["syn_ack_ratio"] = (frame["syn_count"] + 1.0) / (frame["ack_count"] + 1.0)
    frame["hdr_pkt_ratio"] = frame["Header_Length"] / (frame["AVG"] + 1e-5)
    frame["pkt_cv"] = frame["Std"] / (frame["AVG"] + 1e-5)
    model = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=0))
    model.fit(frame.loc[:, FEATURE_NAMES], labels)
    medians = frame.loc[:, FEATURE_NAMES].median().astype(float).to_dict()
    iqr = (frame.loc[:, FEATURE_NAMES].quantile(0.75) - frame.loc[:, FEATURE_NAMES].quantile(0.25))
    return {"model_id": "xgb", "model_name": "Deterministic Bootstrap Model", "model": model,
            "feature_names": list(FEATURE_NAMES), "classes": list(model.classes_),
            "impute_medians": medians, "benign_medians": medians,
            "benign_iqr": iqr.clip(lower=1e-6).astype(float).to_dict(), "is_bootstrap_model": True}


class InferenceEngine:
    def __init__(self, artifact_path: Path) -> None:
        self.artifact_path = artifact_path
        self.bundle: dict[str, Any] | None = None

    @property
    def is_loaded(self) -> bool:
        return self.bundle is not None

    @property
    def is_bootstrap_model(self) -> bool:
        return bool(self.bundle and self.bundle.get("is_bootstrap_model", False))

    def load(self) -> None:
        if self.artifact_path.exists():
            loaded = joblib.load(self.artifact_path)
            self.bundle = loaded if isinstance(loaded, dict) else {"model": loaded}
            self._normalize_bundle()
            logger.info("Loaded ML artifact from %s", self.artifact_path)
        else:
            self.bundle = _bootstrap_model()
            logger.warning("Artifact missing at %s; using deterministic bootstrap model", self.artifact_path)

    def _normalize_bundle(self) -> None:
        assert self.bundle is not None
        model = self.bundle.get("model")
        if model is None or not hasattr(model, "predict_proba"):
            raise ValueError("model bundle must contain a classifier with predict_proba")
        if list(self.bundle.get("feature_names", FEATURE_NAMES)) != list(FEATURE_NAMES):
            raise ValueError("model feature_names do not match the locked 22-feature contract")
        self.bundle["feature_names"] = list(FEATURE_NAMES)
        self.bundle.setdefault("classes", [str(item) for item in getattr(model, "classes_", [])])
        self.bundle.setdefault("model_id", "xgb")
        self.bundle.setdefault("model_name", self.bundle["model_id"])
        self.bundle.setdefault("is_bootstrap_model", False)
        self.bundle.setdefault("impute_medians", {name: 0.0 for name in FEATURE_NAMES})
        self.bundle.setdefault("benign_medians", self.bundle["impute_medians"])
        self.bundle.setdefault("benign_iqr", {name: 1.0 for name in FEATURE_NAMES})

    def _frame(self, payloads: list[FlowWindowPayload]) -> pd.DataFrame:
        frame = pd.DataFrame([{name: getattr(item, name) for name in BASE_FEATURE_NAMES} for item in payloads],
                             columns=BASE_FEATURE_NAMES)
        frame["bytes_per_sec"] = frame["Rate"] * frame["AVG"]
        frame["syn_ack_ratio"] = (frame["syn_count"] + 1.0) / (frame["ack_count"] + 1.0)
        frame["hdr_pkt_ratio"] = frame["Header_Length"] / (frame["AVG"] + 1e-5)
        frame["pkt_cv"] = frame["Std"] / (frame["AVG"] + 1e-5)
        assert self.bundle is not None
        medians = pd.Series(self.bundle["impute_medians"], dtype=float)
        return frame.replace([np.inf, -np.inf], np.nan).fillna(medians).loc[:, FEATURE_NAMES].astype(float)

    def predict_batch(self, payloads: list[FlowWindowPayload]) -> list[PredictionResult]:
        if not payloads:
            return []
        if self.bundle is None:
            raise RuntimeError("inference engine has not been loaded")
        frame = self._frame(payloads)
        model = self.bundle["model"]
        predictions = model.predict(frame)
        probabilities = model.predict_proba(frame)
        classes = [str(item) for item in self.bundle["classes"]]
        results: list[PredictionResult] = []
        for index, payload in enumerate(payloads):
            row = {classes[col]: float(probabilities[index][col]) for col in range(min(len(classes), probabilities.shape[1]))}
            predicted = str(predictions[index])
            values = {name: float(frame.iloc[index][name]) for name in FEATURE_NAMES}
            results.append(PredictionResult(
                window_id=payload.window_id, timestamp=payload.timestamp, src_ip=payload.src_ip, dst_ip=payload.dst_ip,
                predicted_class=predicted, confidence_score=max(row.values(), default=0.0),
                is_anomaly=predicted != "Benign", probabilities=row,
                model_used=str(self.bundle["model_name"]), features_22=values,
                top_anomalies=self._anomalies(values) if predicted in {"DoS", "DDoS"} else [],
            ))
        return results

    def _anomalies(self, values: dict[str, float]) -> list[AnomalyExplanation]:
        assert self.bundle is not None
        medians = self.bundle["benign_medians"]
        iqrs = self.bundle["benign_iqr"]
        ranked = sorted(((abs(values[name] - float(medians.get(name, 0.0))) /
                          max(float(iqrs.get(name, 1e-4)), 1e-4), name) for name in FEATURE_NAMES), reverse=True)
        return [AnomalyExplanation(feature=name, value=round(values[name], 4),
                                   benign_median=round(float(medians.get(name, 0.0)), 4),
                                   z_iqr=round(float(score), 2),
                                   direction="HIGH" if values[name] >= float(medians.get(name, 0.0)) else "LOW")
                for score, name in ranked[:3]]
