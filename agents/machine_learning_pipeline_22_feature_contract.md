# 02 — MACHINE LEARNING PIPELINE & 22-FEATURE CONTRACT
**Scope:** Feature Definitions, Mathematical Formulas, Leakage Prevention, and `.joblib` Artifact Schema.

---

## 1. WHY ONLY 22 DETERMINISTIC FEATURES?
The raw CICIoT2023 CSV dataset contains 46 feature columns. Several of those columns suffer from severe flaws documented in peer-reviewed replication studies:
1. **`IAT` (Inter-Arrival Time):** In CICIoT2023 CSVs, `IAT` holds absolute Unix epoch timestamps (`~1.68e9`) corresponding to the specific day/hour UNB recorded a given attack category. Any model trained with `IAT` achieves 99.9% accuracy on random splits by memorizing capture session timestamps and fails completely on new PCAPs.
2. **`Number` and `Weight`:** Discrete aggregation window artifacts (`15` unique values) that act as batch lookup keys.
3. **`Covariance`, `Radius`, `Variance`, `Magnitue`:** Complex bidirectional sub-stream metrics that depend on internal quirks of UNB's legacy Python scripts and cannot be reproduced reliably in high-speed C/Go packet sniffers.

Therefore, **CICIoT23 Sentinel** locks a strict **22-Feature Contract**:
- **18 Base Features** extracted directly from 100-packet windows by `collector-go`.
- **4 Derived Ratio Features** computed deterministically in `backend-fastapi` from those 18 base features.

---

## 2. THE LOCKED 22-FEATURE TABLE (EXACT ORDER & CASING)

The array of feature names in `bundle["feature_names"]` **MUST** always be in this exact indices `0` through `21` order:

| Index | Exact Feature Name | Origin | Data Type | Valid Range | Physical Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `0` | `flow_duration` | Base (Go) | `float64` | $[10^{-6}, \infty)$ | Elapsed time in seconds between first and last packet in window |
| `1` | `Rate` | Base (Go) | `float64` | $[0, 10^8]$ | Packet transmission rate ($N / \text{flow\_duration}$) in packets/sec |
| `2` | `Header_Length` | Base (Go) | `float64` | $[20, 160]$ | Arithmetic mean of $(\text{Network Header} + \text{Transport Header})$ bytes |
| `3` | `Duration` | Base (Go) | `float64` | $[0, 255]$ | Arithmetic mean of IPv4 `TTL` or IPv6 `HopLimit` |
| `4` | `fin_flag_number` | Base (Go) | `float64` | $[0.0, 1.0]$ | Proportion of packets in window with TCP `FIN` flag set |
| `5` | `syn_flag_number` | Base (Go) | `float64` | $[0.0, 1.0]$ | Proportion of packets in window with TCP `SYN` flag set |
| `6` | `rst_flag_number` | Base (Go) | `float64` | $[0.0, 1.0]$ | Proportion of packets in window with TCP `RST` flag set |
| `7` | `psh_flag_number` | Base (Go) | `float64` | $[0.0, 1.0]$ | Proportion of packets in window with TCP `PSH` flag set |
| `8` | `ack_flag_number` | Base (Go) | `float64` | $[0.0, 1.0]$ | Proportion of packets in window with TCP `ACK` flag set |
| `9` | `ack_count` | Base (Go) | `float64` | $[0, N]$ | Raw count of packets in window with TCP `ACK` flag set |
| `10` | `syn_count` | Base (Go) | `float64` | $[0, N]$ | Raw count of packets in window with TCP `SYN` flag set |
| `11` | `fin_count` | Base (Go) | `float64` | $[0, N]$ | Raw count of packets in window with TCP `FIN` flag set |
| `12` | `rst_count` | Base (Go) | `float64` | $[0, N]$ | Raw count of packets in window with TCP `RST` flag set |
| `13` | `TCP` | Base (Go) | `float64` | $[0.0, 1.0]$ | Proportion of packets in window encapsulating TCP |
| `14` | `UDP` | Base (Go) | `float64` | $[0.0, 1.0]$ | Proportion of packets in window encapsulating UDP |
| `15` | `ICMP` | Base (Go) | `float64` | $[0.0, 1.0]$ | Proportion of packets in window encapsulating ICMP / ICMPv6 |
| `16` | `AVG` | Base (Go) | `float64` | $[0, 65535]$ | Arithmetic mean of total packet wire length (bytes) in window |
| `17` | `Std` | Base (Go) | `float64` | $[0, 65535]$ | Population standard deviation of total packet wire length in window |
| `18` | `bytes_per_sec` | Derived (Py) | `float64` | $[0, \infty)$ | Bandwidth volume: $\text{Rate} \times \text{AVG}$ |
| `19` | `syn_ack_ratio` | Derived (Py) | `float64` | $(0, 101]$ | Handshake asymmetry: $(\text{syn\_count} + 1.0) / (\text{ack\_count} + 1.0)$ |
| `20` | `hdr_pkt_ratio` | Derived (Py) | `float64` | $[0, 1.0]$ | Header overhead ratio: $\text{Header\_Length} / (\text{AVG} + 10^{-5})$ |
| `21` | `pkt_cv` | Derived (Py) | `float64` | $[0, \infty)$ | Packet size jitter (Coeff of Variation): $\text{Std} / (\text{AVG} + 10^{-5})$ |

---

## 3. EXACT MATHEMATICAL FORMULAS FOR THE 4 DERIVED RATIOS

Inside `backend-fastapi/app/services/feature_adapter.py`, given a Pandas DataFrame `df` or dictionary containing the 18 base features:

$$
\text{bytes\_per\_sec} = \text{Rate} \times \text{AVG}
$$

$$
\text{syn\_ack\_ratio} = \frac{\text{syn\_count} + 1.0}{\text{ack\_count} + 1.0}
$$

$$
\text{hdr\_pkt\_ratio} = \frac{\text{Header\_Length}}{\text{AVG} + 10^{-5}}
$$

$$
\text{pkt\_cv} = \frac{\text{Std}}{\text{AVG} + 10^{-5}}
$$

### Why These 4 Ratios Are Essential
- **`pkt_cv`:** Single-source `DoS` tools (`hping3`) emit uniform packet sizes ($\text{Std} \approx 0 \implies \text{pkt\_cv} \approx 0$). Multi-source `DDoS` traffic interleaves packets from heterogeneous botnet nodes/OS stacks, yielding higher relative size variance.
- **`syn_ack_ratio`:** Pure TCP SYN floods have $\text{syn\_count} = 100$ and $\text{ack\_count} = 0$, yielding $\text{syn\_ack\_ratio} = 101.0$, whereas normal TCP traffic has high `ack_count` and low `syn_count` ($\text{syn\_ack\_ratio} < 0.2$).
- **`hdr_pkt_ratio`:** Pure L3/L4 floods carry zero application payload ($\text{Header\_Length} \approx \text{AVG}$), pushing $\text{hdr\_pkt\_ratio}$ near $0.74$–$1.0$, whereas HTTP/data transfers carry large payloads ($\text{hdr\_pkt\_ratio} < 0.15$).

---

## 4. PRODUCTION `.joblib` ARTIFACT SPECIFICATION

All four model notebooks (`ciciot23_22f_xgboost.ipynb`, `ciciot23_22f_brf.ipynb`, `ciciot23_22f_svm.ipynb`, `ciciot23_22f_logreg.ipynb`) export a serialized Python dictionary via `joblib.dump(bundle, filename)`.

### 4.1 Expected File Names in `ml/artifacts/`
| Model ID (`model_id`) | Filename | Algorithm |
| :--- | :--- | :--- |
| `"xgb"` (Default) | `ciciot_22f_xgb.joblib` | GPU-trained `XGBClassifier` (`device="cpu"` set prior to export) |
| `"brf"` | `ciciot_22f_brf.joblib` | `imblearn.ensemble.BalancedRandomForestClassifier` |
| `"svm"` | `ciciot_22f_svm.joblib` | `Pipeline(StandardScaler, Nystroem, CalibratedClassifierCV(SGDClassifier))` |
| `"lr"` | `ciciot_22f_lr.joblib` | `Pipeline(StandardScaler, LogisticRegression)` |

### 4.2 Universal Bundle Dictionary Structure (With Backwards-Compatible Fallback)
The FastAPI loader (`ml_registry.py`) must support both the compact export snippet and the full telemetry bundle structure below. If any optional key (`metrics`, `benign_medians`, `classes`) is omitted in a user-supplied `.joblib`, `ml_registry.py` **MUST** automatically populate it on startup from the model attributes (`model.classes_`, `model.feature_importances_`) so the API never throws a `KeyError`:

```python
{
    "model_id": "xgb",                              # str: "xgb" | "brf" | "svm" | "lr"
    "model_name": "XGBoost_GPU_CICIoT23_22F",       # str: Human-readable display name
    "model": <fitted_estimator>,                    # Supports .predict(X) and .predict_proba(X)
    "feature_names": DETERMINISTIC_22,              # list[str] of length 22
    "encoder": <LabelEncoder or None>,              # Used if model.predict() returns 0, 1, 2 integers
    "classes": ["Benign", "DDoS", "DoS"],           # list[str]: Ordered class names matching predict_proba columns
    "impute_medians": {                             # dict[str, float]: Median of each of the 22 features in X_train
        "flow_duration": 0.0412,
        # ... all 22 features
    },
    "benign_medians": {                             # dict[str, float]: Median of each feature on Benign training rows
        "flow_duration": 1.240,
        # ... all 22 features (if missing, fallback to impute_medians)
    },
    "benign_iqr": {                                 # dict[str, float]: IQR (Q75 - Q25) on Benign training rows
        "flow_duration": 2.150,
        # ... all 22 features (clamped to >= 1e-6)
    },
    "metrics": {                                    # Optional dict: If missing, computed on ml/sample_data/test_sample_500.csv at startup
        "test_accuracy": 0.9142,
        "test_macro_f1": 0.9085,
        "confusion_matrix": [
            [26219, 2, 5],
            [310, 421500, 41265],
            [85, 18400, 144083]
        ],
        "classification_report": {
            "Benign": {"precision": 0.985, "recall": 0.999, "f1-score": 0.992, "support": 26226},
            "DDoS":   {"precision": 0.958, "recall": 0.910, "f1-score": 0.933, "support": 463075},
            "DoS":    {"precision": 0.777, "recall": 0.886, "f1-score": 0.828, "support": 162568}
        },
        "feature_importances": {
            "syn_ack_ratio": 0.184,
            "pkt_cv": 0.142,
            # ... all 22 features summing to 1.0
        }
    }
}
```

---

## 5. LOCAL EXPLAINABILITY ALGORITHM (TOP 3 ANOMALOUS FEATURES)
When a window is classified as `"DoS"` or `"DDoS"`, Page 3 (Attack Detection & Alerts) and Page 4 (Flow Explorer) display the **Top 3 Anomalous Features** that explain *why* the window looks malicious compared to normal `Benign` traffic.

Inside `backend-fastapi/app/services/explainability.py`, compute the robust **IQR Z-Score** for each feature $i \in \{0 \dots 21\}$:

$$
z_{\text{IQR}}(i) = \frac{|x_i - \text{median}_{\text{Benign}}(i)|}{\max(\text{IQR}_{\text{Benign}}(i), 10^{-4})} \times w_i
$$

Where:
- $x_i$ is the observed feature value in the current window.
- $\text{median}_{\text{Benign}}(i)$ is `bundle["benign_medians"][feature_i]` (falling back to `bundle["impute_medians"][feature_i]` if `benign_medians` was not saved).
- $\text{IQR}_{\text{Benign}}(i)$ is `bundle["benign_iqr"][feature_i]`.
- $w_i = \max(\text{feature\_importance}(i), 0.02)$ weights the deviation by how much the model actually relies on feature $i$ so irrelevant zero-variance flags don't dominate the explanation.

Sort all 22 features by $z_{\text{IQR}}(i)$ descending and return the top 3 as:
```python
[
    {
        "feature": feat_name,
        "value": round(float(val), 4),
        "benign_median": round(float(b_med), 4),
        "z_iqr": round(float(score), 2),
        "direction": "HIGH" if val >= b_med else "LOW"
    }
]
```