# Project objective

Demonstrate an AIML workflow that connects a reproducible trained classifier to a
useful traffic-analysis application, and evaluate the limits of its performance.

## Core deliverable

A real trained XGBoost artifact is loaded by FastAPI, receives inputs validated
against its training contract, and produces traceable predictions in a small
React dashboard. Users can inspect inputs, class scores, source/model identity,
recorded evaluation results and alert/session history.

The current experiment classifies selected Benign, DoS and DDoS dataset traffic.
It is not evidence of universal attack detection. CSV replay demonstrates model
serving; a real-packet/live claim additionally requires validated extraction
compatibility and independent labeled capture evaluation.

## Scientific priority

The supplied CSV-trained model and the proposed raw-packet statistics are not
currently compatible. Preserve the historical notebook/model. Recover the
original extractor with parity evidence or retrain using a documented extractor
shared by training and serving. Use capture-grouped splits and do not let held-out
test labels determine training-data cleaning.

Measure class precision/recall and macro-F1, false alerts, missed episodes,
latency, throughput and capture loss. Keep ground truth separate from predictions
and distinguish saved benchmarks from evaluations actually run in the application.

## Scope and source of truth

First complete model serving, dataset analysis and three UI views. Then validate
PCAP and live inference. Go capture optimization, extra model comparisons,
managed fleets and network-changing controls are optional extensions.

The [v3 architecture](agents/master_architecture_integration_blueprint.md),
[ML specification](agents/machine_learning_pipeline_22_feature_contract.md), and
[current audit](agents/project_audit.md) govern the plan. These documents describe
work to be completed; they do not certify the current prototype.
