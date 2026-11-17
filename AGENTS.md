# CICIoT23 Sentinel — instructions for coding agents

The purpose is an AIML project demonstrating a traceable path from training to
an application using the trained model. Scientific validity and a working
vertical slice take priority over the number of dashboard pages or controls.

## Read before working

1. [Architecture and milestones](agents/master_architecture_integration_blueprint.md).
2. [Engineering and evidence rules](agents/agent_governance_anti_drift_protocol.md).
3. [Model and feature contracts](agents/machine_learning_pipeline_22_feature_contract.md).
4. The specification for the component being changed: [backend](agents/fastapi_backend_ml_engine_database_specification.md),
   [collector](agents/go_packet_collector_specification.md), or [UI](agents/react_soc_dashboard_ui_ux_specification.md).
5. [Current audit and backlog](agents/project_audit.md) and [quickstart](agents/readme_quickstart_guide.md).

These v3 documents describe the target, not completed implementation. As of the
2026-11-15 review, backend functionality is partial, the Go collector and React
application source files are largely empty, and model/extractor parity is not
established. Read the current code and tests before claiming a feature works.

## Non-negotiable evidence rules

- Preserve the uploaded notebook (`ciciot23_training_legacy.ipynb`) and model as historical experiment artifacts.
  Do not edit their metrics or mark provenance verified without evidence.
- Identical feature names do not establish identical feature meanings. The
  existing CSV-trained model must not be declared compatible with the proposed
  100-packet extractor. Require a versioned contract and parity evidence.
- Keep dataset evaluation, feature-row replay, PCAP inference, live inference,
  and synthetic software tests visibly distinct. Synthetic tests do not measure
  model accuracy; predictions do not create ground truth.
- Use the real XGBoost artifact for the assessed demo. Missing optional model
  files mean unavailable models, not automatically substituted classifiers.
- Observe-only is the target default. Disable network-changing actions until
  authentication, attribution, command acknowledgements and compatibility gates
  are implemented and tested. The existing code does not yet meet these gates.
- Preserve the old CSV feature order and formulas for that artifact. A new
  extraction policy requires a new contract and a compatible retrained model.
- Report limitations and failed checks honestly; do not fake data, benchmark
  scores, completed features or successful device actions.

## Working method

Explicit user direction governs project scope. The user authorized this v3
specification revision. Routine fixes, incremental implementations and tests do
not require a repeated override approval. For a new scientific assumption or
breaking contract, document the evidence and migration; ask a focused question
only if a material choice cannot be resolved from the user's goal.

Keep changes reviewable. Implement complete, testable paths in small steps;
unimplemented capabilities must be visibly unavailable. Reuse existing modules
where coherent; there is no fixed file-name hierarchy that forces empty stubs.
Run checks relevant to the change and distinguish blocked checks from passes.
Use the canonical `AGENTS.md`; `Agents.md` is a compatibility pointer only.

## Executable contract after retraining revision

`sentinel_ml/contract.py` defines the exact ordered base/derived schema, formulas,
validation, float32 dtype and version hash. `sentinel_ml/capture.py` is shared by
training and the API. No independent Go or Python feature implementation may be
used for this model without parity tests. The corrected main notebook delegates
to `sentinel_ml/training.py`; split independent recording groups before extraction.
Run `python -m pytest -q` from the root for the integration contract tests. Models
must pass `sentinel_ml.artifacts.load` golden-row verification before use.
