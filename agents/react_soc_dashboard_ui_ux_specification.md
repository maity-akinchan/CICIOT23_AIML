# UI integration requirements (deferred)

Current decision (2026-11-17): use the existing supplied XGBoost artifact without
retraining. Preserve contributor Go code. The user explicitly authorizes approximate
packet measurements despite unverified parity with Kaggle. Do not substitute models,
fabricate compatibility, or enable firewall actions. The implementation scope is
Go + FastAPI; UI implementation is deferred.

React entry files remain incomplete. Current work targets Go and FastAPI only.
Future UI should show model identity, packet_approximation warnings, data-source
mode, real features/probabilities and exported inputs. Keep dataset benchmark
metrics separate from live predictions. Do not label a sent command as executed,
and do not render unimplemented security controls as operational.
