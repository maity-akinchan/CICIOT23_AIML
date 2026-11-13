from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

from app.schemas import BatchPredictionRequest, BatchPredictionResponse, IngestBatchRequest, PredictionResult

router = APIRouter()


def _response(predictions: list[PredictionResult]) -> BatchPredictionResponse:
    counts = {"Benign": 0, "DoS": 0, "DDoS": 0}
    for prediction in predictions:
        if prediction.predicted_class in counts:
            counts[prediction.predicted_class] += 1
    return BatchPredictionResponse(predictions=predictions, processed_windows=len(predictions),
                                   benign_count=counts["Benign"], dos_count=counts["DoS"],
                                   ddos_count=counts["DDoS"])


async def _predict(request: Request, payloads) -> BatchPredictionResponse:
    engine = request.app.state.inference_engine
    try:
        predictions = engine.predict_batch(payloads)
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    await request.app.state.ws_manager.broadcast({
        "event_type": "TELEMETRY_BATCH",
        "server_timestamp": datetime.now(timezone.utc).isoformat(),
        "active_model_id": engine.bundle.get("model_id", "xgb"),
        "flows": [prediction.model_dump(mode="json") for prediction in predictions],
        "new_alerts": [],
        "updated_incidents": [],
    })
    return _response(predictions)


@router.post("/ingest/windows", response_model=BatchPredictionResponse)
async def ingest_windows(request: Request, payload: IngestBatchRequest) -> BatchPredictionResponse:
    return await _predict(request, [window.to_flow_payload(payload.capture_mode) for window in payload.windows])


@router.post("/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(request: Request, payload: BatchPredictionRequest) -> BatchPredictionResponse:
    return await _predict(request, payload.data)
