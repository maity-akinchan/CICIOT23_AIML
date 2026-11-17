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
    from starlette.concurrency import run_in_threadpool
    async with request.app.state.ingest_lock:
        engine = request.app.state.inference_engine
        def persist():
            predictions = engine.predict_batch(payloads)
            with request.app.state.sessions.begin() as db:
                flows, alerts, incidents = request.app.state.incidents.record(db,payloads,predictions)
            return predictions,flows,alerts,incidents
        try:
            predictions,flows,alerts,incidents = await run_in_threadpool(persist)
        except (RuntimeError, ValueError) as exc:
            raise HTTPException(503 if not engine.is_loaded else 422, str(exc)) from exc
    from app.routers.analytics import overview
    await request.app.state.ws_manager.broadcast({
        'event_type':'TELEMETRY_BATCH','server_timestamp':datetime.now(timezone.utc).isoformat(),
        'active_model_id':engine.bundle['model_id'],'artifact_sha256':engine.bundle['artifact_sha256'],
        'kpis':overview(request),'flows':flows,'new_alerts':alerts,'updated_incidents':incidents})
    return _response(predictions)


@router.post("/ingest/windows", response_model=BatchPredictionResponse)
async def ingest_windows(request: Request, payload: IngestBatchRequest) -> BatchPredictionResponse:
    verify_contract(payload)
    import hashlib
    windows=[window.to_flow_payload(payload.capture_mode) for window in payload.windows]
    for window in windows:
        window.capture_session_id=payload.capture_session_id
        window.window_id=hashlib.sha256(f'{payload.capture_session_id}:{payload.collector_id}:{window.window_id}'.encode()).hexdigest()
    return await _predict(request, windows)


@router.post("/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(request: Request, payload: BatchPredictionRequest) -> BatchPredictionResponse:
    verify_contract(payload)
    try:
        from starlette.concurrency import run_in_threadpool
        predictions=await run_in_threadpool(request.app.state.inference_engine.predict_batch,payload.data)
        return _response(predictions)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(503 if not request.app.state.inference_engine.is_loaded else 422, str(exc)) from exc


def verify_contract(payload):
    from sentinel_ml.contract import CONTRACT_ID, CONTRACT_HASH
    if payload.feature_contract_id != CONTRACT_ID or payload.contract_hash != CONTRACT_HASH:
        raise HTTPException(422, 'Input contract mismatch')
