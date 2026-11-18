from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, Field, NonNegativeInt
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
    expected=getattr(request.state,'collector_id',None)
    if expected is not None and payload.collector_id!=expected:
        raise HTTPException(403,'Credential belongs to a different service')
    verify_contract(payload,request)
    from sentinel_ml.approximation import CONTRACT_ID as APPROX_ID
    approximate=payload.feature_contract_id==APPROX_ID
    import hashlib
    windows=[window.to_flow_payload(payload.capture_mode) for window in payload.windows]
    for raw,window in zip(payload.windows,windows):
        if approximate:
            if raw.metadata.transport_header_mean is None:raise HTTPException(422,'Measured transport_header_mean is required')
            window.Header_Length=raw.metadata.transport_header_mean
            window.input_representation='packet_approximation'
        window.capture_session_id=payload.capture_session_id
        window.window_id=hashlib.sha256(f'{payload.capture_session_id}:{payload.collector_id}:{window.window_id}'.encode()).hexdigest()
    return await _predict(request, windows)


@router.post("/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(request: Request, payload: BatchPredictionRequest) -> BatchPredictionResponse:
    verify_contract(payload,request)
    try:
        from starlette.concurrency import run_in_threadpool
        predictions=await run_in_threadpool(request.app.state.inference_engine.predict_batch,payload.data)
        return _response(predictions)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(503 if not request.app.state.inference_engine.is_loaded else 422, str(exc)) from exc


def verify_contract(payload,request):
    engine=request.app.state.inference_engine
    if not engine.is_loaded:raise HTTPException(503,engine.error)
    from sentinel_ml.approximation import CONTRACT_ID as APPROX_ID,CONTRACT_HASH as APPROX_HASH
    if payload.feature_contract_id==APPROX_ID and payload.contract_hash==APPROX_HASH and engine.bundle.get('is_legacy'):return
    if payload.feature_contract_id!=engine.bundle['contract_id'] or payload.contract_hash!=engine.bundle['contract_hash']:
        raise HTTPException(422,'Input contract differs from loaded model')

class CaptureCoverage(BaseModel):
    collector_id: str = Field(min_length=1, max_length=64)
    session: str = Field(min_length=1, max_length=64)
    iface: str = Field(min_length=1, max_length=64)
    captured: NonNegativeInt
    accepted: NonNegativeInt
    insufficient_packets: NonNegativeInt
    capacity_evictions: NonNegativeInt
    kernel_drops: NonNegativeInt
    queue_drops: NonNegativeInt
    windows_emitted: NonNegativeInt
    windows_dropped: NonNegativeInt
    http_ok: NonNegativeInt
    http_fail: NonNegativeInt


@router.post("/ingest/coverage", status_code=204)
async def record_coverage(request: Request, payload: CaptureCoverage):
    expected = getattr(request.state, "collector_id", None)
    if expected is not None and payload.collector_id != expected:
        raise HTTPException(403, "Credential belongs to a different service")
    request.app.state.capture_coverage.append({
        **payload.model_dump(), "received_at": datetime.now(timezone.utc).isoformat()
    })


@router.get("/capture/coverage")
async def recent_coverage(request: Request, collector_id: str | None = None):
    reports = request.app.state.capture_coverage
    if collector_id is not None:
        return [row for row in reports if row["collector_id"] == collector_id]
    latest = {row["collector_id"]: row for row in reports}
    return list(latest.values())
