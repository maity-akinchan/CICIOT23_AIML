from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.routers import ingest, websockets, analytics, incidents
from app.database import initialize
from app.services.incident_manager import IncidentManager
from app.services.inference import InferenceEngine
from app.services.ws_manager import manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    import os
    import asyncio
    app.state.ingest_lock = asyncio.Lock()
    model_dir = Path(os.getenv('MODEL_DIR', str(Path(__file__).resolve().parents[2] / 'ml/artifacts')))
    app.state.db_engine, app.state.sessions = initialize()
    app.state.incidents = IncidentManager()
    from app.services.auto_blocker import AutoBlocker
    app.state.auto_blocker = AutoBlocker()
    app.state.registry = {}
    for model_id in ('xgb','rf','lr'):
        candidate = InferenceEngine(model_dir / f'ciciot_22f_{model_id}.joblib')
        try:
            candidate.load()
        except Exception as exc:
            candidate.error = str(exc)
            logger.warning('Model %s unavailable: %s', model_id, exc)
        app.state.registry[model_id] = candidate
    app.state.inference_engine = app.state.registry['xgb']
    app.state.ws_manager = manager
    app.state.replay = dict(is_running=False, speed_fps=10, rows_streamed=0)
    app.state.replay_task = None
    yield
    if app.state.replay_task:
        app.state.replay_task.cancel()
        import asyncio
        try: await app.state.replay_task
        except asyncio.CancelledError: pass
    app.state.db_engine.dispose()


app = FastAPI(title="CICIoT23 Sentinel", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=False,
                   allow_methods=["*"], allow_headers=["*"])


@app.exception_handler(Exception)
async def unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled request error: %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "internal server error"})


@app.get("/health")
async def health() -> dict[str, object]:
    engine = app.state.inference_engine
    return {"status": "ok", "model_loaded": engine.is_loaded,
            "is_bootstrap_model": False, "reason": engine.error,
            "allowed_contracts":[__import__('sentinel_ml.approximation',fromlist=['CONTRACT_ID']).CONTRACT_ID] if engine.is_loaded and engine.bundle.get('is_legacy') else [],
            "allowed_input_modes":['PCAP_REPLAY','PCAP_UPLOAD','LIVE_INTERFACE'],
            "contract_hash":__import__('sentinel_ml.approximation',fromlist=['CONTRACT_HASH']).CONTRACT_HASH,
            "packet_compatibility":"approximate", "observe_only":True}


app.include_router(ingest.router, prefix="/api/v1")


app.include_router(websockets.router)

app.include_router(analytics.router, prefix="/api/v1")
app.include_router(incidents.router, prefix="/api/v1")
from app.routers import devices
app.include_router(devices.router)
from app.routers import pcap
app.include_router(pcap.router,prefix='/api/v1')

from app.routers import replay
app.include_router(replay.router,prefix="/api/v1")

@app.get('/api/v1/contracts/current')
def contract():
    from sentinel_ml.csv_contract import SPEC, CONTRACT_HASH
    from sentinel_ml.approximation import SPEC as PACKET_SPEC, CONTRACT_HASH as PACKET_HASH
    engine=app.state.inference_engine
    return {'csv_specification':SPEC,'csv_contract_hash':CONTRACT_HASH,
            'packet_specification':PACKET_SPEC,'packet_contract_hash':PACKET_HASH,
            'active_model_contract':engine.bundle['contract_id'] if engine.is_loaded else None}

from app.security import authorize
app.middleware("http")(authorize)
from app.routers import downloads
app.include_router(downloads.router,prefix="/api/v1")

from app.routers import services
app.include_router(services.router,prefix='/api/v1')
