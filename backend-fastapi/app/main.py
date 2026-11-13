from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.routers import ingest, websockets
from app.services.inference import InferenceEngine
from app.services.ws_manager import manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    artifact = Path(__file__).resolve().parents[2] / "ml" / "artifacts" / "ciciot_22f_xgb.joblib"
    engine = InferenceEngine(artifact)
    try:
        engine.load()
    except Exception:
        logger.exception("Unable to load the configured ML artifact")
        raise
    app.state.inference_engine = engine
    app.state.ws_manager = manager
    yield


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
            "is_bootstrap_model": engine.is_bootstrap_model}


app.include_router(ingest.router, prefix="/api/v1")


app.include_router(websockets.router)
