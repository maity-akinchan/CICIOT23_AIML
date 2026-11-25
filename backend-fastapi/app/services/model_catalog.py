"""Discover local model artifacts and keep the active engine in memory."""

import asyncio
import logging
from pathlib import Path

from fastapi import HTTPException
from starlette.concurrency import run_in_threadpool

from app.services.inference import InferenceEngine

logger = logging.getLogger(__name__)
DEFAULT_MODEL = 'ciciot_22f_xgb'


class ModelCatalog:
    def __init__(self, directory: Path):
        self.directory = directory
        self.active = InferenceEngine(directory / f'{DEFAULT_MODEL}.joblib')
        self.active.error = f'No compatible .joblib model found in {directory}'
        self._selection_lock = asyncio.Lock()

    def paths(self) -> dict[str, Path]:
        return {
            path.stem: path
            for path in sorted(self.directory.iterdir())
            if path.suffix.lower() == '.joblib' and path.is_file() and not path.is_symlink()
        } if self.directory.is_dir() else {}

    def load_default(self):
        paths = self.paths()
        # Keep the original XGBoost artifact as the startup choice when present.
        for model_id in sorted(paths, key=lambda name: (name != DEFAULT_MODEL, name)):
            try:
                self.active = self._load(paths[model_id])
                return
            except Exception:
                logger.exception('Could not load model %s', model_id)

    @staticmethod
    def _load(path: Path) -> InferenceEngine:
        engine = InferenceEngine(path)
        engine.load()
        return engine

    @staticmethod
    def resolve_id(model_id: str) -> str:
        if model_id in {'xgb', 'rf', 'lr'}:
            return f'ciciot_22f_{model_id}'
        return model_id

    async def select(self, model_id: str) -> InferenceEngine:
        async with self._selection_lock:
            paths = self.paths()
            resolved = model_id if model_id in paths else self.resolve_id(model_id)
            current = self.active
            if current.is_loaded and current.model_id == resolved:
                return current
            path = paths.get(resolved)
            if path is None:
                if model_id in {'xgb', 'rf', 'lr'} and not current.is_loaded:
                    raise HTTPException(503, current.error)
                raise HTTPException(404, 'Model not found')
            try:
                engine = await run_in_threadpool(self._load, path)
            except Exception as exc:
                logger.exception('Could not load model %s', resolved)
                raise HTTPException(422, f'Could not load {resolved}: {exc}') from exc
            self.active = engine
            return engine
