from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.db import dispose_engine
from app.routers import health, ingest, metrics, nodes


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    yield
    await dispose_engine()


def create_app() -> FastAPI:
    app = FastAPI(
        title="probestore",
        summary="Stores nodecheck probe history and exposes it to Prometheus.",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(health.router)
    app.include_router(metrics.router)
    app.include_router(ingest.router)
    app.include_router(nodes.router)
    return app


app = create_app()
