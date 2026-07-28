from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient

os.environ.setdefault(
    "PROBESTORE_DATABASE_URL",
    "postgresql+asyncpg://probestore:probestore@localhost:5432/probestore",
)
os.environ.setdefault("PROBESTORE_API_TOKEN", "test-token")

from app.db import dispose_engine, get_engine  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Base  # noqa: E402

TOKEN = os.environ["PROBESTORE_API_TOKEN"]
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
async def clean_db() -> AsyncIterator[None]:
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    try:
        yield
    finally:
        # asyncpg binds connections to the loop that created them, and
        # pytest-asyncio gives each test a fresh loop. Without this the next
        # test checks out a connection belonging to a closed loop.
        await dispose_engine()


@pytest.fixture
async def client(clean_db: None) -> AsyncIterator[AsyncClient]:
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


def make_run(**overrides) -> dict:
    payload = {
        "run_id": str(uuid.uuid4()),
        "source": "pytest",
        "started_at": "2026-07-28T06:00:00Z",
        "results": [
            {
                "node": {
                    "name": "de-01",
                    "addr": "203.0.113.10:443",
                    "sni": "www.microsoft.com",
                    "provider": "hetzner",
                },
                "ts": "2026-07-28T06:00:01Z",
                "tcp_ok": True,
                "tls_ok": True,
                "latency_ms": 42.5,
            },
            {
                "node": {
                    "name": "nl-02",
                    "addr": "203.0.113.11:443",
                    "sni": "www.microsoft.com",
                    "provider": "vultr",
                },
                "ts": "2026-07-28T06:00:02Z",
                "tcp_ok": True,
                "tls_ok": False,
                "error": "tls: handshake failure",
                "failed_phase": "tls",
            },
        ],
    }
    payload.update(overrides)
    return payload
