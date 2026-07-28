from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import text

from app.db import SessionDep
from app.schemas import Health

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=Health)
async def healthz(session: SessionDep) -> Health:
    try:
        await session.execute(text("SELECT 1"))
    except Exception:
        return Health(status="degraded", database=False)
    return Health(status="ok", database=True)
