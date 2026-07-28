from __future__ import annotations

import datetime as dt
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import select

from app.db import SessionDep
from app.models import Node, ProbeResult
from app.schemas import NodeStatus, ResultOut

router = APIRouter(prefix="/v1/nodes", tags=["nodes"])


def latest_per_node_stmt():
    """DISTINCT ON is the cheap way to get the newest row per node in Postgres."""
    return (
        select(Node, ProbeResult)
        .join(ProbeResult, ProbeResult.node_id == Node.id)
        .distinct(Node.id)
        .order_by(Node.id, ProbeResult.ts.desc())
    )


@router.get("", response_model=list[NodeStatus])
async def list_nodes(session: SessionDep) -> list[NodeStatus]:
    rows = await session.execute(latest_per_node_stmt())
    return [
        NodeStatus(
            name=node.name,
            addr=node.addr,
            sni=node.sni,
            provider=node.provider,
            ts=result.ts,
            up=result.tcp_ok and result.tls_ok,
            tcp_ok=result.tcp_ok,
            tls_ok=result.tls_ok,
            latency_ms=result.latency_ms,
            error=result.error,
            failed_phase=result.failed_phase,
        )
        for node, result in rows.all()
    ]


@router.get("/{name}/history", response_model=list[ResultOut])
async def node_history(
    name: str,
    session: SessionDep,
    since: Annotated[dt.datetime | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=5000)] = 200,
) -> list[ResultOut]:
    node = await session.scalar(select(Node).where(Node.name == name).limit(1))
    if node is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"unknown node: {name}"
        )

    stmt = (
        select(ProbeResult)
        .where(ProbeResult.node_id == node.id)
        .order_by(ProbeResult.ts.desc())
        .limit(limit)
    )
    if since is not None:
        stmt = stmt.where(ProbeResult.ts >= since)

    rows = await session.scalars(stmt)
    return [ResultOut.model_validate(r) for r in rows]
