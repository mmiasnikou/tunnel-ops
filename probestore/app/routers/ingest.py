from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy import func, select, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import SessionDep
from app.models import Node, ProbeResult, ProbeRun
from app.schemas import RunAccepted, RunIn
from app.security import require_token

router = APIRouter(prefix="/v1", tags=["ingest"])


async def _resolve_nodes(
    session: AsyncSession, payload: RunIn
) -> dict[tuple[str, str], int]:
    """Upsert every (addr, sni) in the batch, return a lookup of key -> node id."""
    seen = {(r.node.addr, r.node.sni): r.node for r in payload.results}

    stmt = (
        pg_insert(Node)
        .values(
            [
                {
                    "name": n.name,
                    "addr": n.addr,
                    "sni": n.sni,
                    "provider": n.provider,
                }
                for n in seen.values()
            ]
        )
        .on_conflict_do_nothing(constraint="uq_node_addr_sni")
    )
    await session.execute(stmt)

    rows = await session.execute(
        select(Node.addr, Node.sni, Node.id).where(
            tuple_(Node.addr, Node.sni).in_(list(seen.keys()))
        )
    )
    return {(addr, sni): node_id for addr, sni, node_id in rows}


@router.post(
    "/runs",
    response_model=RunAccepted,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_token)],
)
async def ingest_run(
    payload: RunIn, session: SessionDep
) -> RunAccepted:
    """Accept one nodecheck run.

    Replaying the same run_id is a no-op: the probe agent may retry after a
    network failure without duplicating history.
    """
    existing = await session.scalar(
        select(ProbeRun).where(ProbeRun.external_id == payload.run_id)
    )
    if existing is not None:
        stored = await session.scalar(
            select(func.count(ProbeResult.id)).where(ProbeResult.run_id == existing.id)
        )
        return RunAccepted(
            run_id=payload.run_id, stored_results=stored or 0, duplicate=True
        )

    run = ProbeRun(
        external_id=payload.run_id,
        source=payload.source,
        started_at=payload.started_at,
    )
    session.add(run)
    await session.flush()

    node_ids = await _resolve_nodes(session, payload)

    session.add_all(
        [
            ProbeResult(
                node_id=node_ids[(r.node.addr, r.node.sni)],
                run_id=run.id,
                ts=r.ts,
                tcp_ok=r.tcp_ok,
                tls_ok=r.tls_ok,
                latency_ms=r.latency_ms,
                error=r.error,
                failed_phase=r.failed_phase,
            )
            for r in payload.results
        ]
    )
    await session.commit()

    return RunAccepted(run_id=payload.run_id, stored_results=len(payload.results))
