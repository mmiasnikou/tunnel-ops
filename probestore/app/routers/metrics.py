from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Response

from app.db import SessionDep
from app.routers.nodes import latest_per_node_stmt

router = APIRouter(tags=["metrics"])

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(node) -> str:
    parts = [
        f'node="{_escape(node.name)}"',
        f'addr="{_escape(node.addr)}"',
        f'sni="{_escape(node.sni)}"',
        f'provider="{_escape(node.provider or "")}"',
    ]
    return "{" + ",".join(parts) + "}"


@router.get("/metrics", response_class=Response)
async def metrics(session: SessionDep) -> Response:
    """Expose the latest known state of every node.

    Deliberately not a per-scrape probe: this reports what the last nodecheck
    run observed, plus how stale that observation is.
    """
    rows = (await session.execute(latest_per_node_stmt())).all()
    now = dt.datetime.now(dt.UTC)

    lines: list[str] = [
        "# HELP nodecheck_node_up Node passed both TCP connect and TLS handshake.",
        "# TYPE nodecheck_node_up gauge",
    ]
    for node, result in rows:
        up = 1 if (result.tcp_ok and result.tls_ok) else 0
        lines.append(f"nodecheck_node_up{_labels(node)} {up}")

    lines += [
        "# HELP nodecheck_handshake_seconds Duration of the last successful probe.",
        "# TYPE nodecheck_handshake_seconds gauge",
    ]
    for node, result in rows:
        if result.latency_ms is not None:
            lines.append(
                f"nodecheck_handshake_seconds{_labels(node)} {result.latency_ms / 1000:.6f}"
            )

    lines += [
        "# HELP nodecheck_last_check_age_seconds Age of the most recent probe result.",
        "# TYPE nodecheck_last_check_age_seconds gauge",
    ]
    for node, result in rows:
        ts = result.ts
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=dt.UTC)
        lines.append(
            f"nodecheck_last_check_age_seconds{_labels(node)} {(now - ts).total_seconds():.1f}"
        )

    return Response(content="\n".join(lines) + "\n", media_type=CONTENT_TYPE)
