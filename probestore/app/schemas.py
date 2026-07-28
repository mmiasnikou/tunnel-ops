from __future__ import annotations

import datetime as dt
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

FailedPhase = Literal["tcp", "tls"]


class NodeRef(BaseModel):
    """Identity of a probe target as reported by nodecheck."""

    name: str = Field(max_length=128)
    addr: str = Field(max_length=255)
    sni: str = Field(max_length=255)
    provider: str | None = Field(default=None, max_length=128)


class ResultIn(BaseModel):
    node: NodeRef
    ts: dt.datetime
    tcp_ok: bool
    tls_ok: bool
    latency_ms: float | None = None
    error: str | None = None
    failed_phase: FailedPhase | None = None


class RunIn(BaseModel):
    """Batch posted by `nodecheck --push-url`."""

    run_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    source: str = Field(max_length=128)
    started_at: dt.datetime
    results: list[ResultIn] = Field(min_length=1)


class RunAccepted(BaseModel):
    run_id: uuid.UUID
    stored_results: int
    duplicate: bool = False


class NodeStatus(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    addr: str
    sni: str
    provider: str | None
    ts: dt.datetime
    up: bool
    tcp_ok: bool
    tls_ok: bool
    latency_ms: float | None
    error: str | None
    failed_phase: FailedPhase | None


class ResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ts: dt.datetime
    tcp_ok: bool
    tls_ok: bool
    latency_ms: float | None
    error: str | None
    failed_phase: FailedPhase | None


class Health(BaseModel):
    status: Literal["ok", "degraded"]
    database: bool
