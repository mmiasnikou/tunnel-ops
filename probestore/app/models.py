from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


class Node(Base):
    """A probe target: an address plus the SNI we expect it to answer for."""

    __tablename__ = "node"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    addr: Mapped[str] = mapped_column(String(255), nullable=False)
    sni: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str | None] = mapped_column(String(128), default=None)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    results: Mapped[list[ProbeResult]] = relationship(
        back_populates="node", cascade="all, delete-orphan"
    )

    __table_args__ = (UniqueConstraint("addr", "sni", name="uq_node_addr_sni"),)


class ProbeRun(Base):
    """One invocation of nodecheck. Carries an external id so replays are idempotent."""

    __tablename__ = "probe_run"

    id: Mapped[int] = mapped_column(primary_key=True)
    external_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, unique=True
    )
    source: Mapped[str] = mapped_column(String(128), nullable=False)
    started_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    received_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    results: Mapped[list[ProbeResult]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class ProbeResult(Base):
    """Outcome of a two-phase probe (TCP connect, then TLS handshake) for one node."""

    __tablename__ = "probe_result"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(
        ForeignKey("node.id", ondelete="CASCADE"), nullable=False
    )
    run_id: Mapped[int] = mapped_column(
        ForeignKey("probe_run.id", ondelete="CASCADE"), nullable=False
    )
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    tcp_ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    tls_ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    latency_ms: Mapped[float | None] = mapped_column(Float, default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    # Added in migration 0002 — which phase failed: "tcp" | "tls" | None.
    failed_phase: Mapped[str | None] = mapped_column(String(16), default=None)

    node: Mapped[Node] = relationship(back_populates="results")
    run: Mapped[ProbeRun] = relationship(back_populates="results")

    # Postgres can scan a B-tree index backwards, so (node_id, ts) serves
    # "latest per node" and "history since X" without an explicit DESC.
    __table_args__ = (Index("ix_probe_result_node_ts", "node_id", "ts"),)
