from __future__ import annotations

from httpx import AsyncClient

from tests.conftest import AUTH, make_run


async def test_ingest_stores_batch(client: AsyncClient) -> None:
    resp = await client.post("/v1/runs", json=make_run(), headers=AUTH)
    assert resp.status_code == 201
    body = resp.json()
    assert body["stored_results"] == 2
    assert body["duplicate"] is False


async def test_replaying_a_run_is_idempotent(client: AsyncClient) -> None:
    """The probe agent retries after a network failure; history must not double up."""
    payload = make_run()
    first = await client.post("/v1/runs", json=payload, headers=AUTH)
    second = await client.post("/v1/runs", json=payload, headers=AUTH)

    assert first.status_code == 201
    assert second.json()["duplicate"] is True
    assert second.json()["stored_results"] == 2

    nodes = (await client.get("/v1/nodes")).json()
    assert len(nodes) == 2


async def test_known_node_is_reused_across_runs(client: AsyncClient) -> None:
    await client.post("/v1/runs", json=make_run(), headers=AUTH)
    await client.post("/v1/runs", json=make_run(), headers=AUTH)

    nodes = (await client.get("/v1/nodes")).json()
    assert len(nodes) == 2

    history = (await client.get("/v1/nodes/de-01/history")).json()
    assert len(history) == 2


async def test_ingest_requires_token(client: AsyncClient) -> None:
    resp = await client.post("/v1/runs", json=make_run())
    assert resp.status_code == 401

    resp = await client.post(
        "/v1/runs", json=make_run(), headers={"Authorization": "Bearer wrong"}
    )
    assert resp.status_code == 401
