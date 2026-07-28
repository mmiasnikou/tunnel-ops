from __future__ import annotations

from httpx import AsyncClient

from tests.conftest import AUTH, make_run


async def test_status_reflects_failed_handshake(client: AsyncClient) -> None:
    await client.post("/v1/runs", json=make_run(), headers=AUTH)

    nodes = {n["name"]: n for n in (await client.get("/v1/nodes")).json()}
    assert nodes["de-01"]["up"] is True
    assert nodes["nl-02"]["up"] is False
    assert nodes["nl-02"]["failed_phase"] == "tls"


async def test_history_for_unknown_node_is_404(client: AsyncClient) -> None:
    resp = await client.get("/v1/nodes/does-not-exist/history")
    assert resp.status_code == 404
