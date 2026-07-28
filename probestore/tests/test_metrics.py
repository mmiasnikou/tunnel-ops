from __future__ import annotations

from httpx import AsyncClient

from tests.conftest import AUTH, make_run


async def test_metrics_exposition(client: AsyncClient) -> None:
    await client.post("/v1/runs", json=make_run(), headers=AUTH)

    resp = await client.get("/metrics")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")

    body = resp.text
    assert "# TYPE nodecheck_node_up gauge" in body
    assert 'nodecheck_node_up{node="de-01",addr="203.0.113.10:443"' in body
    # the node whose TLS handshake failed must expose 0, not be omitted
    down = [
        line
        for line in body.splitlines()
        if 'node="nl-02"' in line and line.startswith("nodecheck_node_up")
    ]
    assert down[0].endswith(" 0")
    assert "nodecheck_last_check_age_seconds" in body
