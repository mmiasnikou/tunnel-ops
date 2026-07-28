# probestore

Stores [`nodecheck`](https://github.com/mmiasnikou/tunnel-ops) probe history and exposes it to Prometheus.

`nodecheck` answers *"is this node up right now?"* and exits. `probestore` keeps the
answers: it accepts a run over HTTP, writes it to PostgreSQL, and serves the current
state of the fleet, per-node history, and a `/metrics` endpoint Prometheus can scrape.

FastAPI · SQLAlchemy 2.0 (async, asyncpg) · Alembic · PostgreSQL 16

---

## Why it exists

A one-shot probe tells you nothing about *patterns*. When a provider starts getting
its IP ranges filtered, you don't see a single hard failure — you see the TLS phase
degrading on a handful of nodes over a couple of days. That is only visible if the
results are stored and graphed, which is what this service is for.

## Endpoints

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `POST` | `/v1/runs` | bearer | Ingest one nodecheck run (batch) |
| `GET` | `/v1/nodes` | — | Latest state of every known node |
| `GET` | `/v1/nodes/{name}/history?since=&limit=` | — | History for one node |
| `GET` | `/metrics` | — | Prometheus text exposition |
| `GET` | `/healthz` | — | Liveness + database reachability |

### Ingest contract

```json
{
  "run_id": "0f0b1b6e-6a3f-4a5b-9d0c-2f2f2f2f2f2f",
  "source": "cron@monitor-01",
  "started_at": "2026-07-28T06:00:00Z",
  "results": [
    {
      "node": {"name": "de-01", "addr": "203.0.113.10:443",
               "sni": "www.microsoft.com", "provider": "hetzner"},
      "ts": "2026-07-28T06:00:01Z",
      "tcp_ok": true, "tls_ok": true, "latency_ms": 42.5
    }
  ]
}
```

`run_id` makes ingestion **idempotent**. A probe agent that loses the network mid-POST
can retry the identical payload without duplicating history — the second call returns
`duplicate: true` and stores nothing.

Nodes are identified by `(addr, sni)`, upserted on first sight. The same address probed
with a different expected SNI is a different target, because that is exactly the
distinction a Reality-style handshake turns on.

### Exposed metrics

```
nodecheck_node_up{node,addr,sni,provider}                  1 | 0
nodecheck_handshake_seconds{node,addr,sni,provider}        last successful probe
nodecheck_last_check_age_seconds{node,addr,sni,provider}   staleness of the datapoint
```

`/metrics` reports what the last run observed — it does not probe on scrape. The age
gauge is what lets you alert on *"the prober itself stopped reporting"*, which is a
different and more dangerous failure than a node going down.

## Quickstart

```bash
cp .env.example .env          # set PROBESTORE_API_TOKEN
docker compose up -d --build  # postgres + alembic upgrade head + app on :8080
curl -s localhost:8080/healthz
```

Local, against your own Postgres:

```bash
pip install -e ".[dev]"
alembic upgrade head
make dev            # uvicorn on :8080, autoreload
make lint test
```

## Schema

```
node          (id, name, addr, sni, provider, created_at)   unique (addr, sni)
probe_run     (id, external_id, source, started_at, received_at)
probe_result  (id, node_id, run_id, ts, tcp_ok, tls_ok, latency_ms, error, failed_phase)
              index (node_id, ts)
```

Two migrations: `0001` creates the schema, `0002` adds `failed_phase` plus the
`(node_id, ts)` index and backfills the new column from existing rows. Both
`upgrade` and `downgrade` are exercised in CI against a clean database.

## Operational notes

- The container runs as an unprivileged user; migrations run as a separate
  compose service that must complete before the app starts.
- `POST /v1/runs` is the only authenticated route. Read endpoints are open on the
  assumption they sit behind a reverse proxy — put Traefik in front and restrict
  `/metrics` to the Prometheus source if the deployment is public.
- Retention is not implemented. `probe_result` grows linearly with
  `nodes × runs`; at one run every five minutes across fifteen nodes that is
  roughly 1.6M rows a year, which Postgres handles without partitioning. Add a
  cron `DELETE ... WHERE ts < now() - interval '90 days'` if that matters.

## License

MIT
