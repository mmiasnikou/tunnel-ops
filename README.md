# tunnel-ops

Operational tooling for running fleets of tunnel exit nodes — WireGuard,
AmneziaWG, VLESS/Reality and friends.

Small, dependency-free Go binaries that answer operational questions about a
distributed node fleet. Standard library only, static binaries, no runtime.

| Binary | What it does |
| --- | --- |
| [`nodecheck`](cmd/nodecheck) | Concurrently probes node reachability in two phases and reports JSON or Prometheus metrics |

---

## Why two phases

A health check that returns a single boolean tells you almost nothing. A node
whose TCP port is open is not necessarily a node that works.

`nodecheck` deliberately splits the probe:

1. **TCP connect** — is the port open at all?
2. **TLS handshake with the expected SNI** — for VLESS/Reality this is the
   masquerade site the node is supposed to impersonate.

The interesting state is the one in between. **TCP succeeds, TLS fails** means
the port is listening but Reality is misconfigured, the certificate is wrong,
or the traffic is being intercepted. A single boolean would collapse that into
"down" and throw away the diagnosis.

Each phase is timed separately and exported as its own metric. A node whose
handshake latency has quietly doubled is still "up" and is telling you
something a green light never will.

## Install

```bash
git clone https://github.com/mmiasnikou/tunnel-ops
cd tunnel-ops
make build          # binaries land in bin/
make install        # or copy them to /usr/local/bin
```

Prebuilt binaries for linux, windows and darwin (amd64 + arm64) are attached
to each [release](../../releases).

Building by hand:

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o bin/nodecheck ./cmd/nodecheck
```

`CGO_ENABLED=0` produces a static binary with no libc dependency — it will run
in a `scratch` container.

## Usage

```bash
nodecheck -targets targets.json                    # JSON output
nodecheck -targets targets.json -format prom       # Prometheus text format
nodecheck -targets targets.json -timeout 3s -concurrency 64
nodecheck -version
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `-targets` | `targets.json` | JSON file listing the nodes |
| `-timeout` | `5s` | timeout applied to **each phase** separately |
| `-concurrency` | `32` | maximum probes in flight at once |
| `-format` | `json` | `json` or `prom` |
| `-version` | | print version and exit |

**Exit codes:** `0` all nodes healthy, `1` at least one node down (or a bad
targets file), `2` invalid arguments. Suitable for cron and alerting directly.

### Target file

See [`examples/targets.json`](examples/targets.json).

```json
[
  { "name": "de-fra-01", "addr": "1.2.3.4:443", "sni": "www.microsoft.com", "region": "de" }
]
```

`sni` is the masquerade host the node should present. If omitted, the host part
of `addr` is used.

## Metrics

```
vpnnode_up{node,region}                     1 / 0
vpnnode_tcp_connect_seconds{node,region}
vpnnode_tls_handshake_seconds{node,region}
vpnnode_cert_match{node,region}             1 / 0
```

Labels are deliberately restricted to `node` and `region`, both of bounded
cardinality. Do not add `user_id`, `session_id` or `host:port` — that is the
direct route to a cardinality explosion and a dead metrics store.

### Collecting

**Textfile collector** (simplest — reuse an existing `node_exporter`):

```bash
*/2 * * * * nodecheck -targets /etc/tunnel-ops/targets.json -format prom \
  > /var/lib/node_exporter/textfile/nodecheck.prom.$$ \
  && mv /var/lib/node_exporter/textfile/nodecheck.prom.$$ \
        /var/lib/node_exporter/textfile/nodecheck.prom
```

Writing to a temporary file and renaming it is not decoration: `mv` within a
filesystem is atomic, so the collector never reads a half-written file.

**systemd timer** — a `oneshot` `.service` plus a `.timer` with
`OnCalendar=*:0/2`, if you prefer timers to cron.

## Limitations

`cert_match` compares the presented certificate against the SNI that was
requested. It verifies the chain against the system trust store, but it cannot
distinguish an honest node from one behind an intercepting middlebox whose CA
is already trusted by the host running the probe. For a fleet whose whole
purpose is resisting interception, that gap matters. Pinning an expected
certificate fingerprint per target closes it — see the roadmap.

## Roadmap

- Certificate fingerprint pinning per target, to detect interception
- `/metrics` HTTP endpoint for pull-based scraping instead of one-shot runs
- WireGuard/AmneziaWG probe: UDP handshake instead of TLS
- Probes originating from inside filtered networks — the metric that actually
  matters, since a node can be perfectly alive from the outside and unreachable
  from where the users are
- Per-ASN IP survival history: which hosting providers keep addresses longest

## Development

```bash
make help     # list targets
make          # fmt, vet, test, build
make race     # tests under the race detector
make cover    # coverage report
make dist     # cross-compile everything + SHA256SUMS
```

CI runs `gofmt`, `go vet`, `go test -race` with coverage, and verifies cross
compilation for all five platforms on every push and pull request. Pushing a
`v*` tag builds every binary for every platform and attaches them with
`SHA256SUMS` to a GitHub release.

Adding a tool means creating `cmd/<name>/`. The Makefile and both workflows
discover it automatically; neither needs editing.

## License

MIT — see [LICENSE](LICENSE).
