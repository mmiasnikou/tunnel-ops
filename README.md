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

The split generalises past TLS. Every protocol has a reachability phase — did
anything answer at all — and a confirmation phase — was the answer really the
protocol we expect. Which pair of phases a node gets is decided by its `proto`
(see [Probers](#probers)); the reason for having two of them is the same one.

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
| `-push-url` | — | probestore ingest endpoint; when set, the batch is also stored |
| `-push-timeout` | `10s` | timeout for the push request |
| `-push-source` | `nodecheck@<hostname>` | source label recorded with the run |
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

A bad targets file is rejected before any probing starts — an unknown `proto`,
or a `params` object a prober cannot make sense of, fails the whole run with
exit `1`. A typo in the config should not be reported as an outage, and it
must not reach probestore as one either.

What is *not* pre-checked is anything the probe itself reports better: an
address with no port, an unresolvable host. Those come back as ordinary failed
probes, so one bad line does not suppress the results for the rest of the fleet.

### Probers

A target picks its check with `proto`. Omitting it means `tls` — every targets
file written before probers existed keeps working untouched.

| `proto` | Phases | What it checks |
| --- | --- | --- |
| `tls` (default) | `tcp`, `tls` | TCP connect, then a TLS handshake with the expected SNI |
| `udp` | `udp`, `response` | sends a datagram, accepts any reply as proof of life |

```json
[
  { "name": "de-fra-01", "addr": "1.2.3.4:443", "sni": "www.microsoft.com", "region": "de" },
  { "name": "de-fra-01-wg", "addr": "1.2.3.4:51820", "region": "de", "proto": "udp",
    "params": { "payload_hex": "01000000", "attempts": 3 } }
]
```

`udp` params — all optional:

| Field | Default | Meaning |
| --- | --- | --- |
| `payload` | a single `0x00` byte | bytes to send, as literal text |
| `payload_hex` | — | the same, hex-encoded, for non-printable payloads |
| `attempts` | `3` | total datagrams sent before calling the node silent |

The attempts share the phase timeout rather than multiplying it, and exist
because UDP drops packets: one lost datagram is not an outage. A definitive
answer stops the retries early — an ICMP port-unreachable means there is no
listener, and asking again will not change that.

Be honest about what `udp` proves. Its first phase is weak: `net.Dial` on UDP
sends nothing and a write only hands the datagram to the kernel, so that phase
failing is nearly always a local configuration problem. The signal is in the
second phase — something answered, or nothing did. What it cannot tell you is
whether the thing that answered speaks the protocol you expect; that needs a
real handshake, which is what the WireGuard/AmneziaWG probers on the roadmap
will add.

`params` are input configuration and are never echoed back into the output — a
result gets printed, piped into a textfile collector, logged and pasted into
tickets, and prober settings have no diagnostic value on any of those surfaces.
Secrets still do not belong there, for the same reason the push token is
environment-only: a targets file gets copied between hosts and committed.

Protocol-specific fields are omitted from the output rather than reported as
zero. A `udp` result carries no `tcp_ok`, `tls_seconds` or `cert_match` keys at
all, because a phase that was never run is a different fact from one that was
run and failed. A TCP+TLS result still reports every one of those fields
exactly as it always did, including as zeroes for a phase the probe never
reached.

## Storing history

A single probe answers *"is the node up right now?"*. Point `-push-url` at a
[probestore](probestore/) instance and the answers accumulate instead:

```bash
export NODECHECK_PUSH_TOKEN=...        # never pass the token as a flag: argv is world-readable
nodecheck -targets targets.json -push-url https://probes.example.com/v1/runs
```

Each run carries a generated `run_id`, and probestore keys ingestion on it, so
a push retried after a network failure is stored exactly once. The retry loop
(immediate, then 1s, then 3s) exists because a prober that gives up on the
first refused connection loses precisely the outage it was built to record.
Rejected credentials are not retried — a 401 will be a 401 next time too.

Exit codes: `1` a node is down, `2` bad usage, `3` the push failed. The last
one is deliberately distinct: healthy nodes plus a prober that cannot report
is a different alert from a node going dark.

**Only `tls` results are pushed.** The ingest payload's `tcp_ok`/`tls_ok` are
required booleans, so a `udp` result has no honest way to fill them — shipping
one would record `tcp_ok: false, failed_phase: "tcp"` as history for a node
that is perfectly healthy. A gap is better than a stored lie, so those results
are dropped from the batch and only appear on stdout and in `/metrics`.

Carrying them needs both sides changed together: a `proto` field and nullable
phase booleans in the payload, and probestore's `node` uniqueness reconsidered
— it keys on `(addr, sni)`, and UDP targets have no SNI, so two protocols on
one address would collide into a single node. That is a separate, coordinated
change.

## Metrics

```
vpnnode_up{node,region}                     1 / 0
vpnnode_tcp_connect_seconds{node,region}
vpnnode_tls_handshake_seconds{node,region}
vpnnode_cert_match{node,region}             1 / 0
```

Labels are deliberately restricted to `node` and `region`, both of bounded
cardinality. Do not add `user_id`, `session_id` or `host:port` — that is the
direct route to a cardinality explosion and a dead metrics store. `proto` is
not a label either: it would be bounded, but adding it changes the identity of
every existing series and breaks the dashboards and recording rules already
built on them.

`vpnnode_up` covers every node whatever its protocol. The phase metrics carry
a sample only for the nodes that actually ran that phase, so a `udp` node
appears in `vpnnode_up` and nowhere else — publishing `0.0000` for a handshake
it never performed would feed an invented number to anything computing an
average. The metric families are always declared, so the shape of a scrape
does not change with the composition of the fleet.

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
- WireGuard/AmneziaWG probers: a real UDP handshake instead of "any reply".
  Both need Curve25519 + BLAKE2s + ChaCha20-Poly1305, and only the first of
  those is in the standard library — so this one costs either a `x/crypto`
  dependency or a vendored implementation, and that trade is worth making
  deliberately rather than by accident
- Push non-`tls` results to probestore (needs the coordinated ingest change
  described under [Storing history](#storing-history))
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
