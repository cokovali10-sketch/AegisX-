# AegisX Security Suite — Architecture

## 1. Design goals

1. **Defense in depth** — detection at the network edge (SYN recon + six
   protocol decoys), host layer (Rayon FIM + eBPF exec tracing + YARA memory
   scan), and content layer (AI phishing analysis + anomaly detection).
2. **Closed detection → response loop** — an attacker event is not just
   recorded; it is scored, OSINT-enriched, and (above a threshold) actively
   mitigated by auto-banning the offending IP via nftables/iptables.
3. **Polyglot with one contract** — every module speaks the same Protobuf IDL
   (`proto/aegisx.proto`, 4 services); no bespoke wire formats between
   languages.
4. **Zero-trust defaults** — FIM baseline is authoritative until an operator
   re-seeds; decoys never trust a captured value for enforcement.
5. **Graceful degradation** — missing OSINT keys, ChromaDB, scikit-learn, a
   down gateway, or missing kernel capabilities never drops a captured event;
   every integration is optional and has a fallback.
6. **Operable as code** — single `docker compose` file with kernel
   capabilities, health checks, env-driven config.

## 2. Inter-module data flows

### 2.1 Decoy → AI → mitigate → UI (XDR/SOAR kill chain)

```
ShadowPot (Go)
  SSH/HTTP/MySQL/Redis/Pg/Telnet ──► event.Bus ──► gRPC StreamHoneypotEvents ──► PhishGuard
       │                                                                       │
       │ payload → internal/pcap (writes .pcap)          score + OSINT enrich  │
       │                                                       ▼               │
       │                                              ThreatIntel (multi-feed) │
       │                                              AnomalyDetector (ML)     │
       │                                                       │               │
       │                                                       ▼               │
       │                                          PlaybookEngine (SOAR)        │
       │                       threshold met? e.g. playbook `ban-offender`     │
       │                                                       │               │
       └──◄── gRPC Command(migrate_ban_ip) ====================┘               │
                    cmdserver → nftables / iptables DROP                       │
       ═══════════════════════  IP auto-banned  ══════════════════════════════ │
                                                              WS /events push  │
                                                      ┌─────────────────────┘
                                                      ▼
                                           Control Center (attack globe / feed)
```

Every captured event is scored (`ScoringResult`), enriched with threat-intel
reputation, recorded to PCAP, and broadcast to the UI. When the ban window
threshold is crossed, PhishGuard issues a `mitigate_ban_ip` command to
ShadowPot's command plane (`:50053`), which enforces a firewall source-IP drop.

### 2.2 Recon → AI → UI

`Sentinel-Recon` streams discovered `OpenPort`s (SYN or connect mode) via
client-streaming `SubmitScan`; PhishGuard acknowledges with a `ScanResponse`
and forwards observations to the dashboard.

### 2.3 FIM + eBPF exec + YARA memory

`zerotrust-fim` (`aegisx-fim`) computes a Rayon-parallel BLAKE3 baseline and
emits normalized `FimEvent`s over a Unix domain socket (JSON-lines). With the
`ebpf` feature it attaches an aya `sys_enter_execve` tracepoint (falling back
to `/proc` scanning when the kernel/bpffs disallows it); with the `yara`
feature it scans process memory with a YARA rule set. `phishguard/app/fim_bridge.py`
relays these frames as structured telemetry.

## 3. Threat model

| Asset | Trust boundary | Assumed attacker |
|---|---|---|
| Decoy listeners | 0.0.0.0:22/2222/8080/3306/5432/6379 | internet botnets, credential stuffers, scanners |
| SYN scanner | CAP_NET_RAW | none (operator-deployed) |
| gRPC gateway | docker network | compromised decoy container |
| FIM baseline DB | root-owned volume | post-exploitation persistence attempts |
| WebSocket feed | host loopback | none (UI only) |
| SOAR command plane | gRPC :50053 (internal net) | compromised PhishGuard |

Controls:
- Decoys sanitize captured payloads (printable-ASCII projection, 2 KB cap).
- gRPC is internal-network only; the UI WebSocket binds to the compose bridge.
- `zerotrust-fim` runs `privileged` only for eBPF tracepoint +
  `/proc` anomaly scanning; the SQLite baseline is WAL-mode, single-writer.
- The firewall blocker refuses to run over the host network without explicit
  `BAN_BACKEND`; default `auto` picks nftables → iptables → journal (dry-run).

## 4. Concurrency & performance

- **Sentinel-Recon**: bounded semaphore worker pool (default `NumCPU*4`, min
  256), raw-socket SYN correlation via seq→probe map, adaptive `Pacer` that
  observes RTT/loss against a default 1000 pps budget
  to throttle `maxpps` and avoid self-exhaustion; results channel buffers 4096
  so backpressure never stalls the pool; graceful fallback SYN→connect.
- **ShadowPot**: one goroutine per connection, 1024-deep pub/sub bus with
  drop-on-slow-consumer; gRPC streamer reconnects with exponential backoff
  (500ms → 30s); PCAP writer is buffer-gated; blocker global per IP.
- **ZeroTrust FIM**: Rayon thread pool parallel hash across files; `DashMap`
  sharded in-memory baseline for lock-free lookup; SQLite writes funnel through
  a single thread; 1 MiB streaming hash buffers; BLAKE3 chosen for parallelism
  on large trees and future Merkle-subtree proofs.
- **PhishGuard**: async FastAPI + `grpc.aio`; per-event scoring is pure CPU;
  OSINT lookups are async, fan-out across feeds, and TTL-cached.

## 5. Threat-intel aggregation & scoring (PhishGuard)

`ThreatIntelAggregator` fans out across AbuseIPDB, VirusTotal, OTX, and
ThreatFox both sync and async, applies per-feed weighting (catches rate-limit
fallbacks) and blends a normalized `0..100` reputation score.

**ML anomaly detection**: `AnomalyDetector` fits an IsolationForest over
per-IP feature vectors (score age, category mix, event rate); when
scikit-learn is unavailable it transparently falls back to a heuristic
z-score model. This is used to rank low-confidence events for SOAR review.

**SOAR playbook engine**: YAML playbooks (`playbooks/default.yaml`) declare
conditions, actions (`mitigate_ban_ip`, enrichment, notification) and
confidence thresholds. The visitor is the **safe ast evaluator** — the playbook
never executes raw code.

Example mitigation flow: 3+ malicious events from one IP within 300 s →
confidence High → `mitigate_ban_ip {backend: nftables}` over the SOAR plane.

## 6. gRPC contract (`proto/aegisx.proto`)

| Service | Key methods |
|---|---|
| `AegisX` | `StreamHoneypotEvents`, `SubmitScan` |
| `ThreatIntelService` | `Query`, `Report`, `Tag`, `IndicatorSubscription`, `IndicatorUpdate` |
| `eBPFStreamer` | `StreamExecEvents` |
| `SOARPlaybookService` | `List`, `Status`, `Run` (fire-and-forget) |

Docker/new builds regenerate Go and Python bindings automatically via
`scripts/gen-proto.ps1` / `Makefile`.

## 7. Extending the suite

- **New decoy protocol**: implement a listener in
  `shadowpot/internal/listener`, publish a normalized `event.Event`; the rest
  of the pipeline is protocol-agnostic.
- **New OSINT feed**: add a provider in `phishguard/app/intel/aggregator.py`
  returning an `IntelResult`; no upstream changes.
- **New SOAR action**: add a `PlaybookAction` kind in
  `phishguard/app/soar/playbook.py` and a matching guard in the gRPC server.
- **New UI panel**: add a screen under `control-center/.../ui/screens` and
  consume an existing `StateFlow` from `AegisXState`.
- **FFI consumers**: `cargo build --features ffi` exports `aegis_hash_file`,
  `aegis_verify_file`, `aegis_snapshot_json`, `aegis_hash_bytes`,
  `aegis_version`.

## 8. Operations

- Logs: JSON structured output everywhere (`RUST_LOG`, shop logging).
- Telemetry: `TelemetryFrame`s carry per-node counters; the UI renders flows
  and sparklines; add Prometheus export by tapping the same state.
- Backup: `aegisx-data` volume holds Chroma + FIM baselines; PCAPs in
  `report_dir` are retained on the compose volume.
- Blocking is observable: `SHADOWPOT_BAN_BACKEND=journal` logs every intended
  `nftables`/`iptables` command for dry-run audits.