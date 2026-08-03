# AegisX Security Suite

![CI](https://github.com/anomalyco/AegisX/actions/workflows/ci.yml/badge.svg)
![Go](https://img.shields.io/badge/Go-1.22-00ADD8)
![Python](https://img.shields.io/badge/Python-3.12-3776AB)
![Rust](https://img.shields.io/badge/Rust%20(ebpf+yara+ffi)-stable-DEA584)
![Kotlin](https://img.shields.io/badge/Kotlin%20Compose-Desktop-7F52FF)
![gRPC/Protobuf](https://img.shields.io/badge/gRPC-Protobuf-4285F4)
![License](https://img.shields.io/badge/License-Apache--2.0-blue)

**AegisX is a multi-language, autonomous XDR (Extended Detection & Response) /
SOAR (Security Orchestration, Automation & Response) platform.** It unifies
raw-socket network scanning, active multi-protocol decoys, zero-trust
file-integrity monitoring with kernel-level exec tracing, AI-driven threat
intelligence and automated mitigation playbooks — all speaking a single
gRPC/Protobuf contract.

> **Legal note:** AegisX is a *defensive* toolset. Scan and decoy only networks
> and systems you own or are explicitly authorized to test.

---

## Table of contents

- [Highlights](#highlights)
- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [Prerequisites](#prerequisites)
- [Quickstart (Docker)](#quickstart-docker)
- [Configuration](#configuration)
- [Manual builds](#manual-builds)
  - [0. Proto bindings](#0-generate-proto-bindings)
  - [1. Sentinel-Recon (Go)](#1-sentinel-recon-go)
  - [2. ShadowPot (Go)](#2-shadowpot-go)
  - [3. ZeroTrust FIM (Rust)](#3-zerotrust-fim-rust)
  - [4. PhishGuard AI (Python)](#4-phishguard-ai-python)
  - [5. Control Center (Kotlin)](#5-control-center-kotlin)
- [End-to-end demo](#end-to-end-demo)
- [Testing & CI](#testing--ci)
- [Security](#security)
- [Observability](#observability)
- [Runtime ports](#runtime-ports)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Highlights

- **Sentinel-Recon (Go)** — raw-socket SYN and TCP-connect port scanner with
  adaptive RTT/loss pacing, exponential-backoff throttling, watermark alerting,
  IPv4/IPv6 checksums and banner grabbing.
- **ShadowPot (Go)** — six-protocol decoy grid (SSH, HTTP, MySQL, Redis,
  PostgreSQL, Telnet), dependency-free PCAP writer, automated
  nftables/iptables IP-ban engine, and a token-authenticated gRPC command plane.
- **ZeroTrust FIM (Rust)** — Rayon-parallel BLAKE3 file-integrity monitor,
  SQLite baseline, in-kernel `sys_enter_execve` eBPF tracing (with `/proc`
  fallback), YARA process-memory scanning, and anomaly heuristics
  (unlinked binaries, reverse shells, privilege escalation).
- **PhishGuard AI (Python)** — FastAPI + gRPC gateway, explainable 0–100 threat
  scoring, multi-feed OSINT aggregation (AbuseIPDB / OTX / VirusTotal /
  ThreatFox), IsolationForest ML anomaly detection, YAML SOAR playbooks with a
  safe expression evaluator (no `eval()`), and Prometheus metrics.
- **Control Center (Kotlin)** — Compose Desktop dashboard: 3D attack globe,
  live regex log query with CSV/JSON export, and an interactive topology map.
- **Single IDL** — one `aegisx.proto` compiled to Go, Python and Kotlin
  bindings; four gRPC services.

## Architecture

```
                    ┌──────────────────────────────────────────────────────┐
                    │  Control Center (Kotlin/Compose Desktop)            │
                    │  3D attack globe · regex log query · topology map   │
                    └───────▲──────────────────────────────▲──────────────┘
                     WS /events                       gRPC Commands
                            │                              │
    ┌───────────────────────┴──────────────────────────────┴───────────┐
    │                  PhishGuard AI (Python)                          │
    │  FastAPI · scoring · ThreatIntel (AbuseIPDB/OTX/VT/ThreatFox)    │
    │  IsolationForest anomaly · YAML SOAR playbooks · gRPC gateway     │
    │  Prometheus /metrics                                            │
    └───▲───────────────────────────▲────────────────────────▲─────────┘
   gRPC │ ev + scored               │ gRPC open-ports         │ gRPC Command (blocks)
        │                           │                         │
 ┌──────┴──────────────┐   ┌────────┴───────────┐   ┌─────────┴──────────┐
 │ ShadowPot (Go)      │   │ Sentinel-Recon (Go)│   │ ShadowPot cmd plane│
 │ SSH/HTTP/MySQL/     │   │ SYN/connect scanner│   │ nftables/iptables  │
 │ Redis/Pg/Telnet     │   │ adaptive RTT/loss  │   │ IP-ban engine      │
 │ + PCAP recorder     │   └────────────────────┘   └────────────────────┘
 └──────────▲──────────┘
            │ Unix socket JSON-lines (shared volume)
 ┌──────────┴────────────────────────────────────┐
 │ ZeroTrust FIM (Rust)                          │
 │ Rayon-parallel BLAKE3 · eBPF execve hook ·    │
 │ YARA process-memory scan · /proc anomaly      │
 └───────────────────────────────────────────────┘
```

| Layer | Language | Responsibility |
|---|---|---|
| `sentinel-recon` | Go | Raw-socket SYN + TCP-connect scanning, adaptive RTT/loss pacing, banner grabbing, JSON/protobuf export |
| `shadowpot` | Go | SSH / HTTP / MySQL / Redis / PostgreSQL / Telnet decoys, PCAP payload recording, automated nftables/iptables IP banning, SOAR command plane |
| `zerotrust-fim` | Rust | Rayon-parallel BLAKE3 FIM, SQLite baseline, eBPF `sys_enter_execve` tracing (with `/proc` fallback), YARA process-memory scanner, Unix-socket IPC |
| `phishguard` | Python | Threat scoring, OSINT aggregation (AbuseIPDB/OTX/VirusTotal/ThreatFox), IsolationForest anomaly detection, YAML SOAR playbooks, gRPC gateway, Prometheus metrics |
| `control-center` | Kotlin | Compose Desktop: 3D attack globe, real-time regex log query + CSV/JSON export, interactive topology map, live feed |
| `proto/` | Protobuf | Single IDL: `AegisX`, `ThreatIntelService`, `eBPFStreamer`, `SOARPlaybookService` |

## Repository layout

```
AegisX/
├── proto/
│   ├── aegisx.proto               # contract: 4 services, 20+ messages
│   ├── go.mod                     # Go module (aegisx/proto)
│   └── gen/{go,python}/           # committed generated bindings
├── scripts/
│   ├── gen-proto.ps1              # Windows codegen
│   ├── demo-attack.py             # end-to-end attack simulation
│   └── verify-scoring.py          # offline scoring-path smoke check
├── deploy/prometheus.yml          # scrape config (profile: observability)
├── .github/workflows/ci.yml       # CI: Go + Python + Kotlin + Rust + Docker
├── Makefile                       # make proto | recon | shadowpot | fim | cc
├── sentinel-recon/                # Go module
│   └── internal/scanner/{scanner,syn,pacing}.go
├── shadowpot/                     # Go module
│   ├── internal/listener/{ssh,http,mysql,redis,postgres,telnet}.go
│   ├── internal/pcap/             # dependency-free PCAP writer
│   ├── internal/blocker/          # threshold + firewall-backend ban engine
│   └── internal/cmdserver/        # token-authenticated gRPC Command plane
├── zerotrust-fim/                 # Rust crate (aegis_core) + aegisx-fim daemon
│   └── src/{hasher,baseline,watch,anomaly,ffi,ipc,memscan,ebpf}.rs
├── phishguard/                    # Python microservice
│   ├── app/{main,grpc_server,grpc_advanced,fim_bridge,metrics}.py
│   ├── app/intel/aggregator.py    # multi-feed threat intel
│   ├── app/ml/anomaly.py          # IsolationForest (heuristic fallback)
│   ├── app/soar/playbook.py       # YAML playbook engine + safe evaluator
│   ├── app/soar/playbooks/*.yaml  # shipped playbooks
│   └── tests/                     # pytest suite (32 tests)
├── control-center/                # Kotlin Compose Desktop
│   └── ui/screens/{AttackGlobe,LogQueryView,TopologyMap}.kt
├── Dockerfile.{sentinel-recon,shadowpot,fim,phishguard}
├── docker-compose.yml
└── .env.example
```

## Prerequisites

| Component | Requirement |
|---|---|
| Full stack (recommended) | Docker Engine **20.10+** with Compose v2 (`docker compose version`) |
| Go modules | Go **1.22+** |
| PhishGuard | Python **3.11+** (developed on 3.12); `numpy`/`scikit-learn` are optional (ML degrades to heuristics) |
| ZeroTrust FIM | Rust **stable**; Linux. Advanced features need `clang`, `libelf-dev`, `zlib1g-dev` (eBPF) and `libyara-dev` (YARA) |
| Control Center | JDK **17+** (tested on 21); Gradle **8.10.2** via wrapper |
| Proto codegen (optional) | `protoc`, `protoc-gen-go`, `protoc-gen-go-grpc`, `grpcio-tools`, `protoc-gen-kotlin` |

## Quickstart (Docker)

The fastest way to see the whole platform running:

```bash
# 1. Configure (optional keys left blank are skipped)
cp .env.example .env

# 2. Build + start every service (phishguard, shadowpot, zerotrust-fim; recon is on-demand)
docker compose up -d --build

# 3. Verify
curl http://localhost:8080/health
curl http://localhost:8080/metrics | head

# 4. Play: hit the SSH decoy with a credential attempt
ssh -p 2222 root@127.0.0.1        # wait BAN_THRESHOLD events → auto-ban

# 5. Watch the live feed in the browser
#    open http://localhost:8080/ws/events (or connect the Control Center)
```

Services that require elevated kernel privileges:
- `shadowpot` uses `cap_add: [NET_ADMIN, NET_RAW]` to install firewall rules.
- `zerotrust-fim` runs `privileged: true` for the eBPF hook, `/proc` reads and
  YARA process-memory scanning. On constrained runners tighten this to an
  explicit `cap_add` list.

On-demand scanner (starts once, exits):

```bash
docker compose --profile recon up sentinel-recon
```

## Configuration

Copy `.env.example` → `.env` and edit. All variables have sane defaults; keys
without values are skipped at runtime.

| Variable | Default | Purpose |
|---|---|---|
| `PHISHGUARD_HTTP_PORT` | `8080` | Web UI / REST / WebSocket host port |
| `PHISHGUARD_GRPC_PORT` | `50051` | decoy + recon gRPC intake host port |
| `DECOY_HTTP_PORT` | `8080` | HTTP honeypot host port |
| `DECOY_SSH_PORT` | `2222` | SSH honeypot host port |
| `DECOY_MYSQL_PORT` | `3306` | MySQL honeypot host port |
| `DECOY_REDIS_PORT` | `6379` | Redis honeypot host port |
| `DECOY_POSTGRES_PORT` | `5432` | PostgreSQL honeypot host port |
| `DECOY_TELNET_PORT` | `23` | Telnet honeypot host port |
| `SHADOWPOT_GRPC_PORT` | `50053` | SOAR command plane host port |
| `AEGISX_SHADOWPOT_TOKEN` | *(empty)* | shared bearer token securing the command plane (recommended in production) |
| `PCAP_ENABLED` | `true` | record raw payloads to `.pcap` |
| `BAN_ENABLED` | `true` | automated IP-ban engine |
| `BAN_THRESHOLD` | `3` | malicious events within window before auto-ban |
| `BAN_WINDOW_SECONDS` | `300` | sliding detection window |
| `BAN_DURATION_SECONDS` | `3600` | ban lifetime |
| `BAN_BACKEND` | `auto` | `auto` \| `nftables` \| `iptables` \| `journal` (dry-run) |
| `FIM_WATCH_DIR` | `/etc` | host directory the FIM protects |
| `FIM_RUST_LOG` | `info` | FIM log verbosity |
| `FIM_FEATURES` | *(empty)* | Rust features: `ebpf`, `yara`, or `--features 'ebpf yara ffi'` |
| `ABUSEIPDB_KEY` | *(empty)* | optional AbuseIPDB API v2 key |
| `VT_KEY` | *(empty)* | optional VirusTotal API v3 key |
| `OTX_BASE` | otx.alienvault.com | AlienVault OTX endpoint |
| `THREATFOX_URL` | threatfox-api.abuse.ch | ThreatFox endpoint |
| `PROMETHEUS_PORT` | `9090` | Prometheus UI host port (profile: `observability`) |

## Manual builds

Bindings are committed, so a fresh clone builds without `protoc`. Regenerate
them only if you change `proto/aegisx.proto`.

### 0. Generate proto bindings

```bash
make proto                                  # Linux/macOS
powershell -File scripts/gen-proto.ps1      # Windows
```

### 1. Sentinel-Recon (Go)

```bash
cd sentinel-recon
go build -o bin/aegisx-recon ./cmd/aegisx-recon

# raw-socket SYN scan (needs CAP_NET_RAW / root):
./bin/aegisx-recon -target scanme.example.com -mode syn -start 1 -end 1024 -maxpps 2000

# TCP-connect scan (no privileges):
./bin/aegisx-recon -target scanme.example.com -start 1 -end 1024 -banners
```

### 2. ShadowPot (Go)

```bash
cd shadowpot
go build -o bin/aegisx-shadowpot ./cmd/aegisx-shadowpot

# start the 6 decoys + command plane against a local PhishGuard:
SHADOWPOT_GRPC_UPSTREAM=127.0.0.1:50051 \
SHADOWPOT_GRPC_LISTEN=":50053" \
SHADOWPOT_BAN_BACKEND=journal \
./bin/aegisx-shadowpot
```

`BAN_BACKEND=journal` logs bans instead of touching the firewall — ideal for a
first smoke run.

### 3. ZeroTrust FIM (Rust)

```bash
cd zerotrust-fim
cargo build --release
target/release/aegisx-fim --watch /etc --baseline /var/lib/aegisx/fim-baseline.db \
  --socket /var/run/aegisx-fim.sock --threads 0 --trace-exec

# advanced kernel features (Linux only):
cargo build --release --features ebpf   # aya sys_enter_execve tracepoint (CAP_BPF)
cargo build --release --features yara   # YARA process-memory scan (CAP_SYS_PTRACE)
cargo build --release --features ffi    # C ABI header (aegis_core.h)
```

### 4. PhishGuard AI (Python)

```bash
cd phishguard
python -m venv .venv
source .venv/bin/activate                 # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# run REST + gRPC on one process:
AEGISX_SHADOWPOT_GRPC=shadowpot:50053 \
PYTHONPATH=".:../proto/gen/python" \
python -m uvicorn app.main:app --host 0.0.0.0 --port 8080
```

### 5. Control Center (Kotlin)

```bash
cd control-center
./gradlew run                          # launch the desktop dashboard
./gradlew packageDistributionForCurrentOS   # create a distributable bundle
```

## End-to-end demo

`scripts/demo-attack.py` drives the **full closed loop** against the live stack:

1. **Intake** — streams a 9-event multi-protocol attacker campaign into
   PhishGuard (exactly as ShadowPot does) and prints each verdict.
2. **SOAR** — runs an inline playbook that dispatches a firewall block to
   ShadowPot, writes an incident report and broadcasts a notification.
3. **Command plane auth** — proves the unauthenticated mitigation is rejected
   when a token is configured, then accepts the authenticated one.

```bash
AEGISX_SHADOWPOT_TOKEN="$(openssl rand -hex 32)" docker compose up -d --build
python scripts/demo-attack.py --json --out demo-summary.json
cat demo-summary.json
```

Offline scoring smoke (no services needed):

```bash
python scripts/verify-scoring.py   # e.g. 70.0 HIGH/MALICIOUS SSH with CVE-2014-6271
```

## Testing & CI

CI (`.github/workflows/ci.yml`) runs every suite on every push/PR, including a
full `docker compose build` and a health-check smoke. Locally:

| Suite | Command | Scope |
|---|---|---|
| Go: scanner | `cd sentinel-recon && go test ./...` | pacer, RTT/loss adaptation, checksums, watermark, IPv6 |
| Go: shadowpot | `cd shadowpot && go test ./...` | event bus, IP-ban engine, command plane (+ token auth), PCAP, listener utils |
| Python | `cd phishguard && python -m pytest -q` | ML anomaly, safe-eval playbook engine, threat-intel aggregation, scoring (32 tests) |
| Rust | `cd zerotrust-fim && cargo test --all-features` | exec classification, `/proc` tab parsing (Linux/CI) |
| E2E | `python scripts/verify-scoring.py` | offline scoring-path smoke |

## Security

- **Command plane auth** — `shadowpot:50053` accepts a shared bearer token
  (`AEGISX_SHADOWPOT_TOKEN`). Every `Command` call must carry
  `Authorization: Bearer <token>`; verification uses a constant-time compare.
  Empty token = open plane (dev mode, logged as a warning).
- **No secrets in the repo** — all API keys are injected via environment; the
  committed `.env.example` ships blank values.
- **Firewall enforcement** — bans apply nftables/iptables drop rules inside the
  ShadowPot network namespace (`CAP_NET_ADMIN`). Use `BAN_BACKEND=journal` for
  a non-intrusive dry run.
- **Defensive only** — see the legal note at the top.

## Observability

PhishGuard exposes Prometheus metrics at `/metrics`:

```bash
curl -s http://localhost:8080/metrics | grep aegisx_
```

Key series: `aegisx_grpc_events_total{protocol}` · `aegisx_grpc_verdicts_total`
· `aegisx_soar_playbooks_run_total{playbook}` ·
`aegisx_soar_firewall_blocks_issued_total` ·
`aegisx_http_request_duration_seconds` · `aegisx_analyze_seconds`.

Start the bundled Prometheus:

```bash
docker compose --profile observability up -d prometheus   # UI: http://localhost:9090
```

## Runtime ports

| Service | Port | Purpose |
|---|---|---|
| PhishGuard HTTP/WS | 8080 | REST + `/ws/events` live feed + `/metrics` |
| PhishGuard gRPC | 50051 | decoy / recon telemetry intake |
| ShadowPot HTTP | 8080 | fake admin panel |
| ShadowPot SSH / MySQL / Redis / PostgreSQL / Telnet | 2222/3306/6379/5432/23 | decoys |
| ShadowPot gRPC command plane | 50053 | SOAR firewall-block enforcement (bearer-token auth) |
| Prometheus | 9090 | metrics UI (profile: `observability`) |
| FIM Unix socket | `/var/run/aegisx-fim.sock` | JSON-lines event stream |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `docker compose up` errors on privilege | Confirm your Docker daemon supports `cap_add`/`privileged`; remove `sentinel-recon` (profile `recon`) if its raw-socket capability is blocked |
| `go test` fails with missing `aegisx/proto` | Generated bindings live in `proto/gen/` — keep them tracked; run `make proto` only after editing `aegisx.proto` |
| FIM won't attach eBPF | You need Linux + `CAP_BPF`/`CAP_PERFMON` + tracefs. Run with `--trace-exec` fallback (`/proc` polling) or without features |
| PhishGuard ignores OSINT | Set `ABUSEIPDB_KEY` / `VT_KEY`; missing keys are skipped silently (see logs) |
| No firewall bans happen | Check `SHADOWPOT_BAN_BACKEND` (use `journal` to log) and that 3+ malicious events arrive within `BAN_WINDOW_SECONDS` |
| Windows host, WSL builds | Build Go/Python natively on Windows; run the Rust eBPF/YARA stack inside Docker Linux (see CI) |

## Contributing

1. Fork the repository.
2. Run the affected test suites (see [Testing](#testing--ci)) before pushing.
3. If you change `proto/aegisx.proto`, regenerate bindings and commit them:
   `make proto` / `powershell -File scripts/gen-proto.ps1`.
4. Open a PR — CI runs everything automatically.

## License

Apache-2.0. Intended for defensive security research and operations.
