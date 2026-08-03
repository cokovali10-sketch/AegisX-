# AegisX — 3 minute demo walkthrough

This script drives a tight, scripted AegisX recording you can use for a video
walkthrough or a live presentation. Every command below is real and runs
against the shipped stack (see [Quickstart](../README.md#quickstart-docker)).

## Before you start

```bash
cp .env.example .env
AEGISX_SHADOWPOT_TOKEN="$(openssl rand -hex 32)" docker compose up -d --build

# wait for a green health check (repeat until "ok"):
curl http://localhost:8080/health
```

Open in a browser: `http://localhost:8080/ws/events` (live feed) and, with the
Control Center running, its event/globe views.

## Beat 0 — Title (0:00)

> "AegisX: five languages, one gRPC contract, one autonomous response loop."

## Beat 1 — Live capture (0:10)

Simulate a real attack campaign — 9 events over SSH / HTTP / MySQL / Redis /
PostgreSQL / Telnet, exactly as if it came from the ShadowPot decoys:

```bash
python scripts/demo-attack.py --json
```

Cut to the `/ws/events` feed as verdicts stream in live.

## Beat 2 — Scoring & ML (0:40)

Open the PhishGuard logs / one event detail and show the explainable verdict:
score, confidence, sour-lines brief (which intel feed contributed), and the
IsolationForest anomaly flag.

## Beat 3 — SOAR takes action (0:60)

Show the playbook dispatch in the logs. A firewall `Command` is sent to the
ShadowPot command plane with the bearer token; then show the ban installed:

```bash
docker compose logs shadowpot | tail # look for the Ban issued ... log line
```

## Beat 4 — Auth, under the hood (0:75)

Prove the plane is actually secured. Fire an unauthenticated mitigation and
watch it be rejected, then the authenticated one succeed:

```bash
# unauthenticated -> PERMISSION_DENIED (gRPC), then the token is accepted
PYTHONPATH=".:../proto/gen/python" python - <<'PY'
import grpc
import aegisx_pb2 as pb, aegisx_pb2_grpc as pb_grpc
from pathlib import Path
stub = pb_grpc.AegisXStub(grpc.insecure_channel("localhost:50053"))
frame = pb.CommandFrame(id="demo", command="status", target="",
                        params={}, issued_at=0)
try:
    stub.Command(frame, timeout=5.0)          # no Authorization header
except grpc.RpcError as exc:
    print("rejected:", exc.code().name, exc.details())
stub.Command(frame, timeout=5.0,
             metadata=(("authorization", "Bearer <your-token>"),))
print("authenticated accepted")
PY
```

## Beat 5 — Observability & integrity (0:00)

Finally show the instrumentation the platform ships with:

```bash
curl -s http://localhost:8080/metrics | grep -E 'aegisx_(grpc_events|soar_firewall_blocks|analyze_seconds)'
docker compose logs zerotrust-fim | tail          # BLAKE3 integrity + exec tracing
```

## Outro

> "One IDL, four languages, a closed loop: detect → correlate → respond.
> Tests, CI, and a full Docker stack are all in the repo."

---

### Recording tips

- Keep each beat short; total under 3 minutes is ideal.
- Record the **terminal in one column, the dashboard in the other**.
- Use a confirmed `BAN_BACKEND` (default `auto`) OR `journal` for the dry-run
  cut that doesn't touch a firewall.