#!/usr/bin/env python3
"""AegisX end-to-end attack simulation.

Drives the full defensive pipeline against the live compose stack:

  1. Streams a multi-event attacker campaign into PhishGuard's gRPC intake
     (exactly like ShadowPot's decoy grid does) and prints each scored verdict.
  2. Triggers the SOAR engine via RunPlaybook with an inline playbook, proving
     the action chain reaches ShadowPot's command plane (firewall_block),
     writes an incident report and broadcasts a notification.
  3. Verifies the command plane is secured: an unauthenticated mitigation is
     rejected when AEGISX_SHADOWPOT_TOKEN is set, then the authenticated one is
     accepted.

Usage:
    python scripts/demo-attack.py [--json] [--out summary.json]

Environment:
    AEGISX_GRPC_ADDR        PhishGuard gateway  (default localhost:50051)
    AEGISX_SHADOWPOT_CMD    ShadowPot command plane (default localhost:50053)
    AEGISX_SHADOWPOT_TOKEN  shared bearer token securing the command plane
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path

_PROTO_GEN = Path(__file__).resolve().parent.parent / "proto" / "gen" / "python"
if str(_PROTO_GEN) not in sys.path:
    sys.path.insert(0, str(_PROTO_GEN))

import grpc  # noqa: E402
import aegisx_pb2 as pb  # noqa: E402
import aegisx_pb2_grpc as pb_grpc  # noqa: E402
# --- константы вынесены FORGE refactor ---
CONST_5 = 5.0
CONST_8 = 8
CONST_22 = 22
CONST_8080 = 8080


PHISHGUARD = os.environ.get("AEGISX_GRPC_ADDR", "localhost:50051")
SHADOWPOT_CMD = os.environ.get("AEGISX_SHADOWPOT_CMD", "localhost:50053")
TOKEN = os.environ.get("AEGISX_SHADOWPOT_TOKEN", "")

ATTACKER = os.environ.get("AEGISX_DEMO_ATTACKER_IP", "198.51.100.66")


def _meta(**kv) -> tuple:
    md = tuple(f"{k}: {v}" for k, v in kv.items() if v)
    return md or None


def _ts() -> int:
    return int(time.time() * 1000)


def _event(proto: str, port: int, username: str = "", password: str = "",
           payload: str = "", path: str = "", method: str = "",
           extra: dict | None = None) -> pb.HoneypotEvent:
    md = dict(extra or {})
    return pb.HoneypotEvent(
        id=f"demo-{uuid.uuid4().hex[:CONST_8]}",
        timestamp=_ts(),
        source_ip=ATTACKER,
        source_port=40000 + (port % 2000),
        protocol=proto,
        target_port=port,
        username=username,
        password=password,
        user_agent="Mozilla/5.0 (X11; Linux x86_64) curl/8.5.0" if proto == "http" else "",
        payload=payload,
        method=method,
        path=path,
        metadata=md,
        connection_duration_ms=120.0,
    )


def build_campaign() -> list[pb.HoneypotEvent]:
    """A small, realistic multi-protocol attacker campaign from one source IP."""
    return [
        _event("ssh", CONST_22, username="root", password="toor",
               payload="SSH-2.0-OpenSSH_9.6p1"),
        _event("ssh", CONST_22, username="admin", password="admin123",
               payload="SSH-2.0-OpenSSH_9.6p1"),
        _event("ssh", CONST_22, username="root", password="Passw0rd!",
               payload="SSH-2.0-OpenSSH_9.6p1"),
        _event("http", CONST_8080, path="/admin/login.php", method="POST",
               payload="username=admin&password=letmein",
               extra={"auth_plugin": ""}),
        _event("http", CONST_8080, path="/.env", method="GET",
               payload="GET /.env HTTP/1.1", extra={"auth_plugin": ""}),
        _event("mysql", 3306, username="root", password="",
               payload="\x00\x00\x00\x03mysql_native_password",
               extra={"auth_plugin": "mysql_native_password"}),
        _event("redis", 6379, payload="*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n"),
        _event("postgres", 5432, username="postgres", password="postgres",
               payload="\x00\x03\x00\x00user\x00postgres"),
        _event("telnet", 23, username="cisco", password="cisco",
               payload="\xff\xfb\x01", extra={"auth_plugin": ""}),
    ]


def phase_intake(stub: pb_grpc.AegisXStub, events: list[pb.HoneypotEvent]) -> list[dict]:
    """Stream events into PhishGuard like ShadowPot would; collect verdicts."""
    print(f"\n== Phase 1: intake + AI scoring ({len(events)} events) ==")
    scored: list[dict] = []
    responses = stub.StreamHoneypotEvents(iter(events), timeout=30.0)
    for result in responses:
        rec = {
            "event_id": result.event_id,
            "protocol": _proto_of(result),
            "score": round(result.threat_score, 1),
            "severity": pb.Severity.Name(result.severity).removeprefix("SEVERITY_"),
            "verdict": pb.Verdict.Name(result.verdict).removeprefix("VERDICT_"),
            "summary": result.summary,
            "indicators": list(result.indicators),
        }
        scored.append(rec)
        print(f"  [{rec['protocol']:<8}] {rec['score']:>5.1f}  "
              f"{rec['severity']:<8} {rec['verdict']:<12} {rec['summary']}")
    return scored


def _proto_of(result: pb.ScoringResult) -> str:
    # The scoring result doesn't echo the protocol, so recover it from summary.
    return result.summary.split(" ")[0] if result.summary else "?"


def phase_soar(stub: pb_grpc.SOARPlaybookServiceStub, event: pb.HoneypotEvent) -> dict:
    """Run an inline SOAR playbook through PhishGuard and show the action chain."""
    print("\n== Phase 2: SOAR playbook -> ShadowPot firewall block ==")
    inline = pb.Playbook(
        name="demo_block_and_report",
        description="Demo: block attacker + write incident report + notify",
        enabled=True,
        trigger=pb.PlaybookTrigger(
            min_severity=pb.SEVERITY_HIGH,
            min_verdict=pb.VERDICT_MALICIOUS,
            condition="threat_score >= 80",
        ),
        actions=[
            pb.PlaybookAction(type="firewall_block", target="SOURCE_IP",
                              params={"backend": "nftables"}),
            pb.PlaybookAction(type="incident_report",
                              params={"title": "Demo: active attacker campaign"}),
            pb.PlaybookAction(type="notify", params={"channel": "control-center"}),
        ],
    )
    scoring = pb.ScoringResult(
        event_id=event.id,
        threat_score=92.0,
        severity=pb.SEVERITY_CRITICAL,
        verdict=pb.VERDICT_MALICIOUS,
        indicators=["credential-attempt", "signature:ssh-bruteforce"],
        summary="critical campaign",
        scored_at=_ts(),
    )
    resp = stub.RunPlaybook(
        pb.RunPlaybookRequest(playbook=inline, event=event, scoring=scoring),
        timeout=15.0)
    result = {
        "executed": resp.executed,
        "firewall_block_issued": resp.firewall_block_issued,
        "report_id": resp.report_id,
        "outcomes": list(resp.outcomes),
    }
    for o in resp.outcomes:
        print(f"  -> {o}")
    return result


def phase_command_plane() -> dict:
    """Verify ShadowPot command plane auth: reject unauthenticated, accept token."""
    print("\n== Phase 3: command-plane authentication ==")
    result: dict = {"open_plane": not TOKEN}
    with grpc.insecure_channel(SHADOWPOT_CMD) as channel:
        stub = pb_grpc.AegisXStub(channel)
        frame = pb.CommandFrame(
            id=f"demo-{uuid.uuid4().hex[:CONST_8]}", command="status",
            target="", params={}, issued_at=_ts())
        try:
            ack = stub.Command(frame, timeout=CONST_5, metadata=_meta())
            if TOKEN:
                result["unauthenticated_rejected"] = not bool(ack.accepted)
            else:
                result["open_plane_ack"] = bool(ack.accepted)
        except grpc.RpcError as exc:
            if not TOKEN:
                raise
            result["unauthenticated_rejected"] = True
            result["unauthenticated_detail"] = exc.details() or exc.code().name
            print(f"  unauthenticated status rejected: {exc.details() or exc.code().name}")
        if TOKEN:
            ack = stub.Command(frame, timeout=CONST_5,
                               metadata=(("authorization", f"Bearer {TOKEN}"),))
            result["authenticated_accepted"] = bool(ack.accepted)
            print(f"  authenticated status accepted={ack.accepted} ({ack.detail})")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print JSON summary")
    parser.add_argument("--out", default="", help="write JSON summary to a file")
    args = parser.parse_args()

    events = build_campaign()
    summary: dict = {
        "started_at": _ts(),
        "attacker_ip": ATTACKER,
        "phishguard": PHISHGUARD,
        "shadowpot_command_plane": SHADOWPOT_CMD,
        "token_configured": bool(TOKEN),
        "campaign": [{"protocol": e.protocol, "port": e.target_port,
                      "username": e.username} for e in events],
        "phases": {},
    }
    try:
        with grpc.insecure_channel(PHISHGUARD) as channel:
            stub = pb_grpc.AegisXStub(channel)
            summary["phases"]["intake"] = {
                "events": phase_intake(stub, events)}
            demo_event = events[0]
            summary["phases"]["soar"] = phase_soar(
                pb_grpc.SOARPlaybookServiceStub(channel), demo_event)
        summary["phases"]["command_plane"] = phase_command_plane()
        summary["finished_at"] = _ts()
    except grpc.RpcError as exc:
        summary["error"] = f"gRPC failure: {exc.code().name}: {exc.details()}"
        print(f"\nFAILED: {exc.code().name}: {exc.details()}", file=sys.stderr)
        print("Is the stack running? Start it with `docker compose up -d --build`.", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - report-and-exit demo script
        summary["error"] = f"unexpected failure: {exc}"
        print(f"\nFAILED: {exc}", file=sys.stderr)
        return 2

    if args.out:
        Path(args.out).write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"\nSummary written to {args.out}")
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print("\nPipeline exercised: intake -> AI scoring -> SOAR -> firewall block "
              "-> authenticated command plane.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
