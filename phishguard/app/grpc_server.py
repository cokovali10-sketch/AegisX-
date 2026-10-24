"""AegisX gRPC gateway.

Implements the `AegisX` service from proto/aegisx.proto:
  * StreamHoneypotEvents (bidi)   - ShadowPot decoys stream captures in;
                                     PhishGuard scores and streams results back.
  * SubmitScan (client-stream)    - Sentinel-Recon pushes open ports; we ack
                                     with a consolidated summary.
  * Command (unary)               - Control Center mitigation toggles.
  * StreamTelemetry (bidi)        - system health / rate telemetry relay.

Generated stubs are produced by `make proto` into proto/gen/python.
"""
from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

# Make the generated bindings importable regardless of CWD.
_PROTO_GEN = Path(__file__).resolve().parent.parent.parent / "proto" / "gen" / "python"
if str(_PROTO_GEN) not in sys.path:
    sys.path.insert(0, str(_PROTO_GEN))

import grpc  # noqa: E402

import aegisx_pb2 as pb  # noqa: E402
import aegisx_pb2_grpc as pb_grpc  # noqa: E402

from .analyzers import score as score_engine  # noqa: E402
from .config import get_settings  # noqa: E402
from .fim_bridge import fim_bridge  # noqa: E402
from .grpc_advanced import (  # noqa: E402
    aggregator,
    anomaly_detector,
    register_advanced_servicers,
)
from .intel.threat_intel import ThreatIntel  # noqa: E402
from .intel.vectorstore import VectorStore  # noqa: E402
from .ws_manager import manager  # noqa: E402
# --- константы вынесены FORGE refactor ---
CONST_20 = 20.0
CONST_1000 = 1000


logger = logging.getLogger(__name__)

_SEV_TO_PB = {
    "LOW": pb.SEVERITY_LOW,
    "MEDIUM": pb.SEVERITY_MEDIUM,
    "HIGH": pb.SEVERITY_HIGH,
    "CRITICAL": pb.SEVERITY_CRITICAL,
}
_VERDICT_TO_PB = {
    "BENIGN": pb.VERDICT_BENIGN,
    "SUSPICIOUS": pb.VERDICT_SUSPICIOUS,
    "MALICIOUS": pb.VERDICT_MALICIOUS,
    "NEEDS_REVIEW": pb.VERDICT_NEEDS_REVIEW,
}


def score_attack_event(event: pb.HoneypotEvent, intel: ThreatIntel) -> pb.ScoringResult:
    """Score one decoy-captured event into a full threat assessment."""
    # Base weight: protocol-agnostic brute-force / auth probing is at least
    # suspicious; credential-bearing attempts raise it further.
    base = CONST_20
    indicators: list[str] = [f"protocol:{event.protocol}"]
    if event.username or event.password:
        base += CONST_20
        indicators.append("credential-attempt")
    if event.metadata.get("auth_plugin"):
        base += 10
    if event.protocol == "http" and event.method in {"POST", "PUT"}:
        base += 5

    # OSINT + CVE enrichment (async-friendly, but scoring path is sync here;
    # we run the payload analysis inline and reputation in a fast call).
    intel_result = intel.analyze_payload(event.payload, event.username, event.protocol)
    if intel_result.related_cves:
        base += intel_result.score_modifier

    # ML anomaly signal (degrades gracefully when sklearn is unavailable).
    feats = {
        "protocol": event.protocol,
        "source_ip": event.source_ip,
        "source_port": event.source_port,
        "target_port": event.target_port,
        "payload_len": len(event.payload or ""),
        "duration_ms": event.connection_duration_ms,
        "has_credentials": 1 if (event.username or event.password) else 0,
        "tokens": len((event.payload or "").split()),
        "connection_rate": 1.0,
    }
    ml_result = anomaly_detector.analyze(feats)
    if ml_result["anomaly"]:
        base += 10
        indicators.append(f"ml-anomaly:{ml_result['anomaly_score']:.2f}")

    # Cached OSINT reputation for the source IP (cache-first, short timeout).
    reputation = aggregator.aggregate_sync({"ip": event.source_ip})
    if reputation["verdict"] == "MALICIOUS":
        base += CONST_20
        indicators.append("osint:" + ",".join(reputation.get("sources") or []))

    total = max(0.0, min(100.0, base))
    severity = score_engine.severity_for(total).value
    verdict = score_engine.verdict_for(total, bool(indicators)).value

    mitigation = score_engine.build_mitigation(
        score=total,
        typosquat_count=0,
        young_domain=False,
        raw_ip=False,
    )

    from .metrics import GRPC_EVENTS_TOTAL, GRPC_VERDICTS_TOTAL
    GRPC_EVENTS_TOTAL.labels(event.protocol or "unknown").inc()
    GRPC_VERDICTS_TOTAL.labels(str(verdict)).inc()

    return pb.ScoringResult(
        event_id=event.id,
        threat_score=round(total, 1),
        severity=_SEV_TO_PB[severity],
        verdict=_VERDICT_TO_PB[verdict],
        related_cves=intel_result.related_cves,
        indicators=list(dict.fromkeys(indicators + intel_result.indicators)),
        summary=f"{event.protocol} interaction from {event.source_ip} -> {verdict}",
        mitigation=mitigation,
        scored_at=int(time.time() * CONST_1000),
    )


class AegisXServicer(pb_grpc.AegisXServicer):
    def __init__(self) -> None:
        self.intel = ThreatIntel(
            api_key=get_settings().abuseipdb_key,
            api_url=get_settings().abuseipdb_url,
        )
        self.vector = VectorStore(
            persist_path=get_settings().chroma_path,
            enabled=get_settings().vectorstore_enabled,
        )

    async def StreamHoneypotEvents(self, request_iterator, context):  # noqa: N802
        async for event in request_iterator:
            try:
                result = score_attack_event(event, self.intel)
            except Exception as exc:  # never let one event kill the stream
                logger.exception("scoring failed for %s: %s", event.id, exc)
                result = pb.ScoringResult(
                    event_id=event.id,
                    threat_score=0.0,
                    severity=pb.SEVERITY_LOW,
                    verdict=pb.VERDICT_NEEDS_REVIEW,
                    indicators=["scoring-error"],
                    summary=f"scoring error: {exc}",
                    scored_at=int(time.time() * CONST_1000),
                )

            # Ingest into the vector store for future similarity lookups.
            event_dict = {
                "protocol": event.protocol,
                "source_ip": event.source_ip,
                "payload": event.payload,
                "username": event.username,
                "path": event.path,
            }
            self.vector.add_event(event_dict, verdict=pb.Verdict.Name(result.verdict))

            # Fan out to the Control Center over WebSocket.
            await manager.broadcast({
                "type": "attack_event",
                "event_id": event.id,
                "protocol": event.protocol,
                "source_ip": event.source_ip,
                "source_port": event.source_port,
                "target_port": event.target_port,
                "username": event.username,
                "user_agent": event.user_agent,
                "threat_score": result.threat_score,
                "severity": pb.Severity.Name(result.severity),
                "verdict": pb.Verdict.Name(result.verdict),
                "summary": result.summary,
                "indicators": list(result.indicators),
                "related_cves": list(result.related_cves),
                "mitigation": list(result.mitigation),
                "timestamp": int(time.time() * CONST_1000),
            })

            yield result

    async def SubmitScan(self, request_iterator, context):  # noqa: N802
        count = 0
        open_ports = []
        started = int(time.time() * CONST_1000)
        async for port in request_iterator:
            count += 1
            if port.state == "open":
                open_ports.append(port)
        summary = pb.ScanResponse(
            scan_id=f"scan-{started}",
            target=open_ports[0].host if open_ports else "",
            started_at=started,
            duration_ms=int(time.time() * CONST_1000) - started,
            ports_scanned=count,
        )
        for p in open_ports:
            summary.open_ports.append(p)
        return summary

    async def Command(self, request, context):  # noqa: N802
        # Control plane: mitigation toggles. Enforcement happens in the target
        # daemon; we acknowledge, broadcast for UI state sync, and persist.
        logger.info("command received: %s target=%s params=%s",
                    request.command, request.target, dict(request.params))
        await manager.broadcast({
            "type": "command_ack",
            "id": request.id,
            "command": request.command,
            "target": request.target,
            "accepted": True,
        })
        return pb.CommandAck(
            id=request.id,
            accepted=True,
            detail=f"command '{request.command}' accepted for orchestration",
            acked_at=int(time.time() * CONST_1000),
        )

    async def StreamTelemetry(self, request_iterator, context):  # noqa: N802
        async for frame in request_iterator:
            await manager.broadcast({
                "type": "telemetry",
                "node": frame.node,
                "metric": frame.metric,
                "value": frame.value,
                "labels": dict(frame.labels),
                "timestamp": frame.timestamp,
            })


async def serve_grpc(port: int) -> grpc.aio.Server:
    server = grpc.aio.server(maximum_concurrent_rpcs=256)
    pb_grpc.add_AegisXServicer_to_server(AegisXServicer(), server)
    register_advanced_servicers(server)

    settings = get_settings()
    fim_bridge.ipc = settings.fim_ipc
    fim_bridge.log_path = settings.fim_log
    await fim_bridge.start()

    server.add_insecure_port(f"[::]:{port}")
    await server.start()
    logger.info("gRPC gateway listening on [::]:%s", port)
    return server
