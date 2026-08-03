"""Advanced AegisX gRPC servicers (threat intel, eBPF/FIM, SOAR).

Shares process-wide singletons for the threat aggregator, ML anomaly detector,
SOAR playbook engine and FIM bridge so both the scoring path (sync) and the
gRPC surface (async) observe the same state.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path

_PROTO_GEN = Path(__file__).resolve().parent.parent.parent / "proto" / "gen" / "python"
if str(_PROTO_GEN) not in sys.path:
    sys.path.insert(0, str(_PROTO_GEN))

import grpc  # noqa: E402
import aegisx_pb2 as pb  # noqa: E402
import aegisx_pb2_grpc as pb_grpc  # noqa: E402

from .config import get_settings  # noqa: E402
from .fim_bridge import fim_bridge  # noqa: E402
from .intel.aggregator import ThreatIntelAggregator  # noqa: E402
from .ml.anomaly import AnomalyDetector  # noqa: E402
from .soar.playbook import PlaybookEngine  # noqa: E402

logger = logging.getLogger(__name__)

_SETTINGS = get_settings()

aggregator = ThreatIntelAggregator(_SETTINGS)
anomaly_detector = AnomalyDetector(enabled=_SETTINGS.ml_enabled)
playbook_engine = PlaybookEngine(settings=_SETTINGS)

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


def _severity_str(enum_val) -> str:
    return pb.Severity.Name(enum_val).removeprefix("SEVERITY_")


def _verdict_str(enum_val) -> str:
    return pb.Verdict.Name(enum_val).removeprefix("VERDICT_")


# ----------------------------------------------------------------------------
# ThreatIntelService
# ----------------------------------------------------------------------------
class ThreatIntelServiceServicer(pb_grpc.ThreatIntelServiceServicer):
    def __init__(self, agg=None):
        self.aggregator = agg or aggregator

    @staticmethod
    def _query_dict(request) -> dict:
        query = {}
        if request.ip:
            query["ip"] = request.ip
        if request.domain:
            query["domain"] = request.domain
        if request.url:
            query["url"] = request.url
        if request.file_hash:
            query["file_hash"] = request.file_hash
        query["enrich_related_cves"] = request.enrich_related_cves
        return query

    def _to_report(self, report: dict) -> pb.ThreatIntReport:
        query = pb.ThreatIntQuery(**report.get("query") or {})
        out = pb.ThreatIntReport(
            query=query,
            risk_score=float(report.get("risk_score") or 0.0),
            severity=_SEV_TO_PB.get(report.get("severity"), pb.SEVERITY_UNSPECIFIED),
            verdict=_VERDICT_TO_PB.get(report.get("verdict"), pb.VERDICT_UNSPECIFIED),
            sources=list(report.get("sources") or []),
            report_count=int(report.get("report_count") or 0),
            asn=report.get("asn", ""),
            country=report.get("country", ""),
            related_cves=list(report.get("related_cves") or []),
            collected_at=int(report.get("collected_at") or 0),
        )
        for tag in report.get("tags") or []:
            out.tags.append(pb.ThreatIntTag(
                source=tag.get("source", ""),
                category=tag.get("category", ""),
                value=tag.get("value", ""),
                confidence=float(tag.get("confidence", 0.0)),
            ))
        for source, evidence in (report.get("evidence") or {}).items():
            out.evidence[source] = evidence
        return out

    @staticmethod
    def _to_update(item: dict) -> pb.IndicatorUpdate:
        return pb.IndicatorUpdate(
            indicator=item.get("indicator", ""),
            kind=item.get("kind", ""),
            risk=float(item.get("risk") or 0.0),
            verdict=_VERDICT_TO_PB.get(item.get("verdict"), pb.VERDICT_UNSPECIFIED),
            tags=list(item.get("tags") or []),
            at=int(item.get("at") or 0),
        )

    async def GetReputation(self, request, context):  # noqa: N802
        try:
            report = await self.aggregator.aggregate_async(self._query_dict(request))
            return self._to_report(report)
        except Exception as exc:
            logger.exception("GetReputation failed: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"reputation lookup failed: {exc}")
            return pb.ThreatIntReport(query=request)

    async def StreamIndicators(self, request, context):  # noqa: N802
        while True:
            try:
                for item in self.aggregator.cached_malicious():
                    yield self._to_update(item)
            except Exception as exc:
                logger.warning("indicator stream iteration failed: %s", exc)
            await asyncio.sleep(30.0)


# ----------------------------------------------------------------------------
# eBPFStreamer
# ----------------------------------------------------------------------------
class eBPFStreamerServicer(pb_grpc.eBPFStreamerServicer):
    def __init__(self, bridge=None):
        self.bridge = bridge or fim_bridge

    @staticmethod
    def _to_exec_event(data: dict) -> pb.ExecEvent:
        def num(key, default=0):
            try:
                return int(data.get(key, default))
            except (TypeError, ValueError):
                return default
        return pb.ExecEvent(
            pid=num("pid"),
            ppid=num("ppid"),
            comm=str(data.get("comm", "") or ""),
            exe=str(data.get("exe", "") or ""),
            argv=[str(a) for a in (data.get("argv") or [])],
            user=str(data.get("user", "") or ""),
            uid=str(data.get("uid", "0") or "0"),
            start_ns=num("start_ns"),
            anomaly=bool(data.get("anomaly", False)),
            anomaly_type=str(data.get("anomaly_type", "") or ""),
            detail=str(data.get("detail", "") or ""),
            node=str(data.get("node", "") or ""),
        )

    async def StreamExecEvents(self, request, context):  # noqa: N802
        while True:
            try:
                data = await self.bridge.queue.get()
            except asyncio.CancelledError:
                return
            yield self._to_exec_event(data)


# ----------------------------------------------------------------------------
# SOARPlaybookService
# ----------------------------------------------------------------------------
class SOARPlaybookServiceServicer(pb_grpc.SOARPlaybookServiceServicer):
    def __init__(self, engine=None):
        self.engine = engine or playbook_engine

    @staticmethod
    def _playbook_to_dict(p: pb.Playbook) -> dict:
        trigger = {
            "indicator_tags": list(p.trigger.indicator_tags),
            "protocol": p.trigger.protocol,
            "condition": p.trigger.condition,
        }
        if p.trigger.min_severity != pb.SEVERITY_UNSPECIFIED:
            trigger["min_severity"] = _severity_str(p.trigger.min_severity)
        if p.trigger.min_verdict != pb.VERDICT_UNSPECIFIED:
            trigger["min_verdict"] = _verdict_str(p.trigger.min_verdict)
        return {
            "name": p.name,
            "description": p.description,
            "enabled": p.enabled,
            "trigger": trigger,
            "actions": [{"type": a.type, "target": a.target, "params": dict(a.params)}
                        for a in p.actions],
        }

    @staticmethod
    def _playbook_to_pb(item: dict) -> pb.Playbook:
        trigger = item.get("trigger") or {}
        t = pb.PlaybookTrigger(
            min_severity=_SEV_TO_PB.get(str(trigger.get("min_severity") or ""),
                                        pb.SEVERITY_UNSPECIFIED),
            min_verdict=_VERDICT_TO_PB.get(str(trigger.get("min_verdict") or ""),
                                           pb.VERDICT_UNSPECIFIED),
            indicator_tags=list(trigger.get("indicator_tags") or []),
            protocol=str(trigger.get("protocol") or ""),
            condition=str(trigger.get("condition") or ""),
        )
        p = pb.Playbook(
            name=item.get("name", ""),
            description=item.get("description", ""),
            trigger=t,
            enabled=bool(item.get("enabled")),
        )
        for a in item.get("actions") or []:
            p.actions.append(pb.PlaybookAction(
                type=a.get("type", ""),
                target=a.get("target", ""),
                params=dict(a.get("params") or {}),
            ))
        return p

    @staticmethod
    def _event_to_dict(e: pb.HoneypotEvent) -> dict:
        return {
            "id": e.id,
            "timestamp": e.timestamp,
            "source_ip": e.source_ip,
            "source_port": e.source_port,
            "target_port": e.target_port,
            "protocol": e.protocol,
            "username": e.username,
            "password": e.password,
            "user_agent": e.user_agent,
            "payload": e.payload,
            "method": e.method,
            "path": e.path,
            "metadata": dict(e.metadata),
            "connection_duration_ms": e.connection_duration_ms,
        }

    @staticmethod
    def _scoring_to_dict(s: pb.ScoringResult) -> dict:
        return {
            "event_id": s.event_id,
            "threat_score": s.threat_score,
            "severity": _severity_str(s.severity),
            "verdict": _verdict_str(s.verdict),
            "related_cves": list(s.related_cves),
            "indicators": list(s.indicators),
            "mitigation": list(s.mitigation),
            "summary": s.summary,
        }

    @staticmethod
    def _response_to_pb(result: dict) -> pb.RunPlaybookResponse:
        out = pb.RunPlaybookResponse(
            executed=bool(result.get("executed")),
            outcomes=list(result.get("outcomes") or []),
            firewall_block_issued=bool(result.get("firewall_block_issued")),
            report_id=result.get("report_id", ""),
            finished_at=int(result.get("finished_at") or 0),
        )
        for key, val in (result.get("side_effects") or {}).items():
            out.side_effects[key] = val if isinstance(val, str) else json.dumps(val)
        return out

    async def RunPlaybook(self, request, context):  # noqa: N802
        try:
            from .metrics import SOAR_PLAYBOOKS_RUN_TOTAL
            name = request.playbook.name if (request.HasField("playbook")
                                             and request.playbook.name) else "configured-set"
            playbook = None
            if request.HasField("playbook") and request.playbook.name:
                playbook = self._playbook_to_dict(request.playbook)
            event = self._event_to_dict(request.event)
            scoring = self._scoring_to_dict(request.scoring)
            result = await self.engine.run(playbook, event, scoring)
            SOAR_PLAYBOOKS_RUN_TOTAL.labels(name).inc()
            return self._response_to_pb(result)
        except Exception as exc:
            logger.exception("RunPlaybook failed: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"playbook run failed: {exc}")
            return pb.RunPlaybookResponse(executed=False, outcomes=[f"action failed: {exc}"])

    def ListPlaybooks(self, request, context):  # noqa: N802
        listing = pb.PlaybookList()
        for item in self.engine.list_playbooks():
            listing.playbooks.append(self._playbook_to_pb(item))
        return listing

    def TogglePlaybook(self, request, context):  # noqa: N802
        status = self.engine.toggle(request.name, request.enabled)
        if status is None:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details(f"playbook not found: {request.name}")
            return pb.PlaybookStatus(name=request.name, enabled=False)
        return pb.PlaybookStatus(name=status["name"], enabled=status["enabled"])


def register_advanced_servicers(server: grpc.aio.Server) -> None:
    """Attach the three advanced servicers to an existing aio server."""
    pb_grpc.add_ThreatIntelServiceServicer_to_server(
        ThreatIntelServiceServicer(aggregator), server)
    pb_grpc.add_eBPFStreamerServicer_to_server(
        eBPFStreamerServicer(fim_bridge), server)
    pb_grpc.add_SOARPlaybookServiceServicer_to_server(
        SOARPlaybookServiceServicer(playbook_engine), server)
