"""SOAR playbook engine.

Loads YAML playbooks, evaluates their triggers against scored events with a
safe expression evaluator (no eval()), and executes actions with per-action
error isolation so a single failing action never aborts the run.
"""
from __future__ import annotations

import ast
import json
import logging
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import yaml

from ..config import get_settings
from ..ws_manager import manager

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_VERDICT_RANK = {"BENIGN": 1, "SUSPICIOUS": 2, "NEEDS_REVIEW": 2, "MALICIOUS": 3}

_PB_PATH = Path(__file__).resolve().parent.parent.parent.parent / "proto" / "gen" / "python"

_CMP_OPS = {
    ast.Eq: lambda a, b: a == b,
    ast.NotEq: lambda a, b: a != b,
    ast.Lt: lambda a, b: a < b,
    ast.LtE: lambda a, b: a <= b,
    ast.Gt: lambda a, b: a > b,
    ast.GtE: lambda a, b: a >= b,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}
_BIN_OPS = {
    ast.Add: lambda a, b: a + b,
    ast.Sub: lambda a, b: a - b,
    ast.Mult: lambda a, b: a * b,
    ast.Div: lambda a, b: a / b,
}


def _eval_node(node: ast.AST, env: dict):
    """Evaluate one AST node against a whitelisted identifier environment."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id not in env:
            raise ValueError(f"unknown identifier: {node.id}")
        return env[node.id]
    if isinstance(node, ast.List):
        return [_eval_node(e, env) for e in node.elts]
    if isinstance(node, ast.UnaryOp):
        if isinstance(node.op, ast.Not):
            return not _eval_node(node.operand, env)
        if isinstance(node.op, ast.USub):
            return -_eval_node(node.operand, env)
        if isinstance(node.op, ast.UAdd):
            return +_eval_node(node.operand, env)
        raise ValueError(f"unsupported unary op: {type(node.op).__name__}")
    if isinstance(node, ast.BinOp):
        op = _BIN_OPS.get(type(node.op))
        if op is None:
            raise ValueError(f"unsupported binary op: {type(node.op).__name__}")
        return op(_eval_node(node.left, env), _eval_node(node.right, env))
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            return all(_eval_node(v, env) for v in node.values)
        if isinstance(node.op, ast.Or):
            return any(_eval_node(v, env) for v in node.values)
        raise ValueError(f"unsupported bool op: {type(node.op).__name__}")
    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, env)
        for op, comp in zip(node.ops, node.comparators):
            fn = _CMP_OPS.get(type(op))
            if fn is None:
                raise ValueError(f"unsupported comparison: {type(op).__name__}")
            right = _eval_node(comp, env)
            if not fn(left, right):
                return False
            left = right
        return True
    raise ValueError(f"unsupported expression node: {type(node).__name__}")


def safe_eval_condition(expression: str, env: dict) -> bool:
    """Evaluate a playbook condition without eval(); raises on unsafe nodes."""
    if not expression or not expression.strip():
        return True
    tree = ast.parse(expression, mode="eval")
    return bool(_eval_node(tree.body, env))


class PlaybookEngine:
    """Loads, validates, evaluates and executes SOAR playbooks."""

    def __init__(self, playbooks_dir: str | None = None, settings=None):
        s = settings or get_settings()
        self.settings = s
        self.report_dir = Path(s.report_dir or "/var/lib/aegisx/reports")
        self.shadowpot_grpc = s.shadowpot_grpc
        self.shadowpot_token = getattr(s, "shadowpot_token", "") or ""
        base = playbooks_dir or str(Path(__file__).resolve().parent / "playbooks")
        self.playbooks_dir = Path(base)
        self._playbooks: dict[str, dict] = {}
        self.load_all()

    # ------------------------------------------------------------------ loading
    def load(self, path: str | Path) -> dict:
        """Parse + validate a single YAML playbook file and add it to the set."""
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        items = raw.get("playbooks", []) if isinstance(raw, dict) else raw
        loaded: dict = {}
        for item in items or []:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            trigger = item.get("trigger") or {}
            actions = item.get("actions") or []
            if not isinstance(trigger, dict) or not isinstance(actions, list):
                raise ValueError(f"playbook {item.get('name')} malformed trigger/actions")
            if not any(a.get("type") in ("firewall_block", "run_script",
                                         "incident_report", "notify")
                       for a in actions):
                raise ValueError(f"playbook {item.get('name')} has no supported action")
            item["enabled"] = bool(item.get("enabled", True))
            loaded[item["name"]] = item
        self._playbooks.update(loaded)
        return loaded

    def load_all(self) -> int:
        count = 0
        if not self.playbooks_dir.is_dir():
            logger.warning("playbooks dir missing: %s", self.playbooks_dir)
            return 0
        for path in sorted(self.playbooks_dir.glob("*.yaml")):
            try:
                self.load(path)
                count += 1
            except Exception as exc:
                logger.warning("failed to load playbook %s: %s", path.name, exc)
        return count

    # ---------------------------------------------------------------- evaluation
    def _build_env(self, scoring: dict, event: dict) -> dict:
        score = float(scoring.get("threat_score") or scoring.get("score") or 0.0)
        return {
            "threat_score": score,
            "score": score,
            "severity": str(scoring.get("severity") or "LOW"),
            "verdict": str(scoring.get("verdict") or "BENIGN"),
            "protocol": str(event.get("protocol") or ""),
            "source_ip": str(event.get("source_ip") or ""),
        }

    def evaluate(self, playbook: dict, scoring: dict, event: dict) -> bool:
        """Decide whether a playbook trigger matches a scored event."""
        trigger = playbook.get("trigger") or {}
        env = self._build_env(scoring, event)

        min_sev = str(trigger.get("min_severity") or "").upper()
        if min_sev and min_sev in _SEVERITY_RANK:
            cur = _SEVERITY_RANK.get(str(scoring.get("severity") or "").upper(), 0)
            if cur < _SEVERITY_RANK[min_sev]:
                return False

        min_verdict = str(trigger.get("min_verdict") or "").upper()
        if min_verdict and min_verdict in _VERDICT_RANK:
            cur = _VERDICT_RANK.get(str(scoring.get("verdict") or "").upper(), 0)
            if cur < _VERDICT_RANK[min_verdict]:
                return False

        tags = trigger.get("indicator_tags") or []
        if tags:
            haystack = list(scoring.get("indicators") or []) + list(event.get("indicators") or [])
            hay = " ".join(haystack).lower()
            if not any(str(t).lower() in hay for t in tags):
                return False

        protocol = str(trigger.get("protocol") or "").lower()
        if protocol and str(event.get("protocol") or "").lower() != protocol:
            return False

        condition = str(trigger.get("condition") or "")
        try:
            return safe_eval_condition(condition, env)
        except Exception as exc:
            logger.warning("playbook %s condition failed (%s): %s",
                           playbook.get("name"), condition, exc)
            return False

    # ------------------------------------------------------------------- actions
    def _firewall_block(self, ip: str, backend: str = "nftables") -> bool:
        if not self.shadowpot_grpc or not ip:
            return False
        if str(_PB_PATH) not in sys.path:
            sys.path.insert(0, str(_PB_PATH))
        try:
            import grpc  # type: ignore
            import aegisx_pb2 as pb  # type: ignore
            import aegisx_pb2_grpc as pb_grpc  # type: ignore
            metadata = ()
            if self.shadowpot_token:
                metadata = (("authorization", f"Bearer {self.shadowpot_token}"),)
            with grpc.insecure_channel(self.shadowpot_grpc) as channel:
                stub = pb_grpc.AegisXStub(channel)
                ack = stub.Command(pb.CommandFrame(
                    id=f"soar-{uuid.uuid4().hex[:8]}",
                    command="mitigate_ban_ip",
                    target=ip,
                    params={"backend": backend},
                    issued_at=int(time.time() * 1000),
                ), timeout=5.0, metadata=metadata)
                issued = bool(ack.accepted)
                if issued:
                    from ..metrics import SOAR_BLOCKS_ISSUED_TOTAL
                    SOAR_BLOCKS_ISSUED_TOTAL.inc()
                return issued
        except Exception as exc:
            logger.warning("shadowpot block failed for %s: %s", ip, exc)
            return False

    @staticmethod
    def _run_script(command: str, timeout: float = 15.0) -> int:
        if not command:
            return -1
        clean_env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": "/tmp",
            "LANG": "C",
            "LC_ALL": "C",
        }
        cmd = command.split(" ") if isinstance(command, str) else list(command)
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                              env=clean_env, shell=False)
        return int(proc.returncode)

    def _incident_report(self, event: dict, scoring: dict, playbook: dict,
                         params: dict) -> str:
        self.report_dir.mkdir(parents=True, exist_ok=True)
        ts = int(time.time() * 1000)
        report_id = f"incident-{ts}"
        payload = {
            "report_id": report_id,
            "playbook": playbook.get("name"),
            "title": params.get("title", "AegisX SOAR incident"),
            "timestamp": ts,
            "scoring": {k: scoring.get(k) for k in
                        ("threat_score", "severity", "verdict", "indicators")},
            "event": {
                "protocol": event.get("protocol"),
                "source_ip": event.get("source_ip"),
                "source_port": event.get("source_port"),
                "target_port": event.get("target_port"),
                "username": event.get("username"),
                "payload_preview": (event.get("payload") or "")[:512],
            },
        }
        path = self.report_dir / f"{report_id}.json"
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return report_id

    async def _notify(self, playbook: dict, scoring: dict, event: dict) -> None:
        await manager.broadcast({
            "type": "soar",
            "playbook": playbook.get("name"),
            "severity": scoring.get("severity"),
            "verdict": scoring.get("verdict"),
            "source_ip": event.get("source_ip"),
            "protocol": event.get("protocol"),
            "timestamp": int(time.time() * 1000),
        })

    async def _execute_action(self, action: dict, event: dict, scoring: dict,
                              playbook: dict) -> tuple[str, dict]:
        """Run one action. Returns (outcome, side_effects). Never raises."""
        atype = action.get("type")
        target = action.get("target", "")
        params = dict(action.get("params") or {})
        side: dict = {}
        try:
            if atype == "firewall_block":
                ip = params.get("ip") or target or str(event.get("source_ip") or "")
                if ip == "SOURCE_IP":
                    ip = str(event.get("source_ip") or "")
                issued = self._firewall_block(ip, str(params.get("backend") or "nftables"))
                side["firewall_block_issued"] = issued
                if issued:
                    return f"firewall block issued for {ip}", side
                return f"DRY-RUN block {ip}", side
            if atype == "run_script":
                command = params.get("command") or target
                timeout = float(params.get("timeout", 15.0) or 15.0)
                code = self._run_script(command, timeout)
                return f"script exit code {code}", side
            if atype == "incident_report":
                report_id = self._incident_report(event, scoring, playbook, params)
                side["report_id"] = report_id
                return f"incident_report {report_id}", side
            if atype == "notify":
                await self._notify(playbook, scoring, event)
                side["notified"] = True
                return "notify sent", side
            return f"unknown action type {atype}", side
        except Exception as exc:
            logger.exception("action %s failed", atype)
            return f"action failed: {exc}", side

    # ------------------------------------------------------------------- public
    async def execute(self, playbook: dict, event: dict, scoring: dict) -> dict:
        outcomes: list[str] = []
        side_effects: dict = {}
        report_id = ""
        firewall_block_issued = False
        for action in playbook.get("actions") or []:
            outcome, side = await self._execute_action(action, event, scoring, playbook)
            outcomes.append(outcome)
            side_effects.update(side)
            if side.get("firewall_block_issued"):
                firewall_block_issued = True
            if side.get("report_id"):
                report_id = side["report_id"]
        return {
            "executed": True,
            "outcomes": outcomes,
            "side_effects": side_effects,
            "firewall_block_issued": firewall_block_issued,
            "report_id": report_id,
            "finished_at": int(time.time() * 1000),
        }

    async def run(self, playbook: dict | None, event: dict, scoring: dict) -> dict:
        """Run a named playbook, or every enabled playbook that triggers."""
        executed = False
        outcomes: list[str] = []
        side_effects: dict = {}
        report_id = ""
        firewall_block_issued = False
        started = int(time.time() * 1000)
        candidates = [playbook] if playbook else [
            p for p in self._playbooks.values() if p.get("enabled")]
        for candidate in candidates:
            if candidate is None:
                continue
            if not self.evaluate(candidate, scoring, event):
                continue
            executed = True
            result = await self.execute(candidate, event, scoring)
            outcomes.extend(f"[{candidate.get('name')}] {o}"
                            for o in result["outcomes"])
            side_effects.update(result["side_effects"])
            if result.get("report_id"):
                report_id = result["report_id"]
            if result.get("firewall_block_issued"):
                firewall_block_issued = True
        if not executed:
            outcomes.append("no playbook triggered")
        return {
            "executed": executed,
            "outcomes": outcomes,
            "side_effects": side_effects,
            "firewall_block_issued": firewall_block_issued,
            "report_id": report_id,
            "finished_at": int(time.time() * 1000),
        }

    def list_playbooks(self) -> list[dict]:
        return [
            {
                "name": p.get("name"),
                "description": p.get("description", ""),
                "enabled": bool(p.get("enabled")),
                "trigger": p.get("trigger") or {},
                "actions": p.get("actions") or [],
            }
            for p in self._playbooks.values()
        ]

    def toggle(self, name: str, enabled: bool) -> dict | None:
        playbook = self._playbooks.get(name)
        if playbook is None:
            return None
        playbook["enabled"] = bool(enabled)
        return {"name": name, "enabled": playbook["enabled"]}
