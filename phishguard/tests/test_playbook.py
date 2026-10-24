import asyncio
import types

import pytest

from app.soar.playbook import PlaybookEngine, safe_eval_condition
# --- константы вынесены FORGE refactor ---
CONST_70 = 70



def _settings(tmp_path):
    return types.SimpleNamespace(report_dir=str(tmp_path), shadowpot_grpc="")


def _engine(tmp_path):
    return PlaybookEngine(settings=_settings(tmp_path))


def _http_playbook(e):
    return [p for p in e.list_playbooks() if p["name"] == "review_suspicious_http"][0]


def _scored(**kw):
    base = {"threat_score": 80, "severity": "HIGH", "verdict": "MALICIOUS"}
    base.update(kw)
    return base


def test_playbooks_load(tmp_path):
    e = _engine(tmp_path)
    names = [p["name"] for p in e.list_playbooks()]
    assert "block_malicious_ssh" in names
    assert "review_suspicious_http" in names


def test_safe_eval_arithmetic_and_compare():
    assert safe_eval_condition("threat_score >= 60", {"threat_score": CONST_70}) is True
    assert safe_eval_condition("threat_score >= 60", {"threat_score": 30}) is False
    assert safe_eval_condition(
        'threat_score >= 60 and severity == "HIGH"',
        {"threat_score": CONST_70, "severity": "HIGH"}) is True
    assert safe_eval_condition("", {}) is True  # empty condition = always true


def test_safe_eval_rejects_unsafe_nodes():
    # Call / attribute access is not part of the whitelist -> must raise.
    with pytest.raises(ValueError):
        safe_eval_condition("__import__('os')", {})
    with pytest.raises(ValueError):
        safe_eval_condition("open('/etc/passwd').read()", {})
    with pytest.raises(ValueError):
        safe_eval_condition("threat_score.__class__", {"threat_score": 1})


def test_evaluate_http_matches(tmp_path):
    e = _engine(tmp_path)
    assert e.evaluate(
        _http_playbook(e),
        _scored(),
        {"protocol": "http", "source_ip": "1.2.3.4"})


def test_evaluate_protocol_mismatch_rejects(tmp_path):
    e = _engine(tmp_path)
    assert not e.evaluate(
        _http_playbook(e),
        _scored(),
        {"protocol": "ssh", "source_ip": "1.2.3.4"})


def test_evaluate_threat_score_gate(tmp_path):
    e = _engine(tmp_path)
    assert not e.evaluate(
        _http_playbook(e),
        _scored(threat_score=10, severity="LOW", verdict="BENIGN"),
        {"protocol": "http", "source_ip": "1.2.3.4"})


def test_run_writes_incident_report(tmp_path):
    e = _engine(tmp_path)
    res = asyncio.run(e.run(
        _http_playbook(e),
        {"protocol": "http", "source_ip": "1.2.3.4", "payload": "GET /admin"},
        _scored()))
    assert res["executed"] is True
    assert res["report_id"]
    assert (tmp_path / f"{res['report_id']}.json").exists()


def test_run_no_trigger_reports_noop(tmp_path):
    e = _engine(tmp_path)
    res = asyncio.run(e.run(
        _http_playbook(e),
        {"protocol": "http", "source_ip": "1.2.3.4"},
        _scored(threat_score=0, severity="LOW", verdict="BENIGN")))
    assert res["executed"] is False
    assert "no playbook triggered" in res["outcomes"]


def test_toggle_enabled_flag(tmp_path):
    e = _engine(tmp_path)
    before = e.list_playbooks()
    assert before[0]["enabled"] is True
    toggled = e.toggle(before[0]["name"], False)
    assert toggled["enabled"] is False
