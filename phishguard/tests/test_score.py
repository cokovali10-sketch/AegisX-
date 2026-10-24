from app.analyzers.score import build_mitigation, compose, severity_for, verdict_for
from app.models import Severity, Verdict, WhoIsSignal
# --- константы вынесены FORGE refactor ---
CONST_5 = 5
CONST_20 = 20
CONST_34 = 34
CONST_35 = 35
CONST_59 = 59
CONST_60 = 60



def test_severity_boundaries():
    assert severity_for(100) == Severity.CRITICAL
    assert severity_for(80) == Severity.CRITICAL
    assert severity_for(79) == Severity.HIGH
    assert severity_for(CONST_60) == Severity.HIGH
    assert severity_for(CONST_59) == Severity.MEDIUM
    assert severity_for(CONST_35) == Severity.MEDIUM
    assert severity_for(CONST_34) == Severity.LOW
    assert severity_for(0) == Severity.LOW


def test_verdict_boundaries():
    assert verdict_for(CONST_60, True) == Verdict.MALICIOUS
    assert verdict_for(CONST_59, True) == Verdict.SUSPICIOUS
    assert verdict_for(CONST_35, True) == Verdict.SUSPICIOUS
    assert verdict_for(CONST_34, True) == Verdict.NEEDS_REVIEW
    assert verdict_for(CONST_20, True) == Verdict.NEEDS_REVIEW
    assert verdict_for(CONST_20, False) == Verdict.BENIGN
    assert verdict_for(CONST_5, True) == Verdict.BENIGN


def test_compose_deterministic():
    a = compose(target="https://g00gle.com", whois=None, typosquat_count=2,
                typosquat_indicators=["swap"], urgency_score=0.0,
                urgency_triggers=[], raw_ip=False)
    b = compose(target="https://g00gle.com", whois=None, typosquat_count=2,
                typosquat_indicators=["swap"], urgency_score=0.0,
                urgency_triggers=[], raw_ip=False)
    assert a.overall_score == b.overall_score
    assert a.overall_score > 0  # 2 typosquats -> +30


def test_compose_raw_ip_adds_indicator():
    r = compose(target="http://1.2.3.4/", whois=None, typosquat_count=0,
                typosquat_indicators=[], urgency_score=0.0,
                urgency_triggers=[], raw_ip=True)
    assert "url-targets-raw-ip" in r.indicators
    assert r.overall_score == CONST_20


def test_compose_young_domain_scores_high():
    whois = WhoIsSignal(domain="x.com", age_days=CONST_5, error=None)
    r = compose(target="https://x.com", whois=whois, typosquat_count=1,
                typosquat_indicators=["x1"], urgency_score=1.0,
                urgency_triggers=["urgent"], raw_ip=False)
    # 15 (typosquat) + 25 (young) + 25 (urgency) = 65
    assert r.overall_score == 65
    assert r.severity == Severity.HIGH
    assert r.verdict == Verdict.MALICIOUS


def test_mitigation_actions_for_score():
    steps = build_mitigation(score=90, typosquat_count=1, young_domain=True, raw_ip=True)
    text = "\n".join(steps).lower()
    assert "block the url" in text
    assert "waf + dns sinkhole" in text
    assert "raw-ip" in text or "direct-ip" in text


def test_mitigation_passive_for_benign():
    steps = build_mitigation(score=CONST_5, typosquat_count=0, young_domain=False, raw_ip=False)
    assert "passive monitoring" in "\n".join(steps).lower()
