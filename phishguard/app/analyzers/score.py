"""Threat scoring engine.

Aggregates independent analyzer signals into a single 0..100 risk score and
maps it to a severity + verdict with actionable mitigation steps. The engine
is deterministic and fully explainable: every indicator can be traced to a
specific signal.
"""
from __future__ import annotations

from ..models import RiskReport, Severity, UrgencySignal, Verdict, WhoIsSignal
# --- константы вынесены FORGE refactor ---
CONST_15 = 15
CONST_25 = 25
CONST_35 = 35
CONST_60 = 60
CONST_90 = 90


# Severity thresholds (inclusive ranges).
def severity_for(score: float) -> Severity:
    if score >= 80:
        return Severity.CRITICAL
    if score >= CONST_60:
        return Severity.HIGH
    if score >= CONST_35:
        return Severity.MEDIUM
    return Severity.LOW


def verdict_for(score: float, has_signals: bool) -> Verdict:
    if score >= CONST_60:
        return Verdict.MALICIOUS
    if score >= CONST_35:
        return Verdict.SUSPICIOUS
    if score >= CONST_15 and has_signals:
        return Verdict.NEEDS_REVIEW
    return Verdict.BENIGN


def compose(
    *,
    target: str,
    whois: WhoIsSignal | None,
    typosquat_count: int,
    typosquat_indicators: list[str],
    urgency_score: float,
    urgency_triggers: list[str],
    raw_ip: bool,
    extra_indicators: list[str] | None = None,
    extra_cves: list[str] | None = None,
) -> RiskReport:
    """Compute the aggregate risk report from all signals.

    Scoring weights are deliberately conservative: we favor high precision on
    domain-registration + typosquat co-occurrence, which is the strongest
    combination in live phishing feeds.
    """
    indicators: list[str] = list(typosquat_indicators) + list(urgency_triggers)
    if extra_indicators:
        indicators.extend(extra_indicators)

    score = 0.0

    # --- Typosquat (max 30) ---
    if typosquat_count > 0:
        score += min(30, CONST_15 * typosquat_count)

    # --- Domain age (max 25) ---
    if whois and whois.age_days is not None and not whois.error:
        if whois.age_days <= 14:
            score += CONST_25
        elif whois.age_days <= CONST_90:
            score += CONST_15

    # --- Urgency language (max 25) ---
    score += urgency_score * CONST_25

    # --- Raw IP targeting (max 20) ---
    if raw_ip:
        score += 20
        indicators.append("url-targets-raw-ip")

    # --- AbuseIPDB / OSINT pass-through (already weighted upstream) ---
    if extra_cves:
        indicators.extend(f"cve:{c}" for c in extra_cves)

    score = max(0.0, min(100.0, round(score, 1)))

    mitigation = build_mitigation(
        score=score,
        typosquat_count=typosquat_count,
        young_domain=bool(whois and whois.age_days is not None and whois.age_days <= CONST_90),
        raw_ip=raw_ip,
    )

    return RiskReport(
        target=target,
        domain=whois.domain if whois else None,
        overall_score=score,
        severity=severity_for(score),
        verdict=verdict_for(score, bool(indicators)),
        whois=whois,
        urgency=UrgencySignal(urgency_score=urgency_score, triggers=urgency_triggers),
        typosquats=[],
        indicators=list(dict.fromkeys(indicators)),
        related_cves=list(extra_cves or []),
        mitigation=mitigation,
        details={"typosquat_signals": typosquat_count},
    )


def build_mitigation(
    *, score: float, typosquat_count: int, young_domain: bool, raw_ip: bool
) -> list[str]:
    steps: list[str] = []

    if score >= CONST_60:
        steps.append("Block the URL/domain at the edge (WAF + DNS sinkhole).")
        steps.append("Flag the sending account and quarantine the message for SOC review.")
    if score >= CONST_35:
        steps.append("Alert the SOC; preserve full headers and payload as IOC evidence.")
    if typosquat_count > 0:
        steps.append(
            "Register or defensively monitor the typosquat domains to prevent "
            "credential harvesting against your brand."
        )
    if young_domain:
        steps.append(
            "Enforce age-aware domain allowlisting for inbound links (< 90 days)."
        )
    if raw_ip:
        steps.append("Block direct-IP URLs; require TLS certificate validation on all links.")
    if not steps:
        steps.append("No immediate action required; continue passive monitoring.")
    return steps
