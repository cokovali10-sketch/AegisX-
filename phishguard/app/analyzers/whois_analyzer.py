"""WHOIS domain-age analysis.

A freshly-registered domain (< 90 days) carrying a typosquat or urgency
signal is a far stronger phishing indicator than an aged, established domain.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from ..models import WhoIsSignal

logger = logging.getLogger(__name__)

# Age thresholds used by the scoring engine (days).
YOUTH_DAYS = 90
INFANCY_DAYS = 14


def _to_datetime(value) -> datetime | None:
    """Normalize python-whois creation_date (datetime or list of datetimes)."""
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def analyze(domain: str) -> WhoIsSignal:
    """Query WHOIS and compute domain age. Never raises: returns error signal."""
    if not domain:
        return WhoIsSignal(domain=domain or "", error="no domain")

    try:
        import whois  # python-whois

        result = whois.whois(domain)
    except Exception as exc:  # network errors, registry quirks, rate limits
        logger.debug("whois lookup failed for %s: %s", domain, exc)
        return WhoIsSignal(domain=domain, error=str(exc))

    creation = _to_datetime(getattr(result, "creation_date", None))
    registrar = getattr(result, "registrar", None)
    if isinstance(registrar, list):
        registrar = registrar[0] if registrar else None
    registrar = str(registrar) if registrar else None

    if creation is None:
        return WhoIsSignal(domain=domain, registrar=registrar, error="creation_date unavailable")

    age_days = max(0, int((datetime.now(timezone.utc) - creation).total_seconds() // 86400))
    return WhoIsSignal(
        domain=domain,
        creation_date=creation.isoformat(),
        age_days=age_days,
        registrar=registrar,
    )


def age_signal(signal: WhoIsSignal) -> tuple[float, list[str]]:
    """Score contribution from domain age (0-1 urgency modifier)."""
    if signal.error or signal.age_days is None:
        return 0.0, []
    if signal.age_days <= INFANCY_DAYS:
        return 1.0, [f"domain-registered-{signal.age_days}d-ago"]
    if signal.age_days <= YOUTH_DAYS:
        return 0.6, [f"young-domain-{signal.age_days}d"]
    return 0.0, []
