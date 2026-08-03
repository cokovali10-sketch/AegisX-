"""Heuristic + NLP urgency detection for phishing text.

Combines a weighted lexical rule engine (urgency language, credential
harvesting verbs, brand impersonation tokens) with URL structure and encoding
checks. The lexical engine is deterministic and explainable; a pluggable hook
is provided to swap in an ML classifier without changing the pipeline.
"""
from __future__ import annotations

import re

from ..models import UrgencySignal

# urgency language / action-forcing vocabulary, weight -> keywords
URGENCY_PATTERNS: list[tuple[float, list[str]]] = [
    (1.0, ["urgent", "immediately", "act immediately", "asap", "right away"]),
    (0.9, ["will be suspended", "will be terminated", "account suspended"]),
    (0.9, ["verify your account", "confirm your identity", "confirm your account"]),
    (0.8, ["security alert", "unauthorized access", "suspicious activity"]),
    (0.8, ["account locked", "account disabled", "account blocked"]),
    (0.8, ["paypal", "western union", "money transfer", "lottery", "winnings"]),
    (0.7, ["expire", "expiration", "expires"]),
    (0.7, ["click here", "log in", "sign in", "login"]),
    (0.7, ["click the link", "follow the link"]),
    (0.6, ["invoice", "payment", "transaction", "refund", "transfer"]),
    (0.6, ["update your", "reactivate"]),
    (0.5, ["password", "credentials", "secret", "credit card", "card number"]),
    (0.5, ["support team", "admin", "technical department"]),
]

CREDENTIAL_VERBS = re.compile(
    r"\b(verify|confirm|update|reactivate|login|sign\s*-?\s*in|reset)\b",
    re.IGNORECASE,
)

LEET_TRANSFORMS = re.compile(r"(p[a@4]yp[a@4]l|g[0o]0*gl[еe]|m1cr0s0ft|b@nk[o0]f)", re.IGNORECASE)


def analyze_url(target: str, text: str | None) -> UrgencySignal:
    """Score urgency from URL + optional surrounding text (0..1)."""
    body = (target + " " + (text or "")).lower()
    urgency_score = 0.0
    triggers: list[str] = []

    for weight, keywords in URGENCY_PATTERNS:
        for kw in keywords:
            if kw in body:
                urgency_score = max(urgency_score, weight)
                triggers.append(f"urgent-keyword:{kw}")

    if CREDENTIAL_VERBS.search(body):
        urgency_score = max(urgency_score, 0.6)

    if LEET_TRANSFORMS.search(body):
        urgency_score = max(urgency_score, 0.7)
        triggers.append("leet-char-substitution")

    if re.search(r"%\d{2}", target):
        triggers.append("percent-encoding-in-url")

    if "://" not in target and "@" in target:
        triggers.append("credentials-in-userinfo")

    if target.count("!") >= 2:
        urgency_score = min(1.0, urgency_score + 0.1)
        triggers.append("excessive-exclamation")

    return UrgencySignal(
        urgency_score=round(min(urgency_score, 1.0), 3),
        triggers=list(dict.fromkeys(triggers)),
    )
