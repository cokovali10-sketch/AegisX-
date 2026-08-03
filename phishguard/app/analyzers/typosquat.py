"""Typosquatting detection via Levenshtein distance + homoglyph inspection.

Identifies domain names that are one or two edits away from a well-known
target brand — the classic phishing registration pattern.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from ..models import TyposquatSignal

try:  # C-accelerated Levenshtein if available
    from Levenshtein import distance as _lev  # type: ignore
except Exception:  # pragma: no cover - pure-python fallback
    def _lev(a: str, b: str) -> int:
        if len(a) < len(b):
            a, b = b, a
        prev = list(range(len(a) + 1))
        for j, cb in enumerate(b, 1):
            cur = [j]
            for i, ca in enumerate(a, 1):
                cur.append(min(prev[i] + 1, cur[i - 1] + 1, prev[i - 1] + (ca != cb)))
            prev = cur
        return prev[-1]


# Registry of domains we defend (defenders populate / extend).
KNOWN_DOMAINS: list[str] = [
    "google.com", "gmail.com", "youtube.com", "facebook.com", "instagram.com",
    "microsoft.com", "outlook.com", "office365.com", "linkedin.com", "twitter.com",
    "x.com", "amazon.com", "amazon.in", "apple.com", "icloud.com", "paypal.com",
    "ebay.com", "netflix.com", "dropbox.com", "adobe.com", "github.com",
    "stackoverflow.com", "reddit.com", "whatsapp.com", "telegram.org",
    "discord.com", "zoom.us", "chase.com", "wellsfargo.com", "bankofamerica.com",
    "coinbase.com", "binance.com", "metamask.io",
]

# Characters that lend themselves to homoglyph substitution (l1/I1, 0/O, rn/m...)
HOMOGLYPH_MAP: dict[str, str] = {"0": "o", "1": "l", "l": "i", "5": "s", "3": "e"}

_MAX_DISTANCE = 2


def extract_domain(target: str) -> str | None:
    """Pull a registrable domain from a URL or bare hostname.

    Returns `None` when the target resolves to a raw IP literal (a separate
    phishing signal) or cannot be parsed as a hostname.
    """
    raw = target.strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "//" + raw
    try:
        host = (urlparse(raw).hostname or "").lower()
    except ValueError:
        return None
    if not host:
        return None
    try:
        ipaddress.ip_address(host.split(":")[0])
        return None  # raw IP literal, not a domain
    except ValueError:
        pass
    return host


def analyze(target: str) -> tuple[list[TyposquatSignal], list[str]]:
    """Return (typosquat matches, indicators).

    Inspects the registrable domain AND every subdomain label. Attackers
    frequently bury the typosquat in a subdomain (g00gle-verify-login.bad.com),
    so we compare each label's homoglyph-normalized form against known brands.
    """
    host = extract_domain(target)
    if host is None:
        return [], []

    host = host.split(":")[0]
    labels = host.split(".")
    if len(labels) < 2:
        return [], []

    known_labels = {k.split(".")[0] for k in KNOWN_DOMAINS}
    candidates_to_check = {host}
    if len(labels) >= 2:
        candidates_to_check.add(".".join(labels[-2:]))

    signals: list[TyposquatSignal] = []
    indicators: list[str] = []

    for candidate in candidates_to_check:
        for known in KNOWN_DOMAINS:
            d = _lev(candidate, known)
            if 0 < d <= _MAX_DISTANCE:
                signals.append(TyposquatSignal(
                    matched_domain=known, distance=d, candidate=candidate,
                ))
                indicators.append(f"typosquat-of:{known} (edit-distance={d})")

    # Per-label inspection catches subdomain-brand phishing. TLDs and
    # too-short tokens are excluded to kill false positives like `com`->`zoom`.
    TLDS = {"com", "net", "org", "io", "co", "uk", "us", "de", "fr", "ru",
            "cn", "au", "ca", "in", "biz", "info", "xyz", "top", "online",
            "site", "shop", "app", "dev", "me", "cc", "tv"}
    for label in labels:
        if label in TLDS or label in {"www", "mail", "web", "ftp", "smtp", "vpn"}:
            continue
        for segment in re.split(r"[-_.]", label):
            if len(segment) < 4:
                continue
            normalized = "".join(HOMOGLYPH_MAP.get(c, c) for c in segment)
            if normalized in known_labels and normalized != segment:
                indicators.append(f"homoglyph-brand:{normalized} (as {segment})")
                signals.append(TyposquatSignal(
                    matched_domain=normalized, distance=1, candidate=segment,
                ))
                continue
            for known in known_labels:
                d = _lev(segment, known)
                if 0 < d <= _MAX_DISTANCE:
                    indicators.append(f"subdomain-typosquat-of:{known} (edit-distance={d})")
                    signals.append(TyposquatSignal(
                        matched_domain=known, distance=d, candidate=segment,
                    ))
                    break

    return signals, indicators


def has_raw_ip(target: str) -> bool:
    """True if the URL targets a raw IP literal (phishing indicator)."""
    host = extract_domain(target)
    if host is not None:
        return False
    # If extract_domain returned None, it may have been an IP literal.
    pre = target.split("//")[-1].split("/")[0].split(":")[0]
    try:
        ipaddress.ip_address(pre)
        return True
    except ValueError:
        return False