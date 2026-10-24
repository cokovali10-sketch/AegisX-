"""Cross-feed threat intelligence aggregator.

Fans a single IOC out to several OSINT feeds, normalizes each response into a
comparable risk score, and blends them into one reputation report. Feeds run
with short timeouts and retries; results are cached with a TTL. Every feed
degrades gracefully (missing keys, DNS failure, timeouts) and simply drops out
of the blend rather than failing the request.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import urllib.request
from dataclasses import dataclass, field

from ..analyzers.score import severity_for, verdict_for
from ..config import get_settings
# --- константы вынесены FORGE refactor ---
CONST_300 = 300
CONST_1000 = 1000


logger = logging.getLogger(__name__)

FEED_WEIGHTS: dict[str, float] = {
    "abuseipdb": 0.4,
    "virustotal": 0.3,
    "otx": 0.2,
    "threatfox": 0.1,
}

_EVIDENCE_CAP = CONST_300
_RETRIES = 2
_TIMEOUT = 4.0


def _ev(text) -> str:
    """Trim + normalize a single evidence snippet (best-effort, never fails)."""
    compact = " ".join(str(text).split())
    return compact[:_EVIDENCE_CAP]


@dataclass
class FeedVerdict:
    """Normalized reputation output of a single OSINT feed."""

    source: str
    risk: float = 0.0
    tags: list[str] = field(default_factory=list)
    report_count: int = 0
    country: str = ""
    asn: str = ""
    evidence: str = ""


class ThreatIntelAggregator:
    """Thread-safe aggregator with a TTL cache shared by sync + async paths."""

    def __init__(self, settings=None):
        s = settings or get_settings()
        self.api_key = s.abuseipdb_key
        self.abuse_url = s.abuseipdb_url
        self.vt_key = s.vt_key
        self.otx_base = s.otx_base
        self.threatfox_url = s.threatfox_url
        self.cve_enrich = s.aggregator_cve_enrich
        self.ttl = float(s.ttl_seconds or CONST_300)
        self.timeout = _TIMEOUT
        self._cache: dict[str, tuple[float, dict]] = {}

    # ------------------------------------------------------------------ http
    def _request_json(self, url: str, method: str = "GET", headers: dict | None = None,
                      body: dict | None = None) -> dict:
        """HTTP GET/POST returning parsed JSON. Raises on every retry failure."""
        last = None
        payload = None
        if body is not None:
            payload = json.dumps(body).encode("utf-8")
        for attempt in range(_RETRIES + 1):
            try:
                req = urllib.request.Request(url, data=payload, method=method,
                                             headers=headers or {})
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read()
                    return json.loads(raw.decode("utf-8", "replace"))
            except Exception as exc:  # urllib.error, timeout, json, any
                last = exc
                time.sleep(0.15 * (attempt + 1))
        raise RuntimeError(f"{method} {url} failed: {last}")

    # ------------------------------------------------------------------ feeds
    def _abuse_feed(self, ip: str) -> FeedVerdict | None:
        if not self.api_key:
            return None
        try:
            data = self._request_json(
                f"{self.abuse_url}?ipAddress={ip}&maxAgeInDays=90",
                headers={"Key": self.api_key, "Accept": "application/json"},
            )
        except Exception as exc:
            logger.debug("abuseipdb feed skip %s: %s", ip, exc)
            return None
        d = data.get("data") or {}
        risk = float(d.get("abuseConfidenceScore", 0) or 0)
        tags = [f"category:{c}" for c in (d.get("categories") or [])]
        if d.get("isWhitelisted"):
            tags.append("whitelisted")
        return FeedVerdict(
            source="abuseipdb",
            risk=risk,
            tags=tags,
            report_count=int(d.get("totalReports", 0) or 0),
            country=str(d.get("countryCode", "") or ""),
            evidence=_ev(f"abuseConfidenceScore={d.get('abuseConfidenceScore')} "
                        f"totalReports={d.get('totalReports')} "
                        f"usageType={d.get('usageType', '')}"),
        )

    def _vt_feed(self, ip: str) -> FeedVerdict | None:
        if not self.vt_key:
            return None
        try:
            data = self._request_json(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.vt_key},
            )
        except Exception as exc:
            logger.debug("virustotal feed skip %s: %s", ip, exc)
            return None
        attr = ((data or {}).get("data") or {}).get("attributes") or {}
        stats = attr.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0) or 0)
        total = sum(int(stats.get(k, 0) or 0) for k in
                    ("malicious", "suspicious", "harmless", "undetected", "timeout"))
        risk = round(malicious / max(1, total) * 100.0, 1)
        return FeedVerdict(
            source="virustotal",
            risk=risk,
            tags=list(attr.get("tags") or []),
            country=str(attr.get("country", "") or ""),
            asn=str(attr.get("asn", "") or ""),
            evidence=_ev(f"{malicious}/{total} engines flagged; "
                        f"reputation={attr.get('reputation')}"),
        )

    def _otx_feed(self, ip: str) -> FeedVerdict | None:
        try:
            data = self._request_json(
                f"{self.otx_base}/api/v1/indicators/IPv4/{ip}/general",
            )
        except Exception as exc:
            logger.debug("otx feed skip %s: %s", ip, exc)
            return None
        pulses = (((data or {}).get("pulse_info")) or {}).get("pulses") or []
        reput = str((data or {}).get("reputation", "") or "").lower()
        risk = min(100.0, 5.0 * len(pulses))
        if reput in {"malicious", "evil"}:
            risk = max(risk, 85.0)
        elif reput == "suspicious":
            risk = max(risk, 50.0)
        tags: list[str] = []
        for pul in pulses:
            tags.append(f"pulse:{pul.get('advisory_id') or pul.get('id')}")
            tags.extend(pul.get("tags") or [])
        return FeedVerdict(
            source="otx",
            risk=risk,
            tags=list(dict.fromkeys(tags)),
            report_count=len(pulses),
            country=str((data or {}).get("country_code", "") or ""),
            evidence=_ev(f"reputation={reput} pulses={len(pulses)} "
                        f"type={((data or {}).get('type') or '')}"),
        )

    def _threatfox_feed(self, ip: str) -> FeedVerdict | None:
        try:
            data = self._request_json(
                self.threatfox_url, "POST",
                body={"query": "search_ioc", "search_term": ip},
            )
        except Exception as exc:
            logger.debug("threatfox feed skip %s: %s", ip, exc)
            return None
        items = (data or {}).get("data") or []
        if not items:
            return None
        maxconf = max(int(it.get("confidence_level", 0) or 0) for it in items)
        risk = min(100.0, float(maxconf))
        tags: list[str] = []
        for it in items:
            if it.get("threat_type"):
                tags.append(f"threat:{it['threat_type']}")
            if it.get("malware"):
                tags.append(f"malware:{it['malware']}")
        first = items[0]
        return FeedVerdict(
            source="threatfox",
            risk=risk,
            tags=list(dict.fromkeys(tags)),
            report_count=len(items),
            asn=str(first.get("asn", "") or ""),
            evidence=_ev(f"confidence={maxconf} "
                        f"first_seen={first.get('first_seen')} "
                        f"malware={first.get('malware_print', '')}"),
        )

    # ------------------------------------------------------------ aggregation
    @staticmethod
    def _blend(verdicts: dict[str, FeedVerdict]) -> float:
        valid = {s: v for s, v in verdicts.items() if v is not None}
        if not valid:
            return 0.0
        acc = 0.0
        wsum = 0.0
        for source, v in valid.items():
            w = FEED_WEIGHTS.get(source, 0.0)
            acc += v.risk * w
            wsum += w
        return acc / wsum if wsum > 0 else 0.0

    @staticmethod
    def _key(query: dict) -> str:
        for kind in ("ip", "domain", "url", "file_hash"):
            if query.get(kind):
                return f"{kind}:{query[kind]}"
        return f"query:{json.dumps(query, sort_keys=True)}"

    def _build_report(self, query: dict, verdicts: dict[str, FeedVerdict]) -> dict:
        valid = {s: v for s, v in verdicts.items() if v is not None}
        risk = self._blend(verdicts)
        sources = sorted(valid)
        tags: list[dict] = []
        evidence: dict[str, str] = {}
        report_count = 0
        country = ""
        asn = ""
        for source in sources:
            v = valid[source]
            report_count += v.report_count
            if not country and v.country:
                country = v.country
            if not asn and v.asn:
                asn = v.asn
            evidence[source] = v.evidence
            for tag in v.tags:
                cat = tag.split(":", 1)[0] if ":" in tag else "feed"
                tags.append({"source": source, "category": cat,
                             "value": tag, "confidence": 0.5})
        if risk:
            risk = round(risk, 1)
        verdict = verdict_for(risk, bool(sources)).value
        severity = severity_for(risk).value

        related_cves: list[str] = []
        if self.cve_enrich and query.get("file_hash"):
            related_cves.append(f"unknown-hash:{query['file_hash'][:12]}")

        return {
            "query": {k: v for k, v in query.items() if v},
            "risk_score": risk,
            "severity": severity,
            "verdict": verdict,
            "sources": sources,
            "tags": tags,
            "report_count": report_count,
            "asn": asn,
            "country": country,
            "evidence": evidence,
            "related_cves": related_cves,
            "collected_at": int(time.time() * CONST_1000),
        }

    def aggregate_sync(self, query: dict) -> dict:
        """Blocking reputation lookup (cache-first, short feed timeouts)."""
        key = self._key(query)
        cached = self._cache.get(key)
        if cached and time.time() - cached[0] < self.ttl:
            return cached[1]

        verdicts: dict[str, FeedVerdict | None] = {}
        if query.get("ip"):
            verdicts["abuseipdb"] = self._abuse_feed(query["ip"])
            verdicts["virustotal"] = self._vt_feed(query["ip"])
            verdicts["otx"] = self._otx_feed(query["ip"])
            verdicts["threatfox"] = self._threatfox_feed(query["ip"])
        report = self._build_report(query, verdicts)
        self._cache[key] = (time.time(), report)
        return report

    async def aggregate_async(self, query: dict) -> dict:
        """Non-blocking wrapper: feed work runs in a worker thread."""
        return await asyncio.to_thread(self.aggregate_sync, query)

    def cached_malicious(self, min_verdict: str = "MALICIOUS"):
        """Yield IndicatorUpdate-shaped dicts for cached malicious indicators."""
        now = time.time()
        for key, (ts, report) in self._cache.items():
            if now - ts >= self.ttl or report.get("verdict") != min_verdict:
                continue
            kind, _, value = key.partition(":")
            tags = [t["value"] for t in report.get("tags", [])]
            yield {
                "indicator": value or key,
                "kind": kind,
                "risk": report.get("risk_score", 0.0),
                "verdict": min_verdict,
                "tags": tags,
                "evidence": dict(report.get("evidence", {})),
                "at": report.get("collected_at", int(now * CONST_1000)),
            }
