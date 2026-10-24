import types

from app.intel.aggregator import (
    FEED_WEIGHTS,
    FeedVerdict,
    ThreatIntelAggregator,
)
# --- константы вынесены FORGE refactor ---
CONST_50 = 50



def _agg():
    s = types.SimpleNamespace(
        abuseipdb_key="", abuseipdb_url="https://x", vt_key="", otx_base="",
        threatfox_url="", aggregator_cve_enrich=False, ttl_seconds=300,
    )
    agg = ThreatIntelAggregator(settings=s)
    # Replace network feeds with canned verdicts so tests never touch the wire.
    agg._abuse_feed = lambda ip: FeedVerdict(source="abuseipdb", risk=100)
    agg._vt_feed = lambda ip: None
    agg._otx_feed = lambda ip: FeedVerdict(source="otx", risk=CONST_50)
    agg._threatfox_feed = lambda ip: None
    return agg


def test_blend_empty_zero():
    assert ThreatIntelAggregator._blend({}) == 0.0


def test_blend_all_none_zero():
    assert ThreatIntelAggregator._blend({"a": None, "b": None}) == 0.0


def test_blend_weighted():
    fs = {
        "abuseipdb": FeedVerdict(source="abuseipdb", risk=100),
        "virustotal": None,
        "otx": FeedVerdict(source="otx", risk=CONST_50),
        "threatfox": None,
    }
    # 0.4*100 + 0.2*50 = 50; / 0.6 = 83.33
    blended = ThreatIntelAggregator._blend(fs)
    assert abs(blended - 83.33) < 0.1


def test_key_kinds():
    a = _agg()
    assert a._key({"ip": "1.2.3.4"}) == "ip:1.2.3.4"
    assert a._key({"domain": "x.com"}) == "domain:x.com"


def test_aggregate_sync_high_risk():
    a = _agg()
    report = a.aggregate_sync({"ip": "1.2.3.4"})
    assert report["risk_score"] == 83.3
    assert report["severity"] == "CRITICAL"
    assert report["verdict"] == "MALICIOUS"
    assert report["sources"] == ["abuseipdb", "otx"]


def test_cache_returns_same_object():
    a = _agg()
    r1 = a.aggregate_sync({"ip": "5.5.5.5"})
    r2 = a.aggregate_sync({"ip": "5.5.5.5"})
    assert r1 is r2


def test_cache_hits_differ_by_key():
    a = _agg()
    r1 = a.aggregate_sync({"ip": "1.1.1.1"})
    r2 = a.aggregate_sync({"ip": "2.2.2.2"})
    assert r1 is not r2


def test_cached_malicious_yields_indicators():
    a = _agg()
    a.aggregate_sync({"ip": "9.9.9.9"})
    hits = list(a.cached_malicious())
    assert hits
    assert hits[0]["indicator"] == "9.9.9.9"
    assert hits[0]["verdict"] == "MALICIOUS"


def test_feed_weights_summary():
    assert set(FEED_WEIGHTS) == {"abuseipdb", "virustotal", "otx", "threatfox"}
    assert sum(FEED_WEIGHTS.values()) == 1.0
