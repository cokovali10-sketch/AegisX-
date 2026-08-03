from app.ml.anomaly import AnomalyDetector

NUMERIC = ("source_port", "target_port", "payload_len", "duration_ms",
           "has_credentials", "tokens", "connection_rate")


def _stats(n=10, **overrides):
    s = {k: {"mean": 0.0, "m2": 0.0, "n": n} for k in NUMERIC}
    for k, v in overrides.items():
        s[k].update(v)
    return s


def _event(**kw):
    base = {
        "protocol": "ssh", "source_ip": "1.2.3.4",
        "source_port": 50000, "target_port": 2222, "payload_len": 100,
        "duration_ms": 50, "has_credentials": 1, "tokens": 6,
        "connection_rate": 5,
    }
    base.update(kw)
    return base


def test_disabled_is_noop():
    d = AnomalyDetector(enabled=False)
    assert d.analyze({}) == {"anomaly": False, "anomaly_score": 0.0,
                             "method": "unavailable"}


def test_sklearn_method_selected_when_available():
    d = AnomalyDetector(enabled=True)
    assert d.available is True
    assert d.method == "isolation_forest"


def test_analyze_forest_returns_bounded_shape():
    d = AnomalyDetector(enabled=True)
    r = d.analyze(_event())
    assert set(r) == {"anomaly", "anomaly_score", "method"}
    assert r["anomaly"] in (True, False)
    assert 0.0 <= r["anomaly_score"] <= 1.0


def test_heuristic_flags_outlier_from_known_rolling_stats():
    d = AnomalyDetector(enabled=False)
    # tokens column: mean 6, std ~6.7 (m2/n-1). A value of 60 is ~8 stds out.
    d._rolling = _stats(n=10, tokens={"mean": 6.0, "m2": 400.0, "n": 10})
    anom, score = d._heuristic_score({"tokens": 60})
    assert anom is True
    assert 0.0 < score <= 1.0


def test_heuristic_ignores_keys_without_variance():
    d = AnomalyDetector(enabled=False)
    d._rolling = _stats(n=10, tokens={"mean": 6.0, "m2": 0.0, "n": 10})
    anom, score = d._heuristic_score({"tokens": 999})
    assert anom is False
    assert score == 0.0


def test_heuristic_requires_warmup():
    d = AnomalyDetector(enabled=False)
    d._rolling = _stats(n=2, tokens={"mean": 6.0, "m2": 400.0, "n": 2})
    anom, score = d._heuristic_score({"tokens": 999})
    assert anom is False


def test_analyze_never_raises_on_garbage():
    d = AnomalyDetector(enabled=True)
    r = d.analyze({"protocol": None, "source_ip": None})
    assert isinstance(r, dict)
    assert "method" in r
