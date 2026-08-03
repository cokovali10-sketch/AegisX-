"""Anomaly detection for honeypot events.

Uses a scikit-learn IsolationForest trained on a synthetic "normal" baseline.
When scikit-learn (or numpy) is not installed the detector degrades to a
pure-python statistical heuristic (z-scores against rolling means) so the
pipeline keeps running without an ML dependency.
"""
from __future__ import annotations

import logging
import math
import time

logger = logging.getLogger(__name__)

# Numeric feature keys extracted from a HoneypotEvent-like dict.
_NUMERIC_KEYS = (
    "source_port", "target_port", "payload_len", "duration_ms",
    "has_credentials", "tokens", "connection_rate",
)
_STRING_KEYS = ("protocol", "source_ip")

_PROTOCOL_ENC = {"ssh": 1.0, "http": 2.0, "https": 3.0, "mysql": 4.0,
                 "smtp": 5.0, "ftp": 6.0, "rdp": 7.0, "telnet": 8.0}


def _ip_enc(ip: str) -> float:
    """Deterministic numeric encoding of an IPv4 literal (0.0 when unusable)."""
    try:
        parts = [int(p) for p in str(ip).split(".")]
        if len(parts) != 4:
            return 0.0
        return parts[0] * 1000000 + parts[1] * 1000 + parts[2] + parts[3] / 1000.0
    except (TypeError, ValueError):
        return 0.0


class AnomalyDetector:
    """Scores events for deviation from the baseline, with graceful fallback."""

    def __init__(self, enabled: bool = True, contamination: float = 0.05,
                 n_estimators: int = 100, baseline_samples: int = 600):
        self.enabled = enabled
        self._model = None
        self._np = None
        self.available = False
        self.method = "unavailable"
        self._contamination = contamination
        self._n_estimators = n_estimators
        self._baseline_samples = baseline_samples
        self._baseline = None
        self._rolling = {k: {"mean": 0.0, "m2": 0.0, "n": 0}
                         for k in _NUMERIC_KEYS}
        self._last_update = 0.0
        if not enabled:
            return
        self._try_load()

    # --------------------------------------------------------------- model set
    def _try_load(self) -> None:
        try:
            import numpy as np  # type: ignore
            from sklearn.ensemble import IsolationForest  # type: ignore
        except Exception as exc:
            logger.warning("sklearn unavailable, anomaly detector falls back "
                           "to heuristic scoring: %s", exc)
            self.available = False
            self.method = "heuristic"
            return
        self._np = np
        try:
            rng = np.random.default_rng(42)
            baseline = rng.normal(loc=0.0, scale=1.0,
                                  size=(self._baseline_samples, len(_NUMERIC_KEYS)))
            self._baseline = baseline
            self._model = IsolationForest(
                n_estimators=self._n_estimators,
                contamination=self._contamination,
                random_state=42,
            )
            self._model.fit(baseline)
            self.available = True
            self.method = "isolation_forest"
        except Exception as exc:
            logger.warning("isolation forest init failed, falling back: %s", exc)
            self._model = None
            self._np = None
            self.available = False
            self.method = "heuristic"

    # -------------------------------------------------------------- vectorizing
    @staticmethod
    def _vectorize(feats: dict) -> list[float]:
        """Map a feature dict onto the numeric baseline space (len 7)."""
        protocol = str(feats.get("protocol", ""))
        enc_proto = float(_PROTOCOL_ENC.get(protocol.lower(), 0.0))
        vec = [enc_proto, _ip_enc(str(feats.get("source_ip", "")))]
        for k in _NUMERIC_KEYS:
            raw = feats.get(k, 0)
            try:
                vec.append(float(raw))
            except (TypeError, ValueError):
                vec.append(0.0)
        return vec

    def _forest_score(self, vec: list[float]) -> tuple[bool, float]:
        np = self._np
        if np is None or self._model is None or self._baseline is None:
            return False, 0.0
        try:
            x = np.asarray([vec], dtype=np.float64)
            if len(x[0]) != self._baseline.shape[1]:
                x = x[:, : self._baseline.shape[1]]
            raw = float(self._model.score_samples(x)[0])
            anomaly = raw < -0.15
            score = 1.0 / (1.0 + math.exp(-raw * 2.0))
            return anomaly, round(score, 4)
        except Exception as exc:
            logger.debug("isolation forest scoring failed: %s", exc)
            return False, 0.0

    # ----------------------------------------------------------------- heuristic
    def _update_rolling(self, feats: dict) -> None:
        now = time.monotonic()
        if now - self._last_update < 1.0:
            return
        self._last_update = now
        for k in _NUMERIC_KEYS:
            raw = feats.get(k, 0)
            try:
                x = float(raw)
            except (TypeError, ValueError):
                continue
            stats = self._rolling[k]
            stats["n"] += 1
            delta = x - stats["mean"]
            stats["mean"] += delta / stats["n"]
            delta2 = x - stats["mean"]
            stats["m2"] += delta * delta2

    def _heuristic_score(self, feats: dict) -> tuple[bool, float]:
        max_z = 0.0
        for k in _NUMERIC_KEYS:
            raw = feats.get(k, 0)
            try:
                x = float(raw)
            except (TypeError, ValueError):
                continue
            stats = self._rolling[k]
            if stats["n"] < 5:
                continue
            var = stats["m2"] / (stats["n"] - 1)
            if var <= 1e-9:
                continue
            z = abs(x - stats["mean"]) / math.sqrt(var)
            max_z = max(max_z, z)
        anomaly = max_z >= 2.5
        score = max(0.0, min(1.0, max_z / 5.0))
        return anomaly, round(score, 4)

    # ------------------------------------------------------------------- public
    def analyze(self, feats: dict) -> dict:
        """Return {'anomaly', 'anomaly_score', 'method'} for one event dict."""
        if not self.enabled:
            return {"anomaly": False, "anomaly_score": 0.0, "method": "unavailable"}

        if self.available and self.method == "isolation_forest":
            vec = self._vectorize(feats)
            anomaly, score = self._forest_score(vec)
            if anomaly:
                return {"anomaly": True, "anomaly_score": score,
                        "method": "isolation_forest"}
            return {"anomaly": False, "anomaly_score": score,
                    "method": "isolation_forest"}

        self._update_rolling(feats)
        anomaly, score = self._heuristic_score(feats)
        return {"anomaly": anomaly, "anomaly_score": score, "method": "heuristic"}
