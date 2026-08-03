"""Prometheus instrumentation for the PhishGuard gateway.

Exposed at GET /metrics (see app/main.py) and scraped by the `prometheus`
profile service in docker-compose.yml. Kept dependency-light: only
prometheus-client, no middleware framework.
"""
from __future__ import annotations

from prometheus_client import Counter, Histogram

# Decoy intake / scoring path (grpc_server.py)
GRPC_EVENTS_TOTAL = Counter(
    "aegisx_grpc_events_total",
    "Honeypot events scored by PhishGuard, by protocol",
    ["protocol"],
)
GRPC_VERDICTS_TOTAL = Counter(
    "aegisx_grpc_verdicts_total",
    "Scored events by verdict",
    ["verdict"],
)

# SOAR action chain (grpc_advanced.py / soar/playbook.py)
SOAR_PLAYBOOKS_RUN_TOTAL = Counter(
    "aegisx_soar_playbooks_run_total",
    "SOAR playbook executions, by playbook name",
    ["playbook"],
)
SOAR_BLOCKS_ISSUED_TOTAL = Counter(
    "aegisx_soar_firewall_blocks_issued_total",
    "Firewall block commands dispatched to the ShadowPot command plane",
)

# REST surface (main.py)
HTTP_REQUESTS_TOTAL = Counter(
    "aegisx_http_requests_total",
    "HTTP requests served, by method/path/status",
    ["method", "path", "status"],
)
HTTP_REQUESTS_DURATION = Histogram(
    "aegisx_http_request_duration_seconds",
    "HTTP request latency, by method/path",
    ["method", "path"],
)
ANALYZE_LATENCY = Histogram(
    "aegisx_analyze_seconds",
    "Phishing analysis pipeline latency",
)
