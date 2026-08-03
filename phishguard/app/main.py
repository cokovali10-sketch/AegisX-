"""PhishGuard AI - FastAPI entrypoint.

Runs two surfaces on one process:
  * FastAPI (REST + WebSocket) on AEGISX_HTTP_PORT for URL/text analysis and
    the live dashboard event stream.
  * AegisX gRPC gateway on AEGISX_GRPC_PORT for decoy event intake.
"""
from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from .analyzers import nlp_urgency, score as score_engine, typosquat, whois_analyzer
from .config import get_settings
from .grpc_server import serve_grpc
from .intel.vectorstore import VectorStore
from .metrics import ANALYZE_LATENCY, HTTP_REQUESTS_DURATION, HTTP_REQUESTS_TOTAL
from .models import AnalyzeRequest, RiskReport, WhoIsSignal
from .ws_manager import manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("phishguard")

_grpc_server = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _grpc_server
    settings = get_settings()
    task = asyncio.create_task(start_grpc(settings.grpc_port))
    logger.info("PhishGuard AI started: http=:%s grpc=:%s", settings.http_port, settings.grpc_port)
    yield
    task.cancel()
    if _grpc_server is not None:
        await _grpc_server.stop(grace=5)


async def start_grpc(port: int):
    global _grpc_server
    _grpc_server = await serve_grpc(port)
    await _grpc_server.wait_for_termination()


app = FastAPI(title="AegisX PhishGuard AI", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health():
    vs = VectorStore(
        persist_path=get_settings().chroma_path,
        enabled=get_settings().vectorstore_enabled,
    )
    return {"status": "ok", "vectorstore": vs.stats(), "ts": int(time.time() * 1000)}


@app.get("/metrics")
async def metrics():
    """Prometheus exposition for scraping (see app/metrics.py)."""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        HTTP_REQUESTS_TOTAL.labels(request.method, request.url.path, "500").inc()
        raise
    elapsed = time.perf_counter() - start
    HTTP_REQUESTS_TOTAL.labels(
        request.method, request.url.path, str(response.status_code)).inc()
    HTTP_REQUESTS_DURATION.labels(request.method, request.url.path).observe(elapsed)
    return response


@app.post("/analyze")
async def analyze(req: AnalyzeRequest) -> RiskReport:
    """Phishing analysis pipeline for a URL or free-text target."""
    with ANALYZE_LATENCY.time():
        target = req.target

        # 1. Domain / WHOIS age
        domain = typosquat.extract_domain(target)
        whois: WhoIsSignal | None = None
        if domain:
            whois = whois_analyzer.analyze(domain)

        # 2. Typosquatting + raw IP targeting
        typos, typos_indicators = typosquat.analyze(target)
        raw_ip = typosquat.has_raw_ip(target)

        # 3. NLP / heuristic urgency
        urgency = nlp_urgency.analyze_url(target, req.context)

        # 4. Aggregate risk report
        report = score_engine.compose(
            target=target,
            whois=whois,
            typosquat_count=len(typos),
            typosquat_indicators=typos_indicators,
            urgency_score=urgency.urgency_score,
            urgency_triggers=urgency.triggers,
            raw_ip=raw_ip,
        )
        report.typosquats = typos
        return report


@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket):
    await websocket.accept()
    q = manager.register()
    try:
        # Hello frame so clients can confirm liveness.
        await websocket.send_json({"type": "hello", "version": "0.1.0"})
        while True:
            data = await q.get()
            await websocket.send_text(data)
    except WebSocketDisconnect:
        pass
    finally:
        manager.unregister(q)