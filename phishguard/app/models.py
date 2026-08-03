"""Pydantic models for the PhishGuard REST + telemetry contract."""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Verdict(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class AnalyzeRequest(BaseModel):
    """URL or free-text target submitted for phishing analysis."""

    target: str = Field(..., min_length=1, max_length=4096)
    context: Optional[str] = Field(None, description="optional context (email body, chat snippet)")


class WhoIsSignal(BaseModel):
    domain: str
    creation_date: Optional[str] = None
    age_days: Optional[int] = None
    registrar: Optional[str] = None
    error: Optional[str] = None


class TyposquatSignal(BaseModel):
    matched_domain: str
    distance: int
    candidate: str


class UrgencySignal(BaseModel):
    urgency_score: float = Field(0.0, ge=0, le=1)
    triggers: list[str] = Field(default_factory=list)


class RiskReport(BaseModel):
    """Structured, actionable phishing report."""

    target: str
    domain: Optional[str] = None
    overall_score: float = Field(0.0, ge=0, le=100)
    severity: Severity = Severity.LOW
    verdict: Verdict = Verdict.BENIGN
    whois: Optional[WhoIsSignal] = None
    typosquats: list[TyposquatSignal] = Field(default_factory=list)
    urgency: UrgencySignal = Field(default_factory=UrgencySignal)
    indicators: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)
    mitigation: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


class ScoredEvent(BaseModel):
    """Telemetry projection pushed over the WebSocket to the Control Center."""

    event_id: str
    protocol: str
    source_ip: str
    source_port: int
    target_port: int
    username: str = ""
    user_agent: str = ""
    threat_score: float
    severity: str
    verdict: str
    summary: str
    indicators: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)
    mitigation: list[str] = Field(default_factory=list)
    timestamp: int
