"""
Escalation models — §8.6
"""

from enum import StrEnum
from typing import Any, Literal
from pydantic import BaseModel, Field

class EscalationKind(StrEnum):
    BREAKER = "BREAKER"
    BUDGET = "BUDGET"
    COMPROMISE = "COMPROMISE"
    STALL = "STALL"
    MILESTONE_OVERRUN = "MILESTONE_OVERRUN"
    OFF_TRACK = "OFF_TRACK"
    UNGROUNDED = "UNGROUNDED"
    LOW_CONFIDENCE_STREAK = "LOW_CONFIDENCE_STREAK"
    INTEGRITY = "INTEGRITY"
    MANUAL = "MANUAL"

class Escalation(BaseModel):
    escalation_id: str
    run_id: str
    kind: EscalationKind
    status: Literal["OPEN", "RESOLVED", "EXPIRED"]
    severity: int
    title: str = Field(max_length=120)
    summary: str = Field(max_length=1000)
    evidence: dict[str, Any]
    options: list[Literal["resume", "resume_with_guidance", "halt", "dismiss"]]
    created_at: str
    expires_at: str
    resolved_at: str | None = None
    resolved_by: str | None = None
    resolution: str | None = None
    note: str | None = None
    guidance: str | None = None

class EscalationSpec(BaseModel):
    kind: EscalationKind
    severity: int
    title: str
    summary: str
    suggested: str

class Advisory(BaseModel):
    advisory_id: str
    level: Literal["INFO", "WARN", "ERROR"]
    code: str
    message: str
    delivered: bool = False

