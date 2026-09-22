"""
Decision Engine — §10.8
"""

from typing import Literal, List, Dict, Any
from pydantic import BaseModel
from datetime import datetime
from agentguard.registry import Verdict, ActionType
from agentguard.models.common import Finding, ExecutionResult
from agentguard.telemetry.anomaly import Signal
from agentguard.models.run import Run
from agentguard.models.escalation import EscalationSpec, EscalationKind
from agentguard.models.policy import DecisionPolicy

class HistoryView(BaseModel):
    consecutive_failures: int = 0
    infra_failures_consecutive: int = 0
    prior_denies: int = 0
    ungrounded_flags_recent: int = 0
    u_streak: int = 0
    halfopen: bool = False

class NextStep(BaseModel):
    action: Literal["EXECUTE", "REPLAN", "ASK", "PAUSED"]

class Decision(BaseModel):
    next_step: NextStep
    retry_after_ms: int | None = None
    advice: List[str] = []
    run_effect: Literal["none", "pause", "halt"] = "none"
    halt_reason: str | None = None
    pause_reason: str | None = None
    escalation: EscalationSpec | None = None

class DecisionInput(BaseModel):
    phase: Literal["pre", "post"]
    action_id: str
    action_type: ActionType
    fingerprint: str
    verdict: Verdict
    reason_codes: List[str]
    findings: List[Finding]
    result: ExecutionResult | None = None
    signals: List[Signal] = []
    run: Any
    hist: HistoryView
    policy: DecisionPolicy
    now: datetime
    action_id_hash: int

def resolve_decision(inp: DecisionInput) -> Decision:
    # 1. Base Escalations
    # C-13: ungrounded streak
    if inp.hist.ungrounded_flags_recent >= inp.policy.ungrounded_streak_escalate:
        return Decision(
            next_step=NextStep(action="PAUSED"),
            run_effect="pause",
            pause_reason="UNGROUNDED",
            escalation=EscalationSpec(kind=EscalationKind.UNGROUNDED, severity=55, title="Ungrounded", summary="Streak", suggested="Check")
        )
    # C-14: low conf streak
    if inp.hist.u_streak >= inp.policy.low_conf_streak:
        return Decision(
            next_step=NextStep(action="PAUSED"),
            run_effect="pause",
            pause_reason="LOW_CONFIDENCE_STREAK",
            escalation=EscalationSpec(kind=EscalationKind.LOW_CONFIDENCE_STREAK, severity=50, title="Low Conf", summary="Streak", suggested="Check")
        )
        
    # 2. Map verdict to NextStep
    v = inp.verdict
    d = Decision(next_step=NextStep(action="REPLAN"))
    
    if v == Verdict.HALT:
        d.next_step.action = "PAUSED"
        d.run_effect = "halt"
        d.halt_reason = "GUARD_HALTED"
    elif v == Verdict.DENY:
        d.next_step.action = "REPLAN"
    elif v == Verdict.ASK_HUMAN:
        if inp.run.human_available:
            d.next_step.action = "ASK"
        else:
            if inp.policy.auto_reject_asks:
                d.next_step.action = "REPLAN"
            else:
                d.next_step.action = "PAUSED"
                d.run_effect = "pause"
                d.pause_reason = "HUMAN_REQUIRED"
    elif v in (Verdict.ALLOW, Verdict.ALLOW_WITH_GRANT):
        d.next_step.action = "EXECUTE"
        
    return d
