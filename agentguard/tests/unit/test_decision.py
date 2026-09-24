import pytest
from datetime import datetime
from agentguard.decision.engine import resolve_decision, DecisionInput, HistoryView
from agentguard.models.policy import DecisionPolicy, AnomalyPolicy, BreakerPolicy, GroundingPolicy, UncertaintyPolicy
from agentguard.registry import Verdict
from agentguard.models.run import Run

def test_decision_engine_ask():
    class MockRun:
        human_available = True

    inp = DecisionInput(
        phase="pre",
        action_id="act_1",
        action_type="cli.exec",
        fingerprint="fp1",
        verdict=Verdict.ASK_HUMAN,
        reason_codes=["TEST"],
        findings=[],
        run=MockRun(),
        hist=HistoryView(),
        policy=DecisionPolicy(),
        anomaly=AnomalyPolicy(),
        breaker=BreakerPolicy(),
        grounding=GroundingPolicy(),
        uncertainty=UncertaintyPolicy(),
        now=datetime.now(),
        action_id_hash=123
    )

    decision = resolve_decision(inp)
    assert decision.next_step.action == "ASK"

def test_decision_engine_halt():
    class MockRun:
        human_available = True

    inp = DecisionInput(
        phase="pre",
        action_id="act_1",
        action_type="cli.exec",
        fingerprint="fp1",
        verdict=Verdict.HALT,
        reason_codes=["TEST"],
        findings=[],
        run=MockRun(),
        hist=HistoryView(),
        policy=DecisionPolicy(),
        anomaly=AnomalyPolicy(),
        breaker=BreakerPolicy(),
        grounding=GroundingPolicy(),
        uncertainty=UncertaintyPolicy(),
        now=datetime.now(),
        action_id_hash=123
    )

    decision = resolve_decision(inp)
    assert decision.next_step.action == "PAUSED"
    assert decision.run_effect == "halt"
    assert decision.halt_reason == "GUARD_HALTED"
