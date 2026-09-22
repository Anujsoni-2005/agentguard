import pytest
from unittest.mock import MagicMock
from agentguard.telemetry.breaker import CircuitBreaker, BreakerState
from agentguard.models.policy import BreakerPolicy
from agentguard.models.run import Run
from agentguard.telemetry.anomaly import Signal
from agentguard.registry import RunStatus, ActionType

def make_run():
    run = MagicMock(spec=Run)
    run.status = RunStatus.RUNNING
    run.pause_reason = None
    run.halt_reason = None
    return run

def make_action(fp, action_type=ActionType.CLI_EXEC):
    action = MagicMock()
    action.fingerprint = fp
    action.proposal.action_type = action_type
    return action

def test_breaker_lifecycle():
    policy = BreakerPolicy(enabled=True, probe_actions=2, cooldown_base_s=30)
    breaker = CircuitBreaker(policy)
    run = make_run()
    
    # (a) TRIP via #2
    signal = Signal("ANM-001", "TRIP", "Test", {"fps": ["fp1"]})
    breaker.trip(run, signal)
    
    assert breaker.state.state == "OPEN"
    assert run.status == RunStatus.PAUSED
    assert run.pause_reason == "CIRCUIT_OPEN"
    assert breaker.state.trip_count == 1
    assert "fp1" in breaker.state.tripped_fingerprints
    
    # (c) resolve resume_with_guidance -> HALF_OPEN
    breaker.resume(run)
    assert breaker.state.state == "HALF_OPEN"
    assert breaker.state.probes_remaining == 2
    assert run.status == RunStatus.RUNNING
    
    # (d) tripped fp -> DENY CIRCUIT_OPEN REPLAN
    act_fp1 = make_action("fp1")
    finding = breaker.pre_check(act_fp1, run)
    assert finding is not None
    assert finding.rule_id == "ANM-100"
    
    # high-impact new action
    act_fp2 = make_action("fp2", ActionType.CLI_EXEC)
    finding_hi = breaker.pre_check(act_fp2, run)
    assert finding_hi is not None
    assert finding_hi.rule_id == "ANM-101"
    
    # Low impact action (fs.read)
    act_fp3 = make_action("fp3", ActionType.FS_READ)
    finding_li = breaker.pre_check(act_fp3, run)
    assert finding_li is None
    
    # (e) two successful new-fp probes -> CLOSED
    breaker.observe("OK", None)
    assert breaker.state.probes_remaining == 1
    assert breaker.state.state == "HALF_OPEN"
    
    breaker.observe("OK", None)
    assert breaker.state.probes_remaining == 0
    assert breaker.state.state == "CLOSED"
    assert breaker.state.tripped_fingerprints == []
    
    # (f) failing probe -> OPEN with cooldown 60 s
    breaker.trip(run, signal)
    assert breaker.state.state == "OPEN"
    assert breaker.state.trip_count == 2
    assert breaker.state.cooldown_s == 60 # 30 * 2^1

    # third trip -> still allowed
    breaker.resume(run)
    breaker.trip(run, signal)
    assert breaker.state.trip_count == 3
    assert run.status == RunStatus.PAUSED
    
    # fourth -> HALT
    breaker.resume(run)
    breaker.trip(run, signal)
    assert breaker.state.trip_count == 4
    assert run.status == RunStatus.HALTED
    assert run.halt_reason == "CIRCUIT_TRIPPED_TOO_OFTEN"
