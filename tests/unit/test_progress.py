import pytest
import asyncio
from agentguard.progress.models import MilestoneState, MilestoneStatus
from agentguard.models.run import Run
from agentguard.models.policy import ProgressPolicy
from agentguard.progress.detectors import evaluate_detectors

def make_run(non_tick=0):
    return Run(
        run_id="run_1", 
        status="RUNNING",
        task={"objective": "test_objective", "known_paths": []},
        created_at="now",
        flags={"non_tick_streak": non_tick}
    )

def test_stall_detector():
    run = make_run(7)
    policy = ProgressPolicy(enabled=True, stall_warn_actions=6, stall_escalate_actions=12)
    
    advisories, escalations = evaluate_detectors(run, [], [], policy)
    
    assert len(advisories) == 1
    assert advisories[0].code == "PRG-001"
    assert len(escalations) == 0

def test_stall_detector_escalate():
    run = make_run(12)
    policy = ProgressPolicy(enabled=True, stall_warn_actions=6, stall_escalate_actions=12)
    
    advisories, escalations = evaluate_detectors(run, [], [], policy)
    
    assert len(escalations) == 1
    assert escalations[0] == "STALL"

def test_off_plan_detector():
    run = make_run(0)
    policy = ProgressPolicy(enabled=True, plan_link_window=4, plan_link_min_ratio=0.5)
    
    # We need mock ActionRecords, but evaluate_detectors checks `a.params` for "plan_step_id".
    class MockAction:
        def __init__(self, params):
            self.params = params
    
    history = [
        MockAction({"command": "ls"}),
        MockAction({"command": "ls"}),
        MockAction({"command": "ls"}),
        MockAction({"command": "ls"})
    ]
    
    milestones = [MilestoneStatus(milestone_id="m1", state=MilestoneState.PENDING, updated_at="")]
    
    advisories, escalations = evaluate_detectors(run, history, milestones, policy)
    
    assert len(advisories) == 1
    assert advisories[0].code == "PRG-002"
