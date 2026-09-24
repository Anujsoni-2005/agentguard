"""
Progress detectors — §9.6
"""

from typing import List, Any
from agentguard.models.run import Run
from agentguard.models.action import ActionRecord
from agentguard.models.policy import ProgressPolicy
from agentguard.progress.models import MilestoneStatus
from agentguard.models.escalation import Advisory, EscalationKind

def evaluate_stall(run: Run, history: List[ActionRecord], policy: ProgressPolicy) -> tuple[List[Advisory], List[EscalationKind]]:
    # PRG-001 stall
    # Note: real logic requires calculating ticks based on ws_epoch, milestone changes, and fp uniqueness
    # Mocking basic non-tick count here for architectural stub
    non_tick_count = run.flags.get("non_tick_streak", 0)
    advisories = []
    escalations = []
    
    if non_tick_count >= policy.stall_escalate_actions:
        escalations.append(EscalationKind.STALL)
    elif non_tick_count >= policy.stall_warn_actions:
        advisories.append(Advisory(
            advisory_id="adv_prg_001",
            level="WARN",
            code="PRG-001",
            message=f"No measurable progress in the last {non_tick_count} actions. Re-read the objective, review the last results, and try a different approach."
        ))
    
    return advisories, escalations

def evaluate_detectors(run: Run, history: List[ActionRecord], milestones: List[MilestoneStatus], policy: ProgressPolicy) -> tuple[List[Advisory], List[EscalationKind]]:
    advisories = []
    escalations = []
    
    if not policy.enabled:
        return advisories, escalations
        
    adv_stall, esc_stall = evaluate_stall(run, history, policy)
    advisories.extend(adv_stall)
    escalations.extend(esc_stall)
    
    # PRG-002 off-plan
    if milestones:
        recent = history[-policy.plan_link_window:]
        if recent:
            linked = sum(1 for a in recent if "plan_step_id" in a.params)
            if (linked / len(recent)) < policy.plan_link_min_ratio:
                advisories.append(Advisory(
                    advisory_id="adv_prg_002", level="WARN", code="PRG-002",
                    message="link actions to plan steps"
                ))
                
    # PRG-005 regression
    for m in milestones:
        if m.state == "REGRESSED":
            advisories.append(Advisory(
                advisory_id=f"adv_prg_005_{m.milestone_id}", level="WARN", code="PRG-005",
                message=f"Milestone {m.milestone_id} has regressed."
            ))
            
    # PRG-006 unverified claim
    for m in milestones:
        if m.state == "DONE_CLAIMED":
            # Real logic checks if it persisted claim_grace_actions actions
            pass

    return advisories, escalations
