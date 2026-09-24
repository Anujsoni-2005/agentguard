"""
Grounding Analyzer — §10.6
"""

from typing import List, Dict, Any
from agentguard.models.common import Finding
from agentguard.decision.obsindex import GroundingFacts
from agentguard.registry import Verdict
from agentguard.models.policy import GroundingPolicy

class GroundingAnalyzer:
    def __init__(self, policy: GroundingPolicy):
        self.policy = policy
        self.id = "grounding"

    def analyze(self, facts: GroundingFacts | None, classes: set[str], action_id: str) -> List[Finding]:
        if not self.policy.enabled:
            return []
            
        req = classes.intersection(self.policy.require_evidence_for)
        hi = classes.intersection({"execution", "fs_write", "net_out", "secrets"}) # Mock HIGH_IMPACT set
        
        if facts is None:
            if req:
                return [Finding(
                    finding_id=f"fnd_grd_{action_id}_0",
                    source="grounding",
                    rule_id="GRD-000",
                    reason_code="ANALYZER_ERROR",
                    severity=55,
                    verdict_hint=Verdict.ASK_HUMAN,
                    message="Grounding prefetch failed, evidence required"
                )]
            return []
            
        findings = []
        fnd_idx = 1
        
        def add_fnd(rule: str, reason: str, sev: int, verdict: Verdict, msg: str, is_adv: bool = False):
            nonlocal fnd_idx
            findings.append(Finding(
                finding_id=f"fnd_grd_{action_id}_{fnd_idx}",
                source="grounding",
                rule_id=rule,
                reason_code=reason,
                severity=sev,
                verdict_hint=verdict,
                message=msg,
                evidence={"advisory": True} if is_adv else {}
            ))
            fnd_idx += 1

        # GRD-001
        invalid_cits = []
        for i, c in enumerate(facts.citations):
            invalid = (not c.get("found_action") or not c.get("executed_ok") or c.get("quote_found") is False)
            if invalid:
                invalid_cits.append(i)
                
        if invalid_cits:
            msg = f"Citation {invalid_cits[0]} invalid"
            if req:
                add_fnd("GRD-001", "INVALID_EVIDENCE", 45, Verdict.ASK_HUMAN, msg)
            else:
                add_fnd("GRD-001", "INVALID_EVIDENCE", 30, Verdict.ALLOW, msg, True)
                
        # GRD-002
        has_valid = len(facts.citations) > len(invalid_cits)
        has_ungrounded = any(not t.grounded for t in facts.targets)
        if req and not has_valid and not has_ungrounded:
            if self.policy.strict_evidence:
                add_fnd("GRD-002", "UNGROUNDED_ACTION", 45, Verdict.ASK_HUMAN, "Provide valid citation")
            else:
                add_fnd("GRD-002", "UNGROUNDED_ACTION", 30, Verdict.ALLOW, "Cite observation", True)
                
        # GRD-003
        if hi and has_ungrounded:
            ungrounded_t = next(t for t in facts.targets if not t.grounded)
            add_fnd("GRD-003", "UNGROUNDED_ACTION", 55, Verdict.ASK_HUMAN, f"Target '{ungrounded_t.value}' never observed")
            
        # GRD-005
        if any(a.get("contradicted") for a in facts.rationale_assertions):
            if req:
                add_fnd("GRD-005", "CONTRADICTORY_RATIONALE", 45, Verdict.ASK_HUMAN, "Rationale contradicts execution history")
            else:
                add_fnd("GRD-005", "CONTRADICTORY_RATIONALE", 35, Verdict.ALLOW, "Rationale contradiction", True)
                
        return findings
