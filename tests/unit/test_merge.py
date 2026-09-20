import pytest

from agentguard.models.common import Finding
from agentguard.registry import Verdict
from agentguard.hub.merge import merge_findings

def _f(verdict_hint: str, severity: int, reason: str = "TEST") -> Finding:
    return Finding(
        finding_id="fnd_test",
        source="hub",
        rule_id="TEST-001",
        reason_code=reason,
        severity=severity,
        verdict_hint=Verdict(verdict_hint),
        message="test",
        evidence={},
    )

def test_merge_no_findings():
    v, r, codes = merge_findings([], human_available=True)
    assert v == Verdict.ALLOW
    assert r == 0
    assert codes == []

def test_merge_highest_verdict():
    findings = [
        _f(Verdict.ALLOW, 10, "A"),
        _f(Verdict.ASK_HUMAN, 50, "B"),
        _f(Verdict.DENY, 70, "C"),
    ]
    v, r, codes = merge_findings(findings, human_available=True)
    assert v == Verdict.DENY
    # Max sev 70, n_high = 2 => 70 + min(20, 5*(2-1)) = 75
    assert r == 75
    # Order by severity desc => C (70) then B (50)
    assert codes == ["C", "B"]

def test_merge_risk_formula_zero_high_sev():
    findings = [
        _f(Verdict.ALLOW, 39, "A"),
        _f(Verdict.ALLOW, 20, "B"),
    ]
    v, r, codes = merge_findings(findings, human_available=True)
    assert v == Verdict.ALLOW
    assert r == 39
    assert codes == []

def test_merge_risk_formula_multiple_high_sev():
    findings = [
        _f(Verdict.ASK_HUMAN, 50, "A"),
        _f(Verdict.ASK_HUMAN, 60, "B"),
        _f(Verdict.ASK_HUMAN, 45, "C"),
        _f(Verdict.ASK_HUMAN, 40, "D"),
        _f(Verdict.ASK_HUMAN, 80, "E"),
        _f(Verdict.ASK_HUMAN, 85, "F"), # max
    ]
    # n_high = 6
    # risk = 85 + min(20, 5 * (6-1)) = 85 + min(20, 25) = 85 + 20 = 100 max
    v, r, codes = merge_findings(findings, human_available=True)
    assert v == Verdict.ASK_HUMAN
    assert r == 100
    assert codes == ["F", "E", "B", "A", "C", "D"]

def test_merge_human_unavailable():
    findings = [
        _f(Verdict.ASK_HUMAN, 50, "A"),
    ]
    v, r, codes = merge_findings(findings, human_available=False)
    assert v == Verdict.DENY
    assert r == 50
    assert codes == ["A", "HUMAN_UNAVAILABLE"]
