"""
Verdict merge — §1.5.2 P5

Deterministic merge of findings into a single verdict, risk score,
and ordered list of reason codes.
"""

from __future__ import annotations

from agentguard.models.common import Finding
from agentguard.registry import VERDICT_ORDER, Verdict


def merge_findings(
    findings: list[Finding],
    human_available: bool,
    policy: Any = None,
) -> tuple[Verdict, int, list[str]]:
    """
    Merge findings into (verdict, risk_score, reason_codes). §1.5.2 P5

    verdict = max(f.verdict_hint for f in findings, key=VERDICT_ORDER)
    risk_score = 0 if no findings else:
        max_sev + min(20, 5 * (n_high_sev - 1))  where n counts findings with sev >= 40
        (if n == 0, risk = max_sev)
    reason_codes = unique reason_code of findings with sev >= 40, ordered by sev desc.

    If verdict == ASK_HUMAN and human not available → DENY with HUMAN_UNAVAILABLE.
    """
    if not findings:
        return Verdict.ALLOW, 0, []

    # Compute verdict: max over verdict_hint by VERDICT_ORDER
    verdict = Verdict.ALLOW
    for f in findings:
        if VERDICT_ORDER[f.verdict_hint] > VERDICT_ORDER[verdict]:
            verdict = f.verdict_hint

    # Compute risk_score
    max_sev = max(f.severity for f in findings)
    high_sev_findings = [f for f in findings if f.severity >= 40]
    n = len(high_sev_findings)

    if n == 0:
        risk_score = max_sev
    else:
        risk_score = min(100, max_sev + min(20, 5 * (n - 1)))

    # Compute reason_codes: unique, ordered by severity desc
    high_sev_findings.sort(key=lambda f: f.severity, reverse=True)
    reason_codes: list[str] = []
    seen: set[str] = set()
    for f in high_sev_findings:
        if f.reason_code not in seen:
            reason_codes.append(f.reason_code)
            seen.add(f.reason_code)

    # Human availability check — §0.10.4
    if verdict == Verdict.ASK_HUMAN and not human_available:
        verdict = Verdict.DENY
        if "HUMAN_UNAVAILABLE" not in seen:
            reason_codes.append("HUMAN_UNAVAILABLE")

    return verdict, risk_score, reason_codes
