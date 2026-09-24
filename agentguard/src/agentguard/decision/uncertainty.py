"""
Uncertainty & Calibration — §10.7
"""

from typing import List, Dict, Any
from agentguard.models.common import Finding
from agentguard.registry import Verdict
from agentguard.models.policy import UncertaintyPolicy

class CalibrationStats:
    def __init__(self):
        # bin index 0..4 -> (n, sum_conf, succ)
        self.bins: Dict[int, Dict[str, float]] = {
            i: {"n": 0, "sum_conf": 0.0, "succ": 0.0} for i in range(5)
        }
        self.prior_strength = 10.0

    def update(self, conf: float, success: bool):
        b = min(4, int(conf * 5))
        self.bins[b]["n"] += 1
        self.bins[b]["sum_conf"] += conf
        if success:
            self.bins[b]["succ"] += 1

    def calibrated(self, conf: float) -> float:
        b = min(4, int(conf * 5))
        n = self.bins[b]["n"]
        if n == 0:
            return conf
        succ = self.bins[b]["succ"]
        return (succ + self.prior_strength * conf) / (n + self.prior_strength)

class UncertaintyEvaluator:
    def __init__(self, policy: UncertaintyPolicy, cal_stats: CalibrationStats):
        self.policy = policy
        self.cal_stats = cal_stats

    def evaluate(self, conf: float | None, findings: List[Finding], is_high_impact: bool, novel: bool, failure_ratio: float, current_verdict: Verdict, action_id: str) -> tuple[float, Finding | None]:
        if not self.policy.enabled:
            return 0.0, None

        c_stated = conf if conf is not None else self.policy.default_confidence
        c_cal = self.cal_stats.calibrated(c_stated)

        g = 0.0
        for f in findings:
            if f.source == "grounding":
                if f.verdict_hint == Verdict.ASK_HUMAN:
                    g = 1.0
                    break
                elif getattr(f, 'evidence', {}).get("advisory"):
                    g = max(g, 0.5)

        n_amb = sum(1 for f in findings if f.source in ("cli","net","fs","gui","rules","policy") and 40 <= f.severity <= 59 and f.verdict_hint == Verdict.ASK_HUMAN)
        a = min(1.0, n_amb / 3.0)
        
        n = 1.0 if (is_high_impact and novel) else 0.0
        f = failure_ratio

        u = round(
            self.policy.weights.confidence * (1 - c_cal) +
            self.policy.weights.grounding * g +
            self.policy.weights.ambiguity * a +
            self.policy.weights.novelty * n +
            self.policy.weights.failure * f,
            3
        )

        applies = (self.policy.apply_to_impact == "all") or is_high_impact
        new_finding = None

        if applies and u >= self.policy.ask_above and current_verdict not in (Verdict.ASK_HUMAN, Verdict.DENY, Verdict.HALT):
            new_finding = Finding(
                finding_id=f"fnd_unc_{action_id}",
                source="decision",
                rule_id="GRD-100",
                reason_code="HIGH_UNCERTAINTY",
                severity=50,
                verdict_hint=Verdict.ASK_HUMAN,
                message=f"High uncertainty ({u})",
                evidence={"u": u}
            )
        elif u >= self.policy.advise_above:
            new_finding = Finding(
                finding_id=f"fnd_unc_{action_id}",
                source="decision",
                rule_id="GRD-100",
                reason_code="HIGH_UNCERTAINTY",
                severity=30,
                verdict_hint=Verdict.ALLOW,
                message=f"High uncertainty ({u}); consider verifying before acting",
                evidence={"u": u, "advisory": True}
            )

        return u, new_finding
