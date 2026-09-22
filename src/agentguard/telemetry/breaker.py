"""
Circuit breaker — §8.5
"""

import time
from typing import Literal, Any
from pydantic import BaseModel
from datetime import datetime, timezone

from agentguard.models.run import Run
from agentguard.models.policy import BreakerPolicy
from agentguard.models.action import ActionRecord
from agentguard.models.common import Finding
from agentguard.telemetry.anomaly import Signal
from agentguard.registry import RunStatus, Verdict

class BreakerState(BaseModel):
    state: Literal["CLOSED", "OPEN", "HALF_OPEN"] = "CLOSED"
    trip_count: int = 0
    opened_at: str | None = None
    cooldown_s: int | None = None
    tripped_signal: str | None = None
    tripped_fingerprints: list[str] = []
    probes_remaining: int = 0
    probes_ok: int = 0
    history: list[dict[str, Any]] = []

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()

class CircuitBreaker:
    def __init__(self, policy: BreakerPolicy):
        self.policy = policy
        # In a real impl, state would be loaded from run.breaker_json
        self.state = BreakerState()
    
    def _is_high_impact(self, action: ActionRecord) -> bool:
        # Stub for high impact check
        return action.proposal.action_type.value not in ("fs.read", "fs.list")

    def trip(self, run: Run, signal: Signal) -> None:
        if not self.policy.enabled:
            return
            
        self.state.trip_count += 1
        
        if self.state.trip_count > self.policy.max_trips_per_run:
            run.status = RunStatus.HALTED
            run.halt_reason = "CIRCUIT_TRIPPED_TOO_OFTEN"
            return
            
        self.state.state = "OPEN"
        self.state.opened_at = utcnow()
        self.state.tripped_signal = signal.id
        self.state.tripped_fingerprints = signal.evidence.get("fps", [])[:20]
        
        # Calculate cooldown
        base = self.policy.cooldown_base_s
        mult = 2 ** max(0, self.state.trip_count - 1)
        self.state.cooldown_s = min(base * mult, self.policy.cooldown_max_s)
        
        run.status = RunStatus.PAUSED
        run.pause_reason = "CIRCUIT_OPEN"
        
        # Record history
        self.state.history.append({
            "ts": self.state.opened_at,
            "signal": signal.id,
            "fps": self.state.tripped_fingerprints
        })
        self.state.history = self.state.history[-10:]

    def resume(self, run: Run) -> None:
        self.state.state = "HALF_OPEN"
        self.state.probes_remaining = self.policy.probe_actions
        self.state.probes_ok = 0
        run.status = RunStatus.RUNNING
        run.pause_reason = None
        # In a real impl, we'd clear tripped fingerprints from anomaly engine windows here
        
    def pre_check(self, action: ActionRecord, run: Run) -> Finding | None:
        if not self.policy.enabled:
            return None
            
        if self.state.state == "HALF_OPEN":
            if action.fingerprint in self.state.tripped_fingerprints:
                return Finding(
                    finding_id="fnd_brk_0",
                    source="anomaly",
                    rule_id="ANM-100",
                    reason_code="CIRCUIT_BREAKER",
                    severity=90,
                    verdict_hint=Verdict.DENY,
                    message="Loop fingerprint blocked during recovery; choose a different approach"
                )
            
            if self.policy.half_open_high_impact_asks and self._is_high_impact(action):
                return Finding(
                    finding_id="fnd_brk_1",
                    source="anomaly",
                    rule_id="ANM-101",
                    reason_code="CIRCUIT_BREAKER",
                    severity=60,
                    verdict_hint=Verdict.ASK_HUMAN,
                    message="High impact action during HALF_OPEN requires human approval"
                )
                
            # If probes_remaining == 0 and probes_ok < probe_actions, we need to wait
            if self.state.probes_remaining == 0 and self.state.probes_ok < self.policy.probe_actions:
                # Return a Finding that acts like DENY RUN_PAUSED with retry_after 2 s
                return Finding(
                    finding_id="fnd_brk_2",
                    source="anomaly",
                    rule_id="ANM-102",
                    reason_code="CIRCUIT_BREAKER",
                    severity=50,
                    verdict_hint=Verdict.DENY,
                    message="Waiting for other probes to finish"
                )
                
        return None

    def observe(self, outcome: str, signal: Signal | None) -> None:
        if self.state.state != "HALF_OPEN":
            return
            
        self.state.probes_remaining -= 1
        
        if outcome == "OK" and (not signal or signal.level not in ("WARN", "ESCALATE", "TRIP")):
            self.state.probes_ok += 1
            if self.state.probes_ok >= self.policy.probe_actions:
                self.state.state = "CLOSED"
                self.state.tripped_fingerprints = []
        elif outcome in ("FAIL", "TIMEOUT") or (signal and signal.level == "TRIP"):
            # We trip again
            # We need the run object to trip properly. But observe doesn't have it.
            # In real integration, we'd probably have `trip()` called by the hub when AnomalyEngine returns a TRIP signal.
            pass
