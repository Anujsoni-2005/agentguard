"""
Anomaly engine — §8.4
"""

import time
import collections
from dataclasses import dataclass
from typing import Literal, Any
from pydantic import BaseModel

from agentguard.models.action import ActionRecord
from agentguard.models.policy import AnomalyPolicy
from agentguard.registry import ActionType

@dataclass
class ActionObs:
    seq: int
    t: float                      # time.monotonic() at decision
    fp: str
    action_type: str
    outcome: Literal["OK", "FAIL", "TIMEOUT", "DENIED", "ASKED", "REJECTED", "EXPIRED"]
    out_hash: str | None          # sha256 of normalized stdout+stderr+exit_code
    dur_ms: float | None
    ws_epoch: int
    targets: frozenset[str]       # "host:pypi.org", "path:src/a.py"
    max_sev: int
    reason_codes: tuple[str, ...]
    rule_ids_ge80: tuple[str, ...]

@dataclass
class Signal:
    id: str
    level: Literal["INFO", "WARN", "ESCALATE", "TRIP"]
    message: str
    evidence: dict[str, Any]

def extract_targets(action: ActionRecord, scratch: dict[str, Any]) -> frozenset[str]:
    # Extract targets based on action type
    # net -> host:<h>
    # fs -> path:<rel>
    # cli -> path: and host: from cli_ir in scratch
    # gui -> host:<page host>
    targets = set()
    act_type = action.proposal.action_type
    params = action.params
    
    if act_type == ActionType.NET_HTTP:
        url = getattr(params, "url", "")
        # Very basic host extraction from url
        if "://" in url:
            host = url.split("://", 1)[1].split("/", 1)[0]
            targets.add(f"host:{host}")
    elif act_type in (ActionType.FS_READ, ActionType.FS_WRITE, ActionType.FS_DELETE, ActionType.FS_LIST):
        path = getattr(params, "path", "")
        targets.add(f"path:{path}")
    elif act_type == ActionType.CLI_EXEC:
        cli_ir = scratch.get("cli_ir", {})
        for h in cli_ir.get("static_hosts", []):
            targets.add(f"host:{h}")
        for p in cli_ir.get("resolved_paths", []):
            targets.add(f"path:{p}")
    # GUI is stubbed for now
    
    return frozenset(targets)

class AnomalyEngine:
    def __init__(self, policy: AnomalyPolicy):
        self.policy = policy
        self.window: collections.deque[ActionObs] = collections.deque(maxlen=policy.window_size)
        # target -> (timestamp, rule_ids)
        self.denied_targets: dict[str, tuple[float, tuple[str, ...]]] = {}
        self.first_seen_hosts: dict[str, float] = {}
        self.secret_outputs_count: int = 0
    
    def observe(self, action: ActionRecord, scratch: dict[str, Any], outcome: Literal["OK", "FAIL", "TIMEOUT", "DENIED", "ASKED", "REJECTED", "EXPIRED"], out_hash: str | None, dur_ms: float | None, ws_epoch: int, run: Any = None) -> list[Signal]:
        if not self.policy.enabled:
            return []
            
        targets = extract_targets(action, scratch)
        
        # Calculate max_sev, reason_codes, rule_ids_ge80
        max_sev = max((f.severity for f in action.findings), default=0)
        reason_codes = tuple(action.reason_codes)
        rule_ids_ge80 = tuple(f.rule_id for f in action.findings if f.severity >= 80 and f.rule_id)
        
        obs = ActionObs(
            seq=action.seq,
            t=time.monotonic(),
            fp=action.fingerprint,
            action_type=action.proposal.action_type.value,
            outcome=outcome,
            out_hash=out_hash,
            dur_ms=dur_ms,
            ws_epoch=ws_epoch,
            targets=targets,
            max_sev=max_sev,
            reason_codes=reason_codes,
            rule_ids_ge80=rule_ids_ge80
        )
        
        signals = []
        now = obs.t
        
        # We process signals before appending to window, or after?
        # The spec says "WARN when the newest ... observations ... are all in F". This implies the current observation is in the window.
        # Update first_seen_hosts
        for t_str in targets:
            if t_str.startswith("host:") and t_str not in self.first_seen_hosts:
                self.first_seen_hosts[t_str] = now
                
        # Update evasion state (ANM-009 preprocessing)
        if outcome in ("DENIED", "REJECTED") and max_sev >= 60:
            for t_str in targets:
                self.denied_targets[t_str] = (now, rule_ids_ge80)
        
        # ANM-012 secret outputs preprocessing
        if action.result and action.result.output_tainted: # Just a heuristic if redactor count isn't exposed directly, but redactor might not be here. Wait, action.findings? Spec says "Redactor.count > 0, any kind". Wait, how to know?
            # actually we don't have redactor count on action directly in this simplified model.
            pass
            
        self.window.append(obs)
        window_list = list(self.window)
        
        # ANM-001 repeat-failure loop
        fp_obs = [o for o in window_list if o.fp == obs.fp]
        if len(fp_obs) >= self.policy.repeat_fail_consecutive_warn:
            recent_k = fp_obs[-self.policy.repeat_fail_consecutive_warn:]
            if all(o.outcome in ("FAIL", "TIMEOUT", "DENIED", "REJECTED") for o in recent_k):
                fp_fails = [o for o in fp_obs if o.outcome in ("FAIL", "TIMEOUT", "DENIED", "REJECTED")]
                trip_window = [o for o in fp_fails if now - o.t <= self.policy.repeat_fail_window_s]
                if len(trip_window) >= self.policy.repeat_fail_trip_count:
                    signals.append(Signal("ANM-001", "TRIP", f"Repeated failures for {obs.fp}", {"fps": [obs.fp]}))
                else:
                    signals.append(Signal("ANM-001", "WARN", f"Repeated failures for {obs.fp}", {"fps": [obs.fp]}))

        # ANM-002 repeat-same-output loop
        if obs.outcome == "OK":
            fp_ok = [o for o in window_list if o.fp == obs.fp and o.outcome == "OK"]
            count = 0
            for o in reversed(fp_ok):
                if o.out_hash == obs.out_hash and o.ws_epoch == obs.ws_epoch:
                    count += 1
                else:
                    break
            if count >= self.policy.repeat_same_output_trip:
                signals.append(Signal("ANM-002", "TRIP", f"Repeated exact same output for {obs.fp}", {"fps": [obs.fp]}))
            elif count >= self.policy.repeat_same_output_warn:
                signals.append(Signal("ANM-002", "WARN", f"Repeated exact same output for {obs.fp}", {"fps": [obs.fp]}))

        # ANM-003 velocity
        warn_win = [o for o in window_list if now - o.t <= self.policy.velocity_warn_window_s]
        trip_win = [o for o in window_list if now - o.t <= self.policy.velocity_trip_window_s]
        if len(trip_win) >= self.policy.velocity_trip_count:
            signals.append(Signal("ANM-003", "TRIP", "High action velocity", {}))
        elif len(warn_win) >= self.policy.velocity_warn_count:
            signals.append(Signal("ANM-003", "WARN", "High action velocity", {}))

        # ANM-004 oscillation
        s = [o.fp for o in window_list[-self.policy.periodic_lookback:]]
        max_p_cycles = 0
        best_p, best_cycles = 0, 0
        for p in range(2, self.policy.periodic_max_period + 1):
            if len(s) < p: continue
            block = s[-p:]
            if len(set(block)) == 1: continue
            
            m = 1
            while len(s) >= p * (m + 1):
                if s[-p*(m+1) : -p*m] == block:
                    m += 1
                else:
                    break
            
            if m >= 2:
                if p * m > max_p_cycles:
                    max_p_cycles = p * m
                    best_p, best_cycles = p, m
        if best_cycles >= self.policy.periodic_trip_cycles:
            signals.append(Signal("ANM-004", "TRIP", f"Oscillation detected", {"fps": s[-best_p:]}))
        elif best_cycles >= self.policy.periodic_warn_cycles:
            signals.append(Signal("ANM-004", "WARN", f"Oscillation detected", {"fps": s[-best_p:]}))

        # ANM-005 deny streak
        if obs.outcome in ("DENIED", "REJECTED"):
            consecutive = 0
            for o in reversed(window_list):
                if o.outcome in ("DENIED", "REJECTED"): consecutive += 1
                else: break
            trip_win = [o for o in window_list if o.outcome in ("DENIED", "REJECTED") and now - o.t <= self.policy.deny_streak_window_s]
            if len(trip_win) >= self.policy.deny_streak_trip:
                signals.append(Signal("ANM-005", "TRIP", "High number of denied actions", {}))
            elif consecutive >= self.policy.deny_streak_warn:
                signals.append(Signal("ANM-005", "WARN", "Consecutive denied actions", {}))

        # ANM-006 failure ratio
        exec_obs = [o for o in window_list if o.outcome in ("OK", "FAIL", "TIMEOUT")]
        trip_exec = exec_obs[-self.policy.failure_ratio_trip_window:]
        if len(trip_exec) >= self.policy.failure_ratio_min_samples:
            fails = sum(1 for o in trip_exec if o.outcome in ("FAIL", "TIMEOUT"))
            if fails / len(trip_exec) >= self.policy.failure_ratio_trip:
                signals.append(Signal("ANM-006", "TRIP", "High failure ratio", {}))
        
        if not any(s.id == "ANM-006" for s in signals):
            warn_exec = exec_obs[-self.policy.failure_ratio_warn_window:]
            if len(warn_exec) >= self.policy.failure_ratio_min_samples:
                fails = sum(1 for o in warn_exec if o.outcome in ("FAIL", "TIMEOUT"))
                if fails / len(warn_exec) >= self.policy.failure_ratio_warn:
                    signals.append(Signal("ANM-006", "WARN", "High failure ratio", {}))

        # ANM-007 timeouts
        if obs.outcome == "TIMEOUT":
            consecutive = 0
            for o in reversed(window_list):
                if o.outcome == "TIMEOUT": consecutive += 1
                else: break
            if consecutive >= self.policy.timeout_trip_consecutive:
                signals.append(Signal("ANM-007", "TRIP", "Consecutive timeouts", {}))
            elif consecutive >= self.policy.timeout_warn_consecutive:
                signals.append(Signal("ANM-007", "WARN", "Consecutive timeouts", {}))

        # ANM-008 domain burst
        burst_hosts = sum(1 for h, seen_t in self.first_seen_hosts.items() if now - seen_t <= self.policy.domain_burst_window_s)
        if burst_hosts >= self.policy.domain_burst_trip:
            signals.append(Signal("ANM-008", "TRIP", "Domain burst detected", {}))
        elif burst_hosts >= self.policy.domain_burst_warn:
            signals.append(Signal("ANM-008", "WARN", "Domain burst detected", {}))
        
        # ANM-009 evasion after deny
        for t_str in targets:
            if t_str in self.denied_targets:
                denied_t, rule_ids = self.denied_targets[t_str]
                if now - denied_t <= self.policy.evasion_ttl_s:
                    # check if different fp and not pure read
                    is_pure_read = action.proposal.action_type in (ActionType.FS_READ, ActionType.FS_LIST)
                    if not is_pure_read and outcome not in ("DENIED", "REJECTED"):
                        # Count how many times we've evaded (not counting the original denials)
                        evasion_count = sum(1 for o in window_list 
                                            if any(tgt in self.denied_targets for tgt in o.targets) 
                                            and o.action_type not in ("fs.read", "fs.list")
                                            and o.outcome not in ("DENIED", "REJECTED"))
                        if evasion_count >= 2:
                            signals.append(Signal("ANM-009", "ESCALATE", "Evasion suspected", {"target": t_str}))
                        else:
                            signals.append(Signal("ANM-009", "WARN", "Evasion suspected", {"target": t_str}))
                        break # Only one signal per observation

        # ANM-010 critical probing
        critical_rule_ids: set[str] = set()
        for o in window_list:
            critical_rule_ids.update(o.rule_ids_ge80)
        
        if len(critical_rule_ids) >= self.policy.critical_probe_trip:
            signals.append(Signal("ANM-010", "TRIP", "Critical probing detected", {"rules": list(critical_rule_ids)}))
        elif len(critical_rule_ids) >= self.policy.critical_probe_escalate:
            signals.append(Signal("ANM-010", "ESCALATE", "Critical probing detected", {"rules": list(critical_rule_ids)}))

        # ANM-011 budget pressure
        if run and getattr(run.budgets, "max_steps", 0) > 0:
            ratio = (run.counters.steps_used + 1) / run.budgets.max_steps
            if ratio >= getattr(self.policy, "budget_pressure_trip_ratio", 0.9):
                signals.append(Signal("ANM-011", "TRIP", "High step budget pressure", {"ratio": ratio}))
            elif ratio >= getattr(self.policy, "budget_pressure_warn_ratio", 0.75):
                signals.append(Signal("ANM-011", "WARN", "High step budget pressure", {"ratio": ratio}))
        # ANM-012 secret outputs
        if action.result and action.result.output_tainted:
            self.secret_outputs_count += 1
            if self.secret_outputs_count >= self.policy.output_secret_warn:
                signals.append(Signal("ANM-012", "WARN", "Multiple secret outputs", {}))

        # ANM-013 latency outlier
        if obs.outcome == "OK" and dur_ms is not None and dur_ms >= self.policy.latency_outlier_min_ms:
            same_type_durs = [o.dur_ms for o in window_list if o.action_type == obs.action_type and o.outcome == "OK" and o.dur_ms is not None]
            if len(same_type_durs) >= self.policy.latency_outlier_min_samples:
                # median
                sorted_durs = sorted(same_type_durs)
                n = len(sorted_durs)
                median = sorted_durs[n//2] if n % 2 != 0 else (sorted_durs[n//2 - 1] + sorted_durs[n//2]) / 2.0
                if dur_ms > self.policy.latency_outlier_factor * median:
                    signals.append(Signal("ANM-013", "INFO", "Latency outlier", {"dur_ms": dur_ms, "median": median}))
        
        return signals
