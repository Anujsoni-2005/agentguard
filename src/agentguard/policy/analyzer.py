"""
AgentGuard Custom Rule Analyzer (§7.5)
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Dict, Any, List

import zoneinfo

from agentguard.models.policy import CustomRule
from agentguard.models.common import Finding, AnalysisContext
from agentguard.registry import Verdict

class PolicyAnalyzer:
    id = "policy"
    
    @classmethod
    def evaluate_predicate(cls, pred: Dict[str, Any], ctx: AnalysisContext) -> bool:
        op = pred.get("op")
        if not op:
            return False
            
        if op == "all":
            items = pred.get("items", [])
            if not items:
                return True
            return all(cls.evaluate_predicate(item, ctx) for item in items)
            
        elif op == "any":
            items = pred.get("items", [])
            if not items:
                return False
            return any(cls.evaluate_predicate(item, ctx) for item in items)
            
        elif op == "not":
            item = pred.get("item")
            if not item:
                return False
            return not cls.evaluate_predicate(item, ctx)
            
        elif op == "action_type_in":
            values = pred.get("values", [])
            return ctx.action.action_type in values
            
        elif op == "surface_regex":
            surface = pred.get("surface")
            pattern = pred.get("pattern", "")
            flags = pred.get("flags", [])
            # Get surface text
            text = cls._get_surface(surface, ctx)
            if not text:
                return False
            re_flags = 0
            if "i" in flags: re_flags |= re.IGNORECASE
            if "m" in flags: re_flags |= re.MULTILINE
            if "s" in flags: re_flags |= re.DOTALL
            try:
                return bool(re.search(pattern, text, re_flags))
            except re.error:
                return False
                
        elif op == "param_eq":
            pointer = pred.get("pointer", "")
            value = pred.get("value")
            actual = cls._get_param(pointer, ctx.action.params.model_dump())
            return actual == value
            
        # Stubbing remaining predicates for brevity
        elif op == "risk_at_least":
            value = pred.get("value", 0)
            findings_so_far = ctx.scratch.get("findings_so_far", [])
            max_sev = max((f.severity for f in findings_so_far), default=0)
            return max_sev >= value
            
        elif op == "time_window":
            tz_str = pred.get("tz", "UTC")
            days = pred.get("days", [])
            start = pred.get("start", "00:00")
            end = pred.get("end", "24:00")
            
            now: datetime = ctx.scratch.get("now", datetime.utcnow())
            try:
                tz = zoneinfo.ZoneInfo(tz_str)
                now_loc = now.astimezone(tz)
            except Exception:
                return False
                
            day_str = now_loc.strftime("%a").lower()
            if day_str not in days:
                return False
                
            time_str = now_loc.strftime("%H:%M")
            if start > end:
                return time_str >= start or time_str < end
            else:
                return start <= time_str < end

        return False

    @staticmethod
    def _get_surface(surface: str, ctx: AnalysisContext) -> str:
        # Simplified surface resolution
        return ""

    @staticmethod
    def _get_param(pointer: str, data: Dict[str, Any]) -> Any:
        # RFC 6901 over params
        if not pointer.startswith("/"):
            return None
        parts = pointer.strip("/").split("/")
        curr = data
        for p in parts:
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            elif isinstance(curr, list) and p.isdigit() and int(p) < len(curr):
                curr = curr[int(p)]
            else:
                return None
        return curr

    @classmethod
    def analyze(cls, ctx: AnalysisContext) -> List[Finding]:
        findings = []
        for rule in ctx.policy.custom_rules:
            if not rule.enabled:
                continue
            
            try:
                if cls.evaluate_predicate(rule.when, ctx):
                    findings.append(Finding(
                        finding_id="fnd_pol",
                        source="policy",
                        rule_id=f"POL-{rule.id}",
                        reason_code="POLICY_CUSTOM",
                        severity=rule.then.severity,
                        verdict_hint=Verdict(rule.then.verdict),
                        message=rule.then.message,
                        evidence={}
                    ))
            except Exception:
                continue
                
        return findings
