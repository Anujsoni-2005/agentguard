"""
AgentGuard Grants Manager (§7.6)
"""
from __future__ import annotations

import sqlite3
from typing import Optional, List
from datetime import datetime

from agentguard.models.policy import Grant, GrantMatch
from agentguard.models.common import ActionRecord, AnalysisContext
from agentguard.registry import Verdict, ActionType

class GrantManager:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def _get_active_grants(self, run_id: str, action_type: ActionType, now: str) -> List[Grant]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """
                SELECT * FROM grants 
                WHERE run_id = ? AND status = 'ACTIVE' AND uses < max_uses AND expires_at > ?
                ORDER BY expires_at ASC, grant_id ASC
                """,
                (run_id, now)
            ).fetchall()
            
            grants = []
            for row in rows:
                import json
                d = dict(row)
                d["match"] = json.loads(d.pop("match_json"))
                grants.append(Grant.model_validate(d))
            return grants

    def _consume_grant(self, grant_id: str, now: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                UPDATE grants SET 
                    uses = uses + 1, 
                    status = CASE WHEN uses + 1 >= max_uses THEN 'EXHAUSTED' ELSE status END
                WHERE grant_id = ? AND status = 'ACTIVE' AND uses < max_uses AND expires_at > ?
                """,
                (grant_id, now)
            )
            return cursor.rowcount == 1

    def match_grant(self, ctx: AnalysisContext, verdict: Verdict, max_sev: int, reason_codes: set[str]) -> Optional[Grant]:
        """
        P6 Grant matching logic (§7.6.4)
        """
        if verdict != Verdict.ASK_HUMAN:
            return None
            
        policy = ctx.policy.grants
        if not policy.enabled:
            return None
            
        if max_sev >= policy.never_for_severity_gte:
            return None
            
        if reason_codes.intersection(set(policy.never_for_reason_codes)):
            return None
            
        now_str = ctx.scratch.get("now", datetime.utcnow()).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        candidates = self._get_active_grants(ctx.run.run_id, ctx.action.action_type, now_str)
        
        for g in candidates:
            match = g.match
            if match.action_type != ctx.action.action_type:
                continue
                
            matched = False
            if g.scope == "exact_action":
                matched = (match.params_hash == ctx.action.params_hash)
            elif g.scope == "same_fingerprint":
                matched = (match.fingerprint == ctx.action.fingerprint)
            elif g.scope == "action_type_in_dir":
                # Simplified matching logic
                if match.dir_prefix and ctx.action.action_type in (ActionType.FS_WRITE, ActionType.FS_DELETE, ActionType.CLI_EXEC):
                    matched = True # To fully implement, we check rel_path / cwd
            elif g.scope == "net_host":
                if ctx.action.action_type == ActionType.NET_HTTP:
                    matched = True # To fully implement, we check host_patterns and methods
            
            if matched:
                if self._consume_grant(g.grant_id, now_str):
                    return g
                    
        return None
