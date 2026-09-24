"""
AgentGuard Filesystem Analyzer (§4.6)
"""
from typing import List, Optional

from agentguard.models.common import Finding
from agentguard.protocols import AnalysisContext
from agentguard.models.workspace import FsFacts
from agentguard.registry import Verdict, ActionType
from agentguard.fs.paths import FsPathValidator, match_globs
from agentguard.ids import ULID

class FsAnalyzer:
    id = "fs"
    handles = {ActionType.FS_READ, ActionType.FS_LIST, ActionType.FS_WRITE, ActionType.FS_DELETE}

    @classmethod
    def analyze(cls, ctx: AnalysisContext) -> List[Finding]:
        findings = []
        
        # 1. Input check
        facts: Optional[FsFacts] = ctx.scratch.get("fs")
        if facts is None:
            findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-000", reason_code="ANALYZER_ERROR", severity=60, verdict_hint=Verdict.ASK_HUMAN, message="Missing FS facts"))
            return findings
            
        policy = ctx.policy.fs
        
        # Path string from params
        path = ctx.action.params.get("path", "")
        if not path:
            findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-001", reason_code="FS_PATH_INVALID", severity=80, verdict_hint=Verdict.DENY, message="Path is empty"))
            return findings

        # Re-validate via lexical normalization
        rel_path, norm_findings = FsPathValidator.normalize(
            path, 
            policy.workspace_root, 
            policy, 
            is_read=(ctx.action.action_type in (ActionType.FS_READ, ActionType.FS_LIST))
        )
        if norm_findings:
            findings.extend(norm_findings)
            return findings # Short circuit if path is untrustworthy
            
        if rel_path is None:
            # Means it's lexically outside the workspace, even if allowed for read it shouldn't be handled by standard workspace write rules
            pass # handled above by FS-002 if invalid

        # FS-003 Symlink escape
        if facts.symlink_escape:
            findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-003", reason_code="FS_SYMLINK_ESCAPE", severity=90, verdict_hint=Verdict.DENY, message="Symlink escape detected"))
            return findings

        is_write = ctx.action.action_type in (ActionType.FS_WRITE, ActionType.FS_DELETE)
        
        if rel_path is not None:
            # FS-005 Self protection
            if is_write and match_globs(rel_path, policy.deny_paths):
                findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-005", reason_code="FS_SELF_PROTECTION", severity=95, verdict_hint=Verdict.DENY, message="Modifying agent configuration is not permitted"))
                return findings
                
            # FS-012 Honeytoken access
            is_honeytoken = match_globs(rel_path, ctx.run.workspace.honeytoken_paths) if ctx.run.workspace else False
            if is_honeytoken:
                findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-012", reason_code="FS_HONEYTOKEN_ACCESS", severity=95, verdict_hint=Verdict.DENY, message="Accessed a honeytoken"))
                # The flags update happens in the hub, we just emit the finding.
                return findings

            # FS-010 Sensitive path
            if match_globs(rel_path, policy.sensitive_path_globs):
                findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-010", reason_code="FS_SENSITIVE_PATH", severity=88, verdict_hint=Verdict.ASK_HUMAN, message="Accessing sensitive paths requires approval"))

            # FS-020 Protected path
            if is_write and match_globs(rel_path, policy.protected_path_globs):
                findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-020", reason_code="FS_PROTECTED_PATH", severity=65, verdict_hint=Verdict.ASK_HUMAN, message="Modifying protected file requires human approval"))
                
            # FS-040 Mass Delete
            if ctx.action.action_type == ActionType.FS_DELETE:
                recursive = ctx.action.params.get("recursive", False)
                if recursive:
                    if rel_path == "" or match_globs(rel_path, [".git"]) or (facts.dir_file_count and facts.dir_file_count > policy.mass_delete_threshold_files):
                        findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-040", reason_code="FS_MASS_CHANGE", severity=60, verdict_hint=Verdict.ASK_HUMAN, message="Mass or critical folder deletion requires approval"))
                    elif facts.dir_file_count and facts.dir_file_count > 0:
                        findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-041", reason_code="FS_MASS_CHANGE", severity=45, verdict_hint=Verdict.ASK_HUMAN, message="Recursive directory deletion requires approval"))

        # Output payload logic for vetting
        ctx.scratch["fs_result"] = {"vetted_candidate": True} # Simplified
        
        return findings
