"""
AgentGuard Filesystem Paths & Validation (§4.5.1, §4.5.2)
"""
from __future__ import annotations

import posixpath
import unicodedata
import re
from typing import Optional, Tuple, List, Set

from agentguard.models.common import Finding
from agentguard.models.policy import FsPolicy
from agentguard.registry import Verdict
from agentguard.ids import ULID

# Regex for C0 controls (0x00-0x1F)
C0_RE = re.compile(r'[\x00-\x1f]')
WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"}

def _is_mixed_script(s: str) -> bool:
    # A simplified mixed-script detection: check if string contains chars from different unicode blocks
    # True rigorous mixed-script detection requires full ICU or unicodedata blocks.
    # For now, we reject if NFKC(s) != NFC(s) as primary defense.
    return unicodedata.normalize("NFKC", s) != unicodedata.normalize("NFC", s)

class FsPathValidator:
    @staticmethod
    def normalize(p: str, workspace_root: str, policy: FsPolicy, is_read: bool = False) -> Tuple[Optional[str], List[Finding]]:
        findings = []

        if not p or C0_RE.search(p) or len(p) > policy.max_path_len:
            findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-001", reason_code="FS_PATH_INVALID", severity=80, verdict_hint=Verdict.DENY, message="Path invalid, empty, or too long"))
            return None, findings

        if posixpath.isabs(p):
            allowed_roots = [workspace_root]
            if is_read:
                allowed_roots.extend(policy.read_allow_paths)
            
            valid_root = False
            for root in allowed_roots:
                if p == root or p.startswith(root + "/"):
                    valid_root = True
                    break
            
            if not valid_root:
                findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-002", reason_code="FS_OUTSIDE_WORKSPACE", severity=85, verdict_hint=Verdict.DENY, message="Path escapes workspace"))
                return None, findings
            
            full_path = p
        else:
            full_path = posixpath.join(workspace_root, p)

        norm_path = posixpath.normpath(full_path)
        
        # Re-check containment after normpath
        allowed_roots = [workspace_root]
        if is_read:
            allowed_roots.extend(policy.read_allow_paths)
        
        valid_root = False
        active_root = ""
        for root in allowed_roots:
            if norm_path == root or norm_path.startswith(root + "/"):
                valid_root = True
                active_root = root
                break
        
        if not valid_root:
            findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-002", reason_code="FS_OUTSIDE_WORKSPACE", severity=85, verdict_hint=Verdict.DENY, message="Path escapes workspace after normalization"))
            return None, findings

        if active_root == workspace_root:
            if norm_path == workspace_root:
                rel_path = ""
            else:
                rel_path = norm_path[len(workspace_root) + 1:]
        else:
            rel_path = None # Lexically outside workspace, even if allowed for read

        if rel_path is not None:
            components = rel_path.split("/") if rel_path else []
        else:
            components = norm_path[len(active_root)+1:].split("/") if norm_path != active_root else []

        if len(components) > policy.max_depth:
            findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-001", reason_code="FS_PATH_INVALID", severity=80, verdict_hint=Verdict.DENY, message="Path depth exceeds maximum"))
            return None, findings

        for comp in components:
            if len(comp) > policy.max_component_len:
                findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-001", reason_code="FS_PATH_INVALID", severity=80, verdict_hint=Verdict.DENY, message="Component exceeds maximum length"))
                return None, findings
            if comp.endswith(" ") or comp.endswith("."):
                findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-001", reason_code="FS_PATH_INVALID", severity=80, verdict_hint=Verdict.DENY, message="Component ends with space or dot"))
                return None, findings
            if comp.upper() in WINDOWS_RESERVED:
                findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-001", reason_code="FS_PATH_INVALID", severity=80, verdict_hint=Verdict.DENY, message="Component is a reserved name"))
                return None, findings
            
            nfc_comp = unicodedata.normalize("NFC", comp)
            if comp != nfc_comp:
                comp = nfc_comp # Use NFC

            if _is_mixed_script(comp):
                findings.append(Finding(finding_id=f"fnd_{ULID()}", source="fs", rule_id="FS-001", reason_code="FS_PATH_INVALID", severity=70, verdict_hint=Verdict.DENY, message="Confusable unicode filename (mixed-script/NFKC)"))
                return None, findings
        
        if rel_path is not None:
            rel_path = unicodedata.normalize("NFC", rel_path)

        return rel_path, findings

import fnmatch

def match_globs(rel_path: str, globs: List[str], case_insensitive: bool = True) -> bool:
    """
    Applied to the NFC-lowercased path AND every ancestor prefix.
    """
    if not rel_path:
        return False
        
    path = unicodedata.normalize("NFC", rel_path)
    if case_insensitive:
        path = path.lower()

    for g in globs:
        if case_insensitive:
            g = g.lower()
            
        # Standard fnmatch translation for **
        g_fnmatch = g.replace("**", "*")
        
        # If glob starts with **/, it can also match things directly in root (without the /)
        g_fnmatch_root = g.replace("**/", "") if g.startswith("**/") else None
        
        # Test path and all ancestors
        parts = path.split("/")
        for i in range(1, len(parts) + 1):
            prefix = "/".join(parts[:i])
            if fnmatch.fnmatch(prefix, g_fnmatch):
                return True
            if g_fnmatch_root and fnmatch.fnmatch(prefix, g_fnmatch_root):
                return True
                
    return False
