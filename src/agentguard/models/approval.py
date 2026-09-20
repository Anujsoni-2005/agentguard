"""
Approval models — §1.2.3 + Part 3 §B2
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

from agentguard.models.common import Finding
from agentguard.registry import ActionType, ApprovalStatus


class GrantRequest(BaseModel):
    """Human may ask 'approve and remember'. §1.2.3"""

    scope: Literal["exact_action", "same_fingerprint", "action_type_in_dir"]
    ttl_s: int = Field(ge=1, le=3600)
    max_uses: int = Field(ge=1, le=100)


class Approval(BaseModel):
    """Approval record for an ASK_HUMAN action. §1.2.3 + §B2"""

    approval_id: str
    run_id: str
    action_id: str
    status: ApprovalStatus
    action_hash: str                                          # == ActionRecord.params_hash (TOCTOU binding)
    action_type: ActionType
    summary: str                                              # e.g. "Delete directory /workspace/build (recursive)"
    findings: list[Finding]
    risk_score: int
    artifacts: dict[str, Any] = {}                            # §4 attaches {"diff":"..."}
    requested_at: str
    expires_at: str
    decided_at: str | None = None
    decided_by: str | None = None
    note: str | None = None
    grant_request: GrantRequest | None = None
    # Part 3 §B2 addition
    grant_options: list[Literal[
        "exact_action", "same_fingerprint", "action_type_in_dir"
    ]] = []
