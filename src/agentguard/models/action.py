"""
Action models — §1.2.2 + Part 3 §B2

Per-type params, ActionProposal, ActionRecord, Timing, ActionDecision.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from agentguard.models.common import EvidenceRef, ExecutionResult, Finding
from agentguard.registry import ActionStatus, ActionType, NextStep, Verdict


# ═══════════════════════════════════════════════════════════════════════
# PER-TYPE PARAMS (extra="forbid" everywhere) — §1.2.2
# ═══════════════════════════════════════════════════════════════════════

class CliExecParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: str = Field(min_length=1, max_length=65_536)
    cwd: str = "/workspace"
    env: dict[str, str] = {}
    timeout_s: int = Field(default=30, ge=1, le=300)
    stdin: str | None = Field(default=None, max_length=1_048_576)


class NetHttpParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
    url: str = Field(min_length=8, max_length=8192)
    headers: dict[str, str] = {}
    body_b64: str | None = None
    timeout_s: int = Field(default=20, ge=1, le=120)


class FsReadParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    max_bytes: int = 1_048_576


class FsListParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    recursive: bool = False


class FsWriteParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    content_b64: str
    mode: Literal["create", "overwrite", "append"] = "overwrite"


class FsDeleteParams(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    recursive: bool = False


# GUI params are stubs until §5 is implemented
# TODO(spec-gap): GUI param models defined in §5


# Registry mapping action types to their param models
PARAMS_MODELS: dict[ActionType, type[BaseModel]] = {
    ActionType.CLI_EXEC: CliExecParams,
    ActionType.NET_HTTP: NetHttpParams,
    ActionType.FS_READ: FsReadParams,
    ActionType.FS_WRITE: FsWriteParams,
    ActionType.FS_DELETE: FsDeleteParams,
    ActionType.FS_LIST: FsListParams,
}


# ═══════════════════════════════════════════════════════════════════════
# PROPOSAL & RECORD — §1.2.2
# ═══════════════════════════════════════════════════════════════════════

class ActionProposal(BaseModel):
    """Agent's proposed action — §1.2.2"""

    model_config = ConfigDict(extra="forbid")

    client_action_id: str = Field(
        min_length=8, max_length=64,
        pattern=r"^[A-Za-z0-9_\-]+$",
    )
    action_type: ActionType
    params: dict[str, Any]
    rationale: str = Field(default="", max_length=2000)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence_refs: list[EvidenceRef] = Field(default=[], max_length=10)
    plan_step_id: str | None = Field(default=None, max_length=40)
    agent_meta: dict[str, Any] = {}                           # <= 1KB


class ActionRecord(BaseModel):
    """Internal/persisted superset of the proposal. §1.2.2"""

    action_id: str
    run_id: str
    seq: int
    proposal: ActionProposal
    params: BaseModel                                         # validated typed params
    params_hash: str
    fingerprint: str
    status: ActionStatus
    verdict: Verdict | None = None
    next_step: NextStep | None = None
    reason_codes: list[str] = []
    findings: list[Finding] = []
    risk_score: int | None = None
    received_at: str
    decided_at: str | None = None
    executed_at: str | None = None
    finished_at: str | None = None
    decision_ms: float | None = None
    approval_id: str | None = None
    grant_id: str | None = None
    result: ExecutionResult | None = None

    model_config = ConfigDict(arbitrary_types_allowed=True)


# ═══════════════════════════════════════════════════════════════════════
# TIMING & DECISION RESPONSE — §1.2.2 + §B2
# ═══════════════════════════════════════════════════════════════════════

class Timing(BaseModel):
    """Per-action timing breakdown. §1.2.2"""

    total_ms: float
    validate_ms: float
    prechecks_ms: float
    analyzers_ms: dict[str, float]
    merge_ms: float
    ledger_ms: float
    execute_ms: float | None = None


class ApprovalSummary(BaseModel):
    """Approval subset included in ActionDecision. §1.4.2"""

    approval_id: str
    status: str
    expires_at: str
    summary: str
    risk_score: int


class GrantSummary(BaseModel):
    """Grant subset included in ActionDecision."""

    grant_id: str


class Advisory(BaseModel):
    """Advisory attached to ActionDecision — Part 3 §B2"""

    advisory_id: str
    level: Literal["INFO", "WARN", "ESCALATE"]
    code: str
    source: Literal["anomaly", "progress", "judge", "human", "policy"]
    message: str = Field(max_length=300)
    evidence: dict[str, Any] = {}
    created_at: str


class ActionDecision(BaseModel):
    """HTTP response body for POST /actions and GET /actions/{id}. §1.2.2 + §B2"""

    action_id: str
    run_id: str
    seq: int
    status: ActionStatus
    verdict: Verdict
    next_step: NextStep
    retry_after_ms: int | None = None
    reason_codes: list[str]
    risk_score: int
    findings: list[Finding]
    approval: ApprovalSummary | None = None
    grant: GrantSummary | None = None
    execution: ExecutionResult | None = None
    timing: Timing
    ledger_idx: int
    ledger_hash: str
    # Part 3 §B2 additions
    fingerprint: str = ""
    params_hash: str = ""
    advisories: list[Advisory] = []
    enforced: bool = True
    would_have_verdict: Verdict | None = None
