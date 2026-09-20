"""
Run models — §1.2.1 + Part 3 §B5

Milestone, Budgets, TaskSpec, TaintSource, Taint, RunCounters, Run.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agentguard.registry import RunStatus


class Milestone(BaseModel):
    """Task milestone — Part 3 §B5 replaces Part 1 definition."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9_\-]{1,40}$")
    description: str = Field(max_length=300)
    depends_on: list[str] = []
    required: bool = True
    weight: float = Field(default=1.0, gt=0, le=10)
    budget_steps: int | None = Field(default=None, ge=1, le=1000)
    budget_seconds: int | None = Field(default=None, ge=5, le=86400)
    verify: dict[str, Any] | None = None   # §9 defines VerifierSpec; hub stores opaque


class Budgets(BaseModel):
    """Resource budgets for a run. §1.2.1"""

    model_config = ConfigDict(extra="forbid")

    max_steps: int = Field(default=100, ge=1, le=10_000)
    max_wall_seconds: int = Field(default=900, ge=10, le=86_400)
    max_tokens: int | None = None
    max_cost_usd: float | None = None
    max_egress_bytes: int = 5 * 1024 * 1024


class TaskSpec(BaseModel):
    """Task specification provided when creating a run. §1.2.1 + §B5"""

    model_config = ConfigDict(extra="forbid")

    objective: str = Field(min_length=5, max_length=2000)
    success_criteria: list[str] = Field(default=[], max_length=20)
    milestones: list[Milestone] = Field(default=[], max_length=30)
    workspace_root: str = "/workspace"
    workspace_host_path: str | None = None
    policy_id: str = "default"
    human_available: bool | None = None            # None → AG_HUMAN_AVAILABLE_DEFAULT
    agent: dict[str, str] = {}
    policy_overrides: dict[str, Any] | None = None # §B5: tighten-only overlay


class TaintSource(BaseModel):
    """Record of a taint source. §1.2.1"""

    action_id: str
    url: str | None = None
    reasons: list[str] = []
    at: str


class Taint(BaseModel):
    """Run-level taint tracking. §1.2.1"""

    level: int = 0                                 # 0 clean, 1 suspected, 2 high
    sources: list[TaintSource] = []


class RunCounters(BaseModel):
    """Mutable counters for a run. §1.2.1"""

    steps_used: int = 0
    denied: int = 0
    asked: int = 0
    approved: int = 0
    rejected: int = 0
    failed: int = 0
    egress_bytes: int = 0
    tokens: int = 0
    cost_usd: float = 0.0


class Run(BaseModel):
    """Complete run model. §1.2.1 + §B3 + §B5"""

    run_id: str
    status: RunStatus
    task: TaskSpec
    budgets: Budgets = Budgets()
    created_at: str
    started_at: str | None = None
    ended_at: str | None = None
    next_seq: int = 1
    counters: RunCounters = RunCounters()
    taint: Taint = Taint()
    halt_reason: str | None = None
    pause_reason: str | None = None                # §B3
    unanswered_approvals: int = 0
    sandbox: dict[str, str] = {}
    # Part 3 additions
    policy_version: int = 1
    overlay_sha256: str | None = None
    ws_epoch: int = 0                              # §B6
    outcome_verified: bool | None = None
    pending_advisories_json: str = "[]"
