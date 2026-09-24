### File Tree
`	ext
.coderabbit.yaml
.gitignore
Makefile
README.md
data/ledger/ledger-000001.jsonl
policies/default.agentguard.yaml
pyproject.toml
src/agentguard/__init__.py
src/agentguard/canon.py
src/agentguard/cli/__init__.py
src/agentguard/cli/analyzer.py
src/agentguard/cli/ir.py
src/agentguard/cli/parser.py
src/agentguard/cli/resolver.py
src/agentguard/cli/rules.py
src/agentguard/config.py
src/agentguard/db/migrations/0002_policy_grants.sql
src/agentguard/db/migrations/0003_rulepacks.sql
src/agentguard/decision/__init__.py
src/agentguard/executors/docker.py
src/agentguard/fs/__init__.py
src/agentguard/fs/analyzer.py
src/agentguard/fs/diffing.py
src/agentguard/fs/executor.py
src/agentguard/fs/honeytokens.py
src/agentguard/fs/integrity.py
src/agentguard/fs/manifest.py
src/agentguard/fs/paths.py
src/agentguard/fs/promote.py
src/agentguard/fs/safeio.py
src/agentguard/fs/workspace.py
src/agentguard/gui/__init__.py
src/agentguard/hub/__init__.py
src/agentguard/hub/app.py
src/agentguard/hub/auth.py
src/agentguard/hub/bus.py
src/agentguard/hub/errors.py
src/agentguard/hub/merge.py
src/agentguard/hub/routes_actions.py
src/agentguard/hub/routes_approvals.py
src/agentguard/hub/routes_debug.py
src/agentguard/hub/routes_internal.py
src/agentguard/hub/routes_runs.py
src/agentguard/hub/routes_ws.py
src/agentguard/ids.py
src/agentguard/models/__init__.py
src/agentguard/models/action.py
src/agentguard/models/approval.py
src/agentguard/models/common.py
src/agentguard/models/grant.py
src/agentguard/models/ledger.py
src/agentguard/models/policy.py
src/agentguard/models/rules.py
src/agentguard/models/run.py
src/agentguard/models/workspace.py
src/agentguard/net/__init__.py
src/agentguard/net/analyzer.py
src/agentguard/net/canary.py
src/agentguard/net/executor.py
src/agentguard/net/models.py
src/agentguard/net/ratelimit.py
src/agentguard/net/scanner.py
src/agentguard/net/taint.py
src/agentguard/policy/__init__.py
src/agentguard/policy/analyzer.py
src/agentguard/policy/grants.py
src/agentguard/policy/merge.py
src/agentguard/policy/rules.py
src/agentguard/policy/snapshot.py
src/agentguard/policy/verifier.py
src/agentguard/progress/__init__.py
src/agentguard/protocols.py
src/agentguard/proxy/addon.py
src/agentguard/registry.py
src/agentguard/rules/__init__.py
src/agentguard/sdk/__init__.py
src/agentguard/sdk/client.py
src/agentguard/store/__init__.py
src/agentguard/store/db.py
src/agentguard/store/ledger.py
src/agentguard/store/repo.py
src/agentguard/store/schema.sql
src/agentguard/telemetry/__init__.py
src/agentguard/timeutil.py
tests/__init__.py
tests/conftest.py
tests/golden/fs_cases.yaml
tests/integration/__init__.py
tests/integration/test_fs_p5.py
tests/integration/test_hub_p1.py
tests/unit/__init__.py
tests/unit/test_canon.py
tests/unit/test_cli_golden.py
tests/unit/test_ledger.py
tests/unit/test_merge.py
tests/unit/test_net_scanner.py
tests/unit/test_net_taint.py
tests/unit/test_policy_merge.py
tests/unit/test_verifier.py
`

### src/agentguard/models/policy.py
`python
"""
AgentGuard Policy Models (§7.2, §10.3)
"""
from __future__ import annotations

from typing import Literal, Dict, List, Optional, Any
from pydantic import BaseModel, Field, ConfigDict
from agentguard.registry import ActionType

class HumanPolicy(BaseModel):
    available_default: bool = Field(default=True, json_schema_extra={"merge": "base_only"})
    approval_ttl_s: int = Field(default=900, json_schema_extra={"merge": "min", "ui": {"control": "slider", "min": 30, "max": 3600}})
    max_unanswered_approvals: int = Field(default=2, json_schema_extra={"merge": "min"})

class ConfidencePolicy(BaseModel):
    min_confidence: float = Field(default=0.5, json_schema_extra={"merge": "max", "ui": {"control": "slider", "min": 0.0, "max": 1.0, "step": 0.05}})
    apply_to: List[ActionType] = Field(
        default=[ActionType.CLI_EXEC, ActionType.NET_HTTP, ActionType.FS_WRITE, ActionType.FS_DELETE,
                 ActionType.GUI_CLICK, ActionType.GUI_TYPE, ActionType.GUI_SELECT, ActionType.GUI_PRESS, ActionType.GUI_NAVIGATE],
        json_schema_extra={"merge": "union"}
    )

class Budgets(BaseModel):
    steps: int = Field(default=50, json_schema_extra={"merge": "min"})
    wall_seconds: int = Field(default=300, json_schema_extra={"merge": "min"})
    egress_bytes: int = Field(default=5_242_880, json_schema_extra={"merge": "min"})

class BudgetCaps(BaseModel):
    max_steps_cap: int = Field(default=500, json_schema_extra={"merge": "min", "ui": {"control": "number"}})
    max_wall_seconds_cap: int = Field(default=3600, json_schema_extra={"merge": "min"})
    max_egress_bytes_cap: int = Field(default=52_428_800, json_schema_extra={"merge": "min"})
    default_budgets: Budgets = Field(default_factory=Budgets, json_schema_extra={"merge": "min"})

class FpCanary(BaseModel):
    max_deny_rate: float = Field(default=0.005, json_schema_extra={"merge": "min"})
    max_ask_rate: float = Field(default=0.03, json_schema_extra={"merge": "min"})
    min_corpus: int = Field(default=200, json_schema_extra={"merge": "max"})

class RulesPolicy(BaseModel):
    feed_allow_domains: List[str] = Field(default_factory=list, json_schema_extra={"merge": "intersect_domains"})
    fp_canary: FpCanary = Field(default_factory=FpCanary)
    max_scan_bytes: int = Field(default=262_144, json_schema_extra={"merge": "max"})
    hard_expire_disables_all: bool = Field(default=False, json_schema_extra={"merge": "or"})

class GrantPolicy(BaseModel):
    enabled: bool = Field(default=True, json_schema_extra={"merge": "and", "ui": {"control": "toggle"}})
    allowed_scopes: List[Literal["exact_action","same_fingerprint","action_type_in_dir","net_host"]] = Field(
        default=["exact_action","same_fingerprint","action_type_in_dir"], json_schema_extra={"merge": "intersect"}
    )
    default_ttl_s: int = Field(default=300, json_schema_extra={"merge": "min"})
    default_uses: int = Field(default=1, json_schema_extra={"merge": "min"})
    max_ttl_s: int = Field(default=3600, json_schema_extra={"merge": "min", "ui": {"control": "number"}})
    max_uses: int = Field(default=100, json_schema_extra={"merge": "min"})
    never_for_severity_gte: int = Field(default=80, json_schema_extra={"merge": "min"})
    never_for_reason_codes: List[str] = Field(
        default=["FS_HONEYTOKEN_ACCESS","NET_CANARY_EGRESS","FS_SELF_PROTECTION","CLI_CATASTROPHIC_DELETE",
                 "CLI_DISK_DESTRUCTIVE","CLI_FORK_BOMB","CLI_PRIV_ESC","CLI_CONTAINER_ESCAPE",
                 "TAINTED_CONTEXT_ESCALATION","COMPROMISE_SUSPECTED","CIRCUIT_OPEN","CIRCUIT_HALF_OPEN",
                 "EVASION_SUSPECTED","BUDGET_EXHAUSTED","GUI_CREDENTIAL_FIELD","GUI_DECEPTIVE_ELEMENT","GUI_OCCLUDED"],
        json_schema_extra={"merge": "union"}
    )
    allow_preauthorization: bool = Field(default=True, json_schema_extra={"merge": "and"})

class CompletionPolicy(BaseModel):
    require_verified: bool = Field(default=True, json_schema_extra={"merge": "or"})

class CustomOutcome(BaseModel):
    verdict: Literal["ASK_HUMAN","DENY"]
    severity: int = Field(ge=40, le=100)
    message: str = Field(max_length=300)

class CustomRule(BaseModel):
    id: str = Field(pattern=r"^[A-Za-z0-9_\-]{1,40}$")
    description: str = Field(default="", max_length=300)
    enabled: bool = True
    when: Dict[str, Any]
    then: CustomOutcome

class PluginRef(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9\-]{1,30}$")
    file: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    action_types: Optional[List[ActionType]] = None
    surfaces: List[str] = []
    timeout_ms: int = Field(default=5, ge=1, le=20)
    fuel: int = Field(default=5_000_000, ge=10_000, le=50_000_000)
    memory_mb: int = Field(default=16, ge=1, le=64)
    max_findings: int = Field(default=5, ge=1, le=20)
    enabled: bool = True

# --- §10.3 Phase 7 Grounding/Uncertainty/Decision policies ---
class GroundingPolicy(BaseModel):
    enabled: bool = Field(default=True, json_schema_extra={"merge": "or"})
    require_evidence_for: List[str] = Field(default=["DELETE", "NET_WRITE", "GIT_PUSH", "GUI_STATE_CHANGE"], json_schema_extra={"merge": "union"})
    strict_evidence: bool = Field(default=False, json_schema_extra={"merge": "or"})
    citation_max_age_actions: int = Field(default=30, json_schema_extra={"merge": "min"})
    quote_min_len: int = Field(default=8, json_schema_extra={"merge": "base_only"})
    blind_overwrite: Literal["off","warn","ask"] = Field(default="warn", json_schema_extra={"merge": "stricter_enum"})
    stale_read: Literal["off","warn","ask"] = Field(default="ask", json_schema_extra={"merge": "stricter_enum"})
    rationale_contradiction: bool = Field(default=True, json_schema_extra={"merge": "or"})
    index_max_tokens: int = Field(default=50_000, json_schema_extra={"merge": "base_only"})
    output_store_bytes: int = Field(default=131_072, json_schema_extra={"merge": "base_only"})
    ungrounded_streak_window: int = Field(default=10, json_schema_extra={"merge": "max"})
    ungrounded_streak_escalate: int = Field(default=3, json_schema_extra={"merge": "min"})

class UncertaintyWeights(BaseModel):
    confidence: float = 0.40
    grounding: float = 0.20
    ambiguity: float = 0.15
    novelty: float = 0.10
    failure: float = 0.15

class UncertaintyPolicy(BaseModel):
    enabled: bool = Field(default=True, json_schema_extra={"merge": "or"})
    weights: UncertaintyWeights = Field(default_factory=UncertaintyWeights, json_schema_extra={"merge": "base_only"})
    default_confidence: float = Field(default=0.6, json_schema_extra={"merge": "min"})
    advise_above: float = Field(default=0.45, json_schema_extra={"merge": "min"})
    ask_above: float = Field(default=0.65, json_schema_extra={"merge": "min"})
    apply_to_impact: Literal["high_impact_only","all"] = Field(default="high_impact_only", json_schema_extra={"merge": "stricter_enum"})
    calibration_prior_strength: int = Field(default=10, json_schema_extra={"merge": "base_only"})
    low_conf_streak: int = Field(default=4, json_schema_extra={"merge": "min"})

class DecisionPolicy(BaseModel):
    retry_max_per_fingerprint: int = Field(default=3, json_schema_extra={"merge": "min"})
    retry_base_ms: int = Field(default=500, json_schema_extra={"merge": "base_only"})
    retry_cap_ms: int = Field(default=30_000, json_schema_extra={"merge": "base_only"})
    retry_jitter_ms: int = Field(default=250, json_schema_extra={"merge": "base_only"})
    executor_retry_max: int = Field(default=2, json_schema_extra={"merge": "min"})
    halt_on_executor_failures: int = Field(default=2, json_schema_extra={"merge": "min"})
    permanent_exit_code_min: int = Field(default=126, json_schema_extra={"merge": "base_only"})
    transient_patterns: List[str] = Field(default=[
        "temporary failure","connection reset","connection refused","timed out","timeout","try again",
        "too many requests","service unavailable","bad gateway","gateway timeout","econnreset","eai_again"
    ], json_schema_extra={"merge": "base_only"})
    transient_http_statuses: List[int] = Field(default=[408, 425, 429, 500, 502, 503, 504], json_schema_extra={"merge": "base_only"})
    replan_on_warn_codes: List[str] = Field(default=["ANM-001","ANM-002","ANM-004","ANM-005"], json_schema_extra={"merge": "union"})

# --- Phase 5 (FS), Phase 9 (GUI), Phase 6 (Anomaly, Breaker), Phase 7 (Progress) ---
class FsPolicy(BaseModel):
    workspace_root: str = "/workspace"
    read_allow_paths: List[str] = Field(default_factory=list)
    sensitive_path_globs: List[str] = Field(default_factory=list)
    deny_paths: List[str] = [".agentguard.yaml","**/.agentguard.yaml","policies/**","**/agentguard*.yaml","**/.agentguard/**"]
    protected_path_globs: List[str] = [".git/hooks/**",".git/config",".github/workflows/**",".gitlab-ci.yml",".circleci/**",
                                       "Jenkinsfile",".pre-commit-config.yaml",".husky/**","**/authorized_keys"]
    executable_ext: List[str] = [".sh",".bash",".py",".js",".mjs",".rb",".pl",".php",".ps1",".bat"]
    max_read_bytes: int = 1_048_576
    max_write_bytes: int = 5_242_880
    max_workspace_growth_bytes: int = 209_715_200
    max_list_entries: int = 1000
    max_path_len: int = 4096
    max_component_len: int = 255
    max_depth: int = 32
    mass_delete_threshold_files: int = 50
    wipe_shrink_ratio: float = 0.8
    copy_exclude_globs: List[str] = Field(default_factory=list)
    auto_promote_safe: bool = False
    honeytokens_enabled: bool = True
    scan_script_content: bool = True

class GuiPolicy(BaseModel):
    model_config = ConfigDict(extra="allow")

class AnomalyPolicy(BaseModel):
    model_config = ConfigDict(extra="allow")

class BreakerPolicy(BaseModel):
    model_config = ConfigDict(extra="allow")

class ProgressPolicy(BaseModel):
    model_config = ConfigDict(extra="allow")

# --- Import Phase 1 & 3 Policies ---
from agentguard.cli.ir import CliPolicy
from agentguard.net.models import NetPolicy

class PolicyDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1] = 1
    name: str = Field(default="default", max_length=60, json_schema_extra={"merge": "stricter"})
    description: str = Field(default="", max_length=500, json_schema_extra={"merge": "stricter"})
    mode: Literal["enforce","monitor"] = Field(default="enforce", json_schema_extra={"merge": "stricter", "ui": {"control": "toggle"}})
    monitor_hard_block_severity: int = Field(default=95, ge=80, le=100, json_schema_extra={"merge": "min"})
    human: HumanPolicy = Field(default_factory=HumanPolicy)
    confidence: ConfidencePolicy = Field(default_factory=ConfidencePolicy)
    risk_tiers: Dict[ActionType, Literal["auto","ask_human","block"]] = Field(
        default={t: "auto" for t in ActionType},
        json_schema_extra={"merge": "stricter_tier_map", "ui": {"control": "3-way-switch"}}
    )
    budgets: BudgetCaps = Field(default_factory=BudgetCaps)
    cli: CliPolicy = Field(default_factory=CliPolicy)
    net: NetPolicy = Field(default_factory=NetPolicy)
    fs: FsPolicy = Field(default_factory=FsPolicy)
    gui: GuiPolicy = Field(default_factory=GuiPolicy)
    rules: RulesPolicy = Field(default_factory=RulesPolicy)
    grants: GrantPolicy = Field(default_factory=GrantPolicy)
    anomaly: AnomalyPolicy = Field(default_factory=AnomalyPolicy)
    breaker: BreakerPolicy = Field(default_factory=BreakerPolicy)
    progress: ProgressPolicy = Field(default_factory=ProgressPolicy)
    completion: CompletionPolicy = Field(default_factory=CompletionPolicy)
    custom_rules: List[CustomRule] = Field(default_factory=list, max_length=200, json_schema_extra={"merge": "add_only_rules"})
    plugins: List[PluginRef] = Field(default_factory=list, max_length=10, json_schema_extra={"merge": "base_only"})
    plugins_budget_ms: int = Field(default=20, json_schema_extra={"merge": "base_only"})
    allow_repo_overlay: bool = Field(default=True, json_schema_extra={"merge": "base_only"})
    accept_pack_allow_additions: bool = Field(default=False, json_schema_extra={"merge": "base_only"})
    grounding: GroundingPolicy = Field(default_factory=GroundingPolicy)
    uncertainty: UncertaintyPolicy = Field(default_factory=UncertaintyPolicy)
    decision: DecisionPolicy = Field(default_factory=DecisionPolicy)

# --- Grants Data Models ---
class GrantMatch(BaseModel):
    action_type: ActionType
    params_hash: Optional[str] = None
    fingerprint: Optional[str] = None
    dir_prefix: Optional[str] = None
    host_patterns: Optional[List[str]] = None
    methods: Optional[List[str]] = None

class Grant(BaseModel):
    grant_id: str
    run_id: str
    scope: Literal["exact_action","same_fingerprint","action_type_in_dir","net_host"]
    match: GrantMatch
    status: Literal["ACTIVE","EXHAUSTED","EXPIRED","REVOKED"]
    created_at: str
    expires_at: str
    max_uses: int
    uses: int
    created_by: str
    source: Literal["approval","preauthorization"]
    approval_id: Optional[str]
    note: Optional[str]

class GrantSummary(BaseModel):
    grant_id: str
    scope: str
    expires_at: str
    uses_remaining: int
`

### src/agentguard/models/common.py
`python
"""
Common models — §0.6

Finding, EvidenceRef, ExecutionResult, ErrorBody, ErrorResponse.
All models use extra="forbid" per spec.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from agentguard.registry import Verdict


class Finding(BaseModel):
    """A single finding from an analyzer or pre-check. §0.6"""

    model_config = ConfigDict(extra="forbid")

    finding_id: str                                           # fnd_<ulid>
    source: str                                               # "hub","cli","net","fs","gui","rules","anomaly","progress","grounding"
    rule_id: str                                              # e.g. "CLI-010"
    reason_code: str                                          # from registry
    severity: int = Field(ge=0, le=100)
    verdict_hint: Verdict                                     # analyzers never emit ALLOW_WITH_GRANT
    message: str = Field(max_length=500)                      # human-readable, no secrets
    evidence: dict[str, Any] = {}                             # small, redacted; <= 2 KB serialized


class EvidenceRef(BaseModel):
    """Reference to an earlier action's output as evidence. §0.6"""

    model_config = ConfigDict(extra="forbid")

    action_id: str                                            # earlier action whose OUTPUT supports this decision
    field: Literal["stdout", "stderr", "body", "content", "meta"] = "stdout"
    quote: str | None = Field(default=None, max_length=300)   # verbatim substring (used by §10)


class ExecutionResult(BaseModel):
    """Result of executing an action via the sandbox/proxy. §0.6"""

    model_config = ConfigDict(extra="forbid")

    status: Literal["SUCCEEDED", "FAILED", "TIMED_OUT", "KILLED", "NOT_EXECUTED"]
    exit_code: int | None = None
    stdout: str = ""                                          # UTF-8 (errors="replace"), already redacted
    stderr: str = ""
    truncated: bool = False
    duration_ms: float = 0.0
    output_tainted: bool = False                              # untrusted external content (§3.8)
    taint_reasons: list[str] = []
    meta: dict[str, Any] = {}                                 # type-specific (http status, final_url, oom_killed, ...)


class ErrorBody(BaseModel):
    """Inner error envelope. §0.6"""

    code: str
    message: str
    details: dict[str, Any] = {}
    request_id: str


class ErrorResponse(BaseModel):
    """HTTP error envelope — all non-2xx responses. §0.6"""

    error: ErrorBody
`

### src/agentguard/hub/routes_actions.py
`python
"""
Action Routes — §1.4.2

POST /v1/runs/{run_id}/actions         — propose action
GET  /v1/runs/{run_id}/actions/{id}    — get action (with wait)
GET  /v1/runs/{run_id}/actions         — list actions
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Query, Request
from pydantic import ValidationError

from agentguard.canon import canonical_json, sha256_hex
from agentguard.hub.auth import require_role
from agentguard.hub.errors import AgentGuardError
from agentguard.hub.merge import merge_findings
from agentguard.cli.analyzer import CliAnalyzer
from agentguard.executors.docker import DockerExecutor
from agentguard.protocols import AnalysisContext, PolicySnapshot, RunHistoryView
from agentguard.ids import action_id as gen_action_id, approval_id as gen_approval_id, finding_id as gen_finding_id
from agentguard.models.action import PARAMS_MODELS, ActionDecision, ActionProposal, Timing
from agentguard.models.common import Finding
from agentguard.registry import (
    ActionStatus,
    HIGH_IMPACT_TYPES,
    NEXT_STEP_TABLE,
    RunStatus,
    Verdict,
)
from agentguard.timeutil import duration_ms, perf_counter_ns, utcnow

router = APIRouter(tags=["actions"])


def _get_run_lock(request: Request, run_id: str) -> asyncio.Lock:
    """Get or create per-run lock. §1.5.1"""
    locks: dict[str, asyncio.Lock] = request.app.state.run_locks
    if run_id not in locks:
        locks[run_id] = asyncio.Lock()
    return locks[run_id]


def _compute_fingerprint(action_type: str, params: dict[str, Any]) -> str:
    """
    Compute action fingerprint. §0.11

    fingerprint = sha256_hex(canonical_json({"t": type, "p": normalized_params}))[:16]
    """
    # Simplified: full normalization per type is in §2/§3; use params hash for now
    fp_obj = {"t": action_type, "p": params}
    return sha256_hex(canonical_json(fp_obj))[:16]


@router.post("/runs/{run_id}/actions")
async def propose_action(
    run_id: str,
    request: Request,
    execute: bool = Query(default=True),
    role: str = require_role("agent"),
) -> Any:
    """
    Propose an action. §1.4.2, §1.5.2

    Pipeline: P0 VALIDATE → P1 IDEMPOTENCY → P2-P7 (locked) → P8 EXECUTE → P9 POST-EXEC
    """
    settings = request.app.state.settings
    repo = request.app.state.repo
    ledger = request.app.state.ledger
    bus = request.app.state.bus

    t_start = perf_counter_ns()

    # ── P0: VALIDATE (no lock) ──────────────────────────────────────
    body_bytes = await request.body()
    if len(body_bytes) > settings.max_param_bytes:
        raise AgentGuardError("PAYLOAD_TOO_LARGE", "Request body exceeds AG_MAX_PARAM_BYTES")

    try:
        body = json.loads(body_bytes)
        proposal = ActionProposal.model_validate(body)
    except (json.JSONDecodeError, ValidationError) as e:
        raise AgentGuardError("SCHEMA_INVALID", str(e)[:500])

    param_model_cls = PARAMS_MODELS.get(proposal.action_type)
    if param_model_cls is None:
        raise AgentGuardError("SCHEMA_INVALID", f"Unsupported action type: {proposal.action_type}")

    try:
        params = param_model_cls.model_validate(proposal.params)
    except ValidationError as e:
        raise AgentGuardError("SCHEMA_INVALID", f"Invalid params: {str(e)[:500]}")

    params_hash = sha256_hex(canonical_json(params.model_dump(mode="json")))
    fingerprint = _compute_fingerprint(proposal.action_type, params.model_dump(mode="json"))

    t_validate = perf_counter_ns()

    # ── P1: IDEMPOTENCY ─────────────────────────────────────────────
    existing = await repo.find_action_by_client_id(run_id, proposal.client_action_id)
    if existing is not None:
        if existing["params_hash"] == params_hash:
            res_json = existing.get("result_json")
            if res_json is not None:
                payload = json.loads(res_json)
                payload["idempotent_replay"] = True
                return payload
            return {
                "action_id": existing["action_id"],
                "idempotent_replay": True,
                "run_id": run_id,
                "seq": existing["seq"],
                "status": existing["status"],
                "verdict": existing.get("verdict", "DENY"),
                "next_step": existing.get("next_step", "REPLAN"),
                "reason_codes": json.loads(existing.get("reason_codes_json", "[]")),
                "risk_score": existing.get("risk_score", 0),
                "findings": json.loads(existing.get("findings_json", "[]")),
                "timing": {"total_ms": 0, "validate_ms": 0, "prechecks_ms": 0, "analyzers_ms": {}, "merge_ms": 0, "ledger_ms": 0},
                "ledger_idx": existing.get("ledger_idx_verdict", 0),
                "ledger_hash": "",
            }
        else:
            raise AgentGuardError("IDEMPOTENCY_CONFLICT", "Same client_action_id with different params")

    # ── P2–P7: LOCKED ───────────────────────────────────────────────
    lock = _get_run_lock(request, run_id)
    async with lock:
        # P2: RUN GATE
        run = await repo.get_run(run_id)
        if run is None:
            raise AgentGuardError("RUN_NOT_FOUND", f"Run {run_id} does not exist")

        now = utcnow()
        new_action_id = gen_action_id()

        if run.status != RunStatus.RUNNING:
            # Create action with DENY/RUN_NOT_ACTIVE (§1.7 F-4)
            verdict = Verdict.HALT if run.status == RunStatus.HALTED else Verdict.DENY
            next_step_val = "ABORT"
            reason = "RUN_PAUSED" if run.status == RunStatus.PAUSED else "RUN_NOT_ACTIVE"

            await repo.insert_action(
                action_id=new_action_id, run_id=run_id, seq=run.next_seq,
                client_action_id=proposal.client_action_id,
                action_type=proposal.action_type,
                proposal_json=json.dumps(proposal.model_dump(mode="json")),
                params_hash=params_hash, fingerprint=fingerprint,
                status=ActionStatus.DENIED if verdict == Verdict.DENY else ActionStatus.HALTED,
                received_at=now,
            )

            t_end = perf_counter_ns()
            return _build_decision(
                action_id=new_action_id, run_id=run_id, seq=run.next_seq,
                status=ActionStatus.DENIED if verdict == Verdict.DENY else ActionStatus.HALTED,
                verdict=verdict, next_step_str=next_step_val,
                reason_codes=[reason], risk_score=0, findings=[],
                timing=Timing(
                    total_ms=duration_ms(t_start, t_end),
                    validate_ms=duration_ms(t_start, t_validate),
                    prechecks_ms=0, analyzers_ms={}, merge_ms=0, ledger_ms=0,
                ),
                ledger_idx=0, ledger_hash="",
                fingerprint=fingerprint, params_hash=params_hash,
                retry_after_ms=5000 if reason == "RUN_PAUSED" else None,
            )

        # Assign seq, advance next_seq
        seq = run.next_seq
        run.next_seq += 1

        # Create action row (RECEIVED)
        await repo.insert_action(
            action_id=new_action_id, run_id=run_id, seq=seq,
            client_action_id=proposal.client_action_id,
            action_type=proposal.action_type,
            proposal_json=json.dumps(proposal.model_dump(mode="json")),
            params_hash=params_hash, fingerprint=fingerprint,
            status=ActionStatus.EVALUATING.value,
            received_at=now,
        )

        # Ledger: action.received (durable=False)
        await ledger.append(
            run_id=run_id, event_type="action.received", actor="agent",
            action_id=new_action_id,
            payload={"seq": seq, "action_type": proposal.action_type, "params_hash": params_hash},
            durable=False,
        )

        t_prechecks_start = perf_counter_ns()

        # ── P3: PRE-CHECKS ─────────────────────────────────────────
        findings: list[Finding] = []
        halt_found = False

        # 3a BUDGET
        if run.counters.steps_used + 1 > run.budgets.max_steps:
            findings.append(Finding(
                finding_id=gen_finding_id(), source="hub", rule_id="HUB-001",
                reason_code="BUDGET_EXHAUSTED", severity=100,
                verdict_hint=Verdict.HALT,
                message="Step budget exhausted",
            ))
            halt_found = True

        started = run.started_at or run.created_at
        # TODO: wall-clock budget check using datetime parsing

        if run.budgets.max_tokens and run.counters.tokens >= run.budgets.max_tokens:
            findings.append(Finding(
                finding_id=gen_finding_id(), source="hub", rule_id="HUB-001",
                reason_code="BUDGET_EXHAUSTED", severity=100,
                verdict_hint=Verdict.HALT,
                message="Token budget exhausted",
            ))
            halt_found = True

        # 3b BREAKER (§8 stub)
        anomaly_hook = request.app.state.anomaly_hook
        from agentguard.models.action import ActionRecord
        action_record = ActionRecord(
            action_id=new_action_id, run_id=run_id, seq=seq,
            proposal=proposal, params=params,
            params_hash=params_hash, fingerprint=fingerprint,
            status=ActionStatus.EVALUATING,
            received_at=now,
        )
        breaker_finding = anomaly_hook.pre_check(run, action_record)
        if breaker_finding is not None:
            findings.append(breaker_finding)

        # 3c CONFIDENCE
        if (
            proposal.confidence is not None
            and proposal.confidence < settings.min_confidence
            and proposal.action_type not in {"fs.read", "fs.list"}
        ):
            findings.append(Finding(
                finding_id=gen_finding_id(), source="hub", rule_id="HUB-003",
                reason_code="LOW_CONFIDENCE", severity=45,
                verdict_hint=Verdict.ASK_HUMAN,
                message=f"Agent confidence {proposal.confidence:.2f} below threshold {settings.min_confidence}",
            ))

        # 3d TAINT
        if run.taint.level >= 1 and proposal.action_type in HIGH_IMPACT_TYPES:
            taint_url = run.taint.sources[0].url if run.taint.sources else "unknown"
            findings.append(Finding(
                finding_id=gen_finding_id(), source="hub", rule_id="HUB-004",
                reason_code="TAINTED_CONTEXT_ESCALATION", severity=65,
                verdict_hint=Verdict.ASK_HUMAN,
                message=f"Run context is tainted (source: {taint_url}); high-impact action requires approval",
            ))

        # 3e ALWAYS-ASK POLICY (stub — §7)
        # TODO(spec-gap): policy.risk_tiers check

        t_prechecks_end = perf_counter_ns()

        # ── P4: ANALYZERS ───────────────────────────────────────────
        # Skip if HALT finding already found
        analyzers_ms: dict[str, float] = {}
        if not halt_found:
            analyzers = []
            if proposal.action_type == "cli.exec":
                analyzers.append(CliAnalyzer())
            elif proposal.action_type == "net.http":
                from agentguard.net.analyzer import NetAnalyzer
                analyzers.append(NetAnalyzer())
                
            for analyzer in analyzers:
                ctx = AnalysisContext(
                    run=run, action=action_record, 
                    policy=PolicySnapshot(), history=RunHistoryView(), scratch={}
                )
                try:
                    analyzer_start = perf_counter_ns()
                    findings.extend(analyzer.analyze(ctx))
                    analyzer_time_ms = duration_ms(analyzer_start, perf_counter_ns())
                    analyzers_ms[analyzer.id] = analyzer_time_ms
                    if analyzer_time_ms > analyzer.timeout_ms:
                        findings.append(Finding(source="hub", rule_id="HUB-002", reason_code="ANALYZER_TIMEOUT", severity=55, verdict_hint="ASK_HUMAN", message=f"Analyzer {analyzer.id} timed out"))
                except Exception as e:
                    findings.append(Finding(source="hub", rule_id="HUB-002", reason_code="ANALYZER_ERROR", severity=60, verdict_hint="ASK_HUMAN", message=f"Analyzer {analyzer.id} failed: {e}"))

        t_analyzers_end = perf_counter_ns()

        # ── P5: MERGE ───────────────────────────────────────────────
        human_available = run.task.human_available
        if human_available is None:
            human_available = settings.human_available_default

        verdict, risk_score, reason_codes = merge_findings(findings, human_available)

        t_merge_end = perf_counter_ns()

        # ── P6: GRANT ───────────────────────────────────────────────
        grant_store = request.app.state.grant_store
        grant_summary = None
        if verdict == Verdict.ASK_HUMAN and risk_score < 80:
            grant = await grant_store.match(run_id, action_record)
            if grant is not None:
                verdict = Verdict.ALLOW_WITH_GRANT
                reason_codes = ["GRANT_APPLIED"] + [r for r in reason_codes if r != "GRANT_APPLIED"]
                await grant_store.consume(grant.grant_id)
                from agentguard.models.action import GrantSummary
                grant_summary = GrantSummary(grant_id=grant.grant_id)

        next_step = NEXT_STEP_TABLE[verdict]

        # ── P7: PERSIST + LEDGER ────────────────────────────────────
        status_map = {
            Verdict.ALLOW: ActionStatus.APPROVED,
            Verdict.ALLOW_WITH_GRANT: ActionStatus.APPROVED,
            Verdict.ASK_HUMAN: ActionStatus.PENDING_APPROVAL,
            Verdict.DENY: ActionStatus.DENIED,
            Verdict.HALT: ActionStatus.HALTED,
        }
        action_status = status_map[verdict]

        # Update counters
        run.counters.steps_used += 1
        if verdict == Verdict.DENY:
            run.counters.denied += 1
        elif verdict == Verdict.ASK_HUMAN:
            run.counters.asked += 1

        # Approval creation for ASK_HUMAN
        approval_id_val = None
        approval_summary = None
        if verdict == Verdict.ASK_HUMAN:
            approval_id_val = gen_approval_id()
            expires_at = utcnow()  # TODO: compute from TTL
            summary_text = f"{proposal.action_type}: {proposal.rationale[:100] or 'action requires approval'}"

            await repo.insert_approval({
                "approval_id": approval_id_val,
                "run_id": run_id,
                "action_id": new_action_id,
                "status": "PENDING",
                "action_hash": params_hash,
                "action_type": proposal.action_type,
                "summary": summary_text,
                "findings_json": json.dumps([f.model_dump(mode="json") for f in findings]),
                "risk_score": risk_score,
                "requested_at": now,
                "expires_at": expires_at,
            })

            # Hold unredacted params in memory (§1.3)
            request.app.state.pending_params[new_action_id] = params

            from agentguard.models.action import ApprovalSummary
            approval_summary = ApprovalSummary(
                approval_id=approval_id_val,
                status="PENDING",
                expires_at=expires_at,
                summary=summary_text,
                risk_score=risk_score,
            )

        decided_at = utcnow()

        # Ledger: action.verdict (durable=True — §0.7)
        try:
            verdict_rec = await ledger.append(
                run_id=run_id, event_type="action.verdict", actor="hub",
                action_id=new_action_id,
                payload={
                    "seq": seq, "action_type": proposal.action_type,
                    "params_hash": params_hash, "fingerprint": fingerprint,
                    "verdict": verdict.value, "next_step": next_step.value,
                    "reason_codes": reason_codes, "risk_score": risk_score,
                    "findings": [f.model_dump(mode="json") for f in findings],
                },
                durable=True,
            )
        except Exception:
            # §0.10.5: ledger failure → force DENY, HALT run
            verdict = Verdict.HALT
            action_status = ActionStatus.HALTED
            next_step = NEXT_STEP_TABLE[Verdict.HALT]
            reason_codes = ["ANALYZER_ERROR"]
            run.status = RunStatus.HALTED
            run.halt_reason = "audit unavailable"
            await repo.update_run(run)
            verdict_rec = type("FakeRec", (), {"idx": -1, "hash": ""})()  # type: ignore[assignment]

        t_ledger_end = perf_counter_ns()

        # Update action in DB
        await repo.update_action_verdict(
            new_action_id,
            status=action_status.value,
            verdict=verdict.value,
            next_step=next_step.value,
            risk_score=risk_score,
            reason_codes=reason_codes,
            findings_json=json.dumps([f.model_dump(mode="json") for f in findings]),
            decided_at=decided_at,
            decision_ms=duration_ms(t_start, t_ledger_end),
            ledger_idx=verdict_rec.idx,
            approval_id=approval_id_val,
        )

        # HALT → update run
        if verdict == Verdict.HALT:
            run.status = RunStatus.HALTED
            run.halt_reason = run.halt_reason or "; ".join(reason_codes)
            run.ended_at = utcnow()
            await repo.update_run(run)

        await repo.update_run(run)

    # LOCK RELEASED

    # ── P8: EXECUTE ─────────────────────────────────────────────────
    execution_result = None
    t_execute_end = t_ledger_end

    if verdict in {Verdict.ALLOW, Verdict.ALLOW_WITH_GRANT} and execute:
        # Ledger: action.executing
        await ledger.append(
            run_id=run_id, event_type="action.executing", actor="hub",
            action_id=new_action_id,
            payload={"seq": seq, "action_type": proposal.action_type},
            durable=False,
        )

        if proposal.action_type == "cli.exec":
            executor = DockerExecutor(workspace_dir=request.app.state.settings.workspaces_dir)
            execution_result = await executor.execute(run, action_record, grant=None)
        elif proposal.action_type == "net.http":
            from agentguard.net.executor import execute_http
            from agentguard.net.models import NetPolicy
            from agentguard.models.common import ExecutionResult
            import base64
            
            params = action_record.params
            url = params.url if hasattr(params, "url") else params.get("url")
            method = params.method if hasattr(params, "method") else params.get("method")
            headers = params.headers if hasattr(params, "headers") else params.get("headers", {})
            timeout_s = params.timeout_s if hasattr(params, "timeout_s") else params.get("timeout_s", 20)
            body_b64 = params.body_b64 if hasattr(params, "body_b64") else params.get("body_b64")
            body_bytes = base64.b64decode(body_b64) if body_b64 else None
            
            token = "dummy_token" # In real system, generated per run
            policy = NetPolicy()
            ca_path = False # Mocked for prototype
            
            status, meta, tainted, taint_reasons, stdout, truncated = await execute_http(
                run_id=run_id, token=token, method=method, url=url, 
                headers=headers, body=body_bytes, timeout_s=timeout_s, 
                policy=policy, ca_path=ca_path
            )
            
            execution_result = ExecutionResult(
                status=status,
                exit_code=0 if status == "SUCCEEDED" else -1,
                stdout=stdout,
                stderr="",
                truncated=truncated,
                duration_ms=0.0,
                output_tainted=tainted,
                taint_reasons=taint_reasons,
                meta=meta
            )
        else:
            from agentguard.models.common import ExecutionResult
            execution_result = ExecutionResult(status="NOT_EXECUTED", exit_code=-1, stdout="", stderr="", truncated=False, duration_ms=0.0, output_tainted=False, taint_reasons=[], meta={})

        t_execute_end = perf_counter_ns()

    # ── P9: POST-EXEC ──────────────────────────────────────────────
    if execution_result and execution_result.status != "NOT_EXECUTED":
        async with lock:
            # Update action result
            finished_at = utcnow()
            await repo.update_action_result(
                new_action_id,
                status=execution_result.status,
                result_json=json.dumps(execution_result.model_dump(mode="json")),
                executed_at=now, finished_at=finished_at,
            )
            # Ledger: action.executed
            await ledger.append(
                run_id=run_id, event_type="action.executed", actor="hub",
                action_id=new_action_id,
                payload={
                    "status": execution_result.status,
                    "exit_code": execution_result.exit_code,
                    "duration_ms": execution_result.duration_ms,
                },
                durable=False,
            )

    # ── Build response ──────────────────────────────────────────────
    t_end = perf_counter_ns()

    timing = Timing(
        total_ms=duration_ms(t_start, t_end),
        validate_ms=duration_ms(t_start, t_validate),
        prechecks_ms=duration_ms(t_prechecks_start, t_prechecks_end),
        analyzers_ms=analyzers_ms,
        merge_ms=duration_ms(t_prechecks_end, t_merge_end),
        ledger_ms=duration_ms(t_merge_end, t_ledger_end),
        execute_ms=duration_ms(t_ledger_end, t_execute_end) if execution_result else None,
    )

    # HTTP status: 200 for ALLOW/DENY, 202 for ASK_HUMAN (§1.4.2)
    from fastapi.responses import JSONResponse
    http_status = 202 if verdict == Verdict.ASK_HUMAN else 200

    decision = _build_decision(
        action_id=new_action_id, run_id=run_id, seq=seq,
        status=action_status, verdict=verdict, next_step_str=next_step.value,
        reason_codes=reason_codes, risk_score=risk_score, findings=findings,
        timing=timing,
        ledger_idx=verdict_rec.idx, ledger_hash=verdict_rec.hash,
        fingerprint=fingerprint, params_hash=params_hash,
        approval=approval_summary, grant=grant_summary,
        execution=execution_result,
    )

    return JSONResponse(status_code=http_status, content=decision)


@router.get("/runs/{run_id}/actions/{action_id}")
async def get_action(
    run_id: str,
    action_id: str,
    request: Request,
    wait_s: int = Query(default=0, ge=0, le=30),
    role: str = require_role("agent", "admin"),
) -> dict[str, Any]:
    """Get action decision with optional long-poll. §1.4.2"""
    repo = request.app.state.repo
    action = await repo.find_action_by_client_id(run_id, action_id)
    # Also try by action_id
    if action is None:
        cursor = await repo._db.execute(
            "SELECT * FROM actions WHERE action_id=? AND run_id=?",
            (action_id, run_id),
        )
        row = await cursor.fetchone()
        if row:
            action = dict(row)
    if action is None:
        raise AgentGuardError("ACTION_NOT_FOUND", f"Action {action_id} not found")

    # TODO: long-poll for wait_s if status is PENDING_APPROVAL/EXECUTING

    return {
        "action_id": action["action_id"],
        "run_id": run_id,
        "seq": action["seq"],
        "status": action["status"],
        "verdict": action.get("verdict"),
        "next_step": action.get("next_step"),
        "reason_codes": json.loads(action.get("reason_codes_json", "[]")),
        "risk_score": action.get("risk_score", 0),
        "findings": json.loads(action.get("findings_json", "[]")),
        "timing": {"total_ms": 0, "validate_ms": 0, "prechecks_ms": 0, "analyzers_ms": {}, "merge_ms": 0, "ledger_ms": 0},
        "ledger_idx": action.get("ledger_idx_verdict", 0),
        "ledger_hash": "",
    }


@router.get("/runs/{run_id}/actions")
async def list_actions(
    run_id: str,
    request: Request,
    after_seq: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    role: str = require_role("agent", "admin"),
) -> dict[str, Any]:
    """List actions. §1.4.2"""
    repo = request.app.state.repo
    items = await repo.list_actions(run_id, after_seq=after_seq, limit=limit)
    for item in items:
        item["reason_codes"] = json.loads(item.get("reason_codes_json", "[]"))
        item["findings"] = json.loads(item.get("findings_json", "[]"))
    return {"items": items}


def _build_decision(
    *,
    action_id: str,
    run_id: str,
    seq: int,
    status: ActionStatus,
    verdict: Verdict,
    next_step_str: str,
    reason_codes: list[str],
    risk_score: int,
    findings: list[Finding],
    timing: Timing,
    ledger_idx: int,
    ledger_hash: str,
    fingerprint: str = "",
    params_hash: str = "",
    approval: Any = None,
    grant: Any = None,
    execution: Any = None,
    retry_after_ms: int | None = None,
) -> dict[str, Any]:
    """Build the ActionDecision response dict."""
    result: dict[str, Any] = {
        "action_id": action_id,
        "run_id": run_id,
        "seq": seq,
        "status": status.value if isinstance(status, ActionStatus) else status,
        "verdict": verdict.value if isinstance(verdict, Verdict) else verdict,
        "next_step": next_step_str,
        "retry_after_ms": retry_after_ms,
        "reason_codes": reason_codes,
        "risk_score": risk_score,
        "findings": [f.model_dump(mode="json") if hasattr(f, "model_dump") else f for f in findings],
        "approval": approval.model_dump(mode="json") if approval and hasattr(approval, "model_dump") else approval,
        "grant": grant.model_dump(mode="json") if grant and hasattr(grant, "model_dump") else grant,
        "execution": execution.model_dump(mode="json") if execution and hasattr(execution, "model_dump") else execution,
        "timing": timing.model_dump(mode="json") if hasattr(timing, "model_dump") else timing,
        "ledger_idx": ledger_idx,
        "ledger_hash": ledger_hash,
        "fingerprint": fingerprint,
        "params_hash": params_hash,
        "advisories": [],
        "enforced": True,
        "would_have_verdict": None,
    }
    return result
`

### src/agentguard/cli/analyzer.py
`python
import time
from typing import List, Optional
from agentguard.protocols import Analyzer, AnalysisContext
from agentguard.models.common import Finding
from agentguard.ids import finding_id as gen_finding_id
from .ir import CliPolicy
from .parser import CliParser
from .rules import evaluate_rules

class CliAnalyzer(Analyzer):
    def __init__(self, policy: Optional[CliPolicy] = None):
        self.policy = policy or CliPolicy()

    @property
    def id(self) -> str:
        return "cli"

    @property
    def handles(self) -> set[str]:
        return {"cli.exec"}

    @property
    def timeout_ms(self) -> int:
        return 100

    def analyze(self, ctx: AnalysisContext) -> List[Finding]:
        command_str = getattr(ctx.action.params, "command", None)
        if command_str is None and isinstance(ctx.action.params, dict):
            command_str = ctx.action.params.get("command")
            
        if not command_str:
            return [Finding(finding_id=gen_finding_id(), source="cli", rule_id="CLI-000", reason_code="SCHEMA_INVALID", severity=100, verdict_hint="DENY", message="Missing command")]
        
        parser = CliParser(self.policy)
        ir, parse_findings = parser.parse(command_str)
        
        # Publish IR for later stages
        ctx.scratch["cli_ir"] = ir
        
        if any(f.verdict_hint in ("DENY", "HALT") for f in parse_findings):
            return parse_findings
            
        rule_findings = evaluate_rules(ir, self.policy)
        return parse_findings + rule_findings
`

### src/agentguard/fs/analyzer.py
`python
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
`

### src/agentguard/store/ledger.py
`python
"""
Audit Ledger Writer — §8.3 (MVP)

Implements the LedgerWriter protocol (§0.7) with:
- JSONL file format with hash chaining (§8.3.1)
- Single writer with asyncio.Lock (§8.3.2)
- Durable/non-durable append semantics
- Startup recovery for crash-truncated records (§8.3.4)
- Segment rotation (§8.3.1)

The ledger is the tamper-evident audit trail. Every record's hash depends
on the previous record's hash, forming an unbroken chain.

Genesis: prev_hash = "0" * 64
Hash = sha256_hex(prev_hash.encode("ascii") + canonical_json(record_without_hash_field))
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

import structlog

from agentguard.canon import canonical_json, sha256_hex
from agentguard.models.ledger import LedgerRecord
from agentguard.timeutil import utcnow

logger = structlog.get_logger(__name__)

GENESIS_HASH = "0" * 64
MAX_PAYLOAD_BYTES = 256 * 1024  # §8.3.1: total line <= 256 KiB


def _compute_hash(prev_hash: str, record_dict: dict[str, Any]) -> str:
    """
    Compute ledger record hash per §8.3.1.

    hash = sha256_hex(prev_hash.encode("ascii") + canonical_json(record_without_hash_field))
    The record still contains prev_hash but NOT hash itself.
    """
    without_hash = {k: v for k, v in record_dict.items() if k != "hash"}
    return sha256_hex(prev_hash.encode("ascii") + canonical_json(without_hash))


def _truncate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Replace oversized payload values with truncation markers. §8.3.1"""
    serialized = canonical_json(payload)
    if len(serialized) <= MAX_PAYLOAD_BYTES:
        return payload
    # Truncate large values
    truncated = {}
    for k, v in payload.items():
        val_bytes = canonical_json(v)
        if len(val_bytes) > 8192:
            truncated[k] = {
                "_truncated": True,
                "sha256": sha256_hex(val_bytes),
                "size": len(val_bytes),
            }
        else:
            truncated[k] = v
    return truncated


def _segment_path(ledger_dir: str, segment_num: int) -> str:
    """Generate segment file path: ledger-000001.jsonl"""
    return os.path.join(ledger_dir, f"ledger-{segment_num:06d}.jsonl")


class FileLedgerWriter:
    """
    Production ledger writer — §8.3.

    Thread-safety: single writer enforced by asyncio.Lock.
    Durability: durable=True → os.fsync before returning.
    """

    def __init__(
        self,
        ledger_dir: str,
        *,
        fsync_policy: str = "always",
        segment_max_bytes: int = 268_435_456,
    ) -> None:
        self._ledger_dir = ledger_dir
        self._fsync_policy = fsync_policy
        self._segment_max_bytes = segment_max_bytes
        self._lock = asyncio.Lock()
        self._fd: int = -1
        self._segment_num: int = 1
        self._segment_path: str = ""
        self._segment_size: int = 0
        self._last_hash: str = GENESIS_HASH
        self._next_idx: int = 0
        self._last_fsync_ns: int = 0
        self._index_batch: list[tuple[int, str | None, str, str, str | None, int]] = []

        os.makedirs(ledger_dir, exist_ok=True)

    async def initialize(self) -> None:
        """
        Initialize or recover the ledger. §8.3.4

        1. Find existing segments and load state from the last one.
        2. Recover truncated records from crashes.
        3. Verify tail hash chain.
        """
        segments = sorted(Path(self._ledger_dir).glob("ledger-*.jsonl"))

        if not segments:
            # Fresh start — open first segment
            self._segment_num = 1
            self._open_segment()
            logger.info("ledger.initialized", segment=1, idx=0)
            return

        # Load from the last segment
        last_segment = segments[-1]
        self._segment_num = int(last_segment.stem.split("-")[1])
        self._segment_path = str(last_segment)

        # Read all records from the last segment to rebuild state
        await self._recover_segment(last_segment)

        # Re-open for appending
        self._fd = os.open(
            self._segment_path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o600,
        )
        self._segment_size = os.path.getsize(self._segment_path)

        logger.info(
            "ledger.recovered",
            segment=self._segment_num,
            next_idx=self._next_idx,
            last_hash=self._last_hash[:16] + "...",
        )

    async def _recover_segment(self, path: Path) -> None:
        """
        Read segment, recover from truncated writes, rebuild state. §8.3.4
        """
        content = path.read_bytes()
        lines = content.split(b"\n")

        good_lines: list[bytes] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                # Verify hash chain
                expected_hash = _compute_hash(
                    record.get("prev_hash", GENESIS_HASH), record
                )
                if record.get("hash") != expected_hash:
                    logger.warning(
                        "ledger.hash_mismatch",
                        idx=record.get("idx"),
                        expected=expected_hash[:16],
                        got=record.get("hash", "")[:16],
                    )
                    break
                good_lines.append(line)
                self._last_hash = record["hash"]
                self._next_idx = record["idx"] + 1
            except (json.JSONDecodeError, KeyError) as exc:
                logger.warning("ledger.truncated_record", error=str(exc))
                break

        # Truncate to last good line if needed (§8.3.4 step 1)
        good_content = b"\n".join(good_lines) + b"\n" if good_lines else b""
        if len(good_content) < len(content):
            truncated_bytes = len(content) - len(good_content)
            logger.warning("ledger.truncating", truncated_bytes=truncated_bytes)
            with open(path, "wb") as f:
                f.write(good_content)
                f.flush()
                os.fsync(f.fileno())

    def _open_segment(self) -> None:
        """Open a new ledger segment file."""
        if self._fd != -1:
            os.close(self._fd)
        self._segment_path = _segment_path(self._ledger_dir, self._segment_num)
        self._fd = os.open(
            self._segment_path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o600,
        )
        self._segment_size = 0

    def _maybe_rotate(self) -> None:
        """Rotate to a new segment if current exceeds max size. §8.3.1"""
        if self._segment_size >= self._segment_max_bytes:
            self._segment_num += 1
            self._open_segment()
            logger.info("ledger.rotated", segment=self._segment_num)

    async def append(
        self,
        *,
        run_id: str | None,
        event_type: str,
        actor: str,
        action_id: str | None,
        payload: dict[str, Any],
        durable: bool,
    ) -> LedgerRecord:
        """
        Append a record to the ledger. §8.3.2

        When durable=True, the record and all earlier records are guaranteed
        on disk (os.fsync) before this method returns.
        """
        async with self._lock:
            # Truncate oversized payloads
            safe_payload = _truncate_payload(payload)

            # Build record (without hash initially)
            rec_dict: dict[str, Any] = {
                "v": 1,
                "idx": self._next_idx,
                "ts": utcnow(),
                "run_id": run_id,
                "event_type": event_type,
                "actor": actor,
                "action_id": action_id,
                "payload": safe_payload,
                "prev_hash": self._last_hash,
            }

            # Compute hash
            rec_hash = _compute_hash(self._last_hash, rec_dict)
            rec_dict["hash"] = rec_hash

            # Serialize to canonical JSON + newline
            line = canonical_json(rec_dict) + b"\n"

            # Write (O_APPEND)
            offset = self._segment_size
            os.write(self._fd, line)
            self._segment_size += len(line)

            # Update state
            self._last_hash = rec_hash
            idx = self._next_idx
            self._next_idx += 1

            # Index batch entry
            self._index_batch.append(
                (idx, run_id, event_type, rec_dict["ts"], action_id, offset)
            )

            # Durability — §8.3.2
            now_ns = time.perf_counter_ns()
            should_fsync = durable or self._fsync_policy == "always"

            if not should_fsync:
                # Batch fsync: if > 100ms since last fsync, schedule one
                if (now_ns - self._last_fsync_ns) > 100_000_000:
                    should_fsync = True

            if should_fsync:
                os.fsync(self._fd)
                self._last_fsync_ns = now_ns

            # Check segment rotation
            self._maybe_rotate()

        # Build the LedgerRecord model to return
        record = LedgerRecord(**rec_dict)

        # TODO(spec-gap): publish to EventBus after releasing lock (§8.3.2)
        # TODO(spec-gap): checkpoint enqueue logic (§8.3.3)

        return record

    @property
    def next_idx(self) -> int:
        return self._next_idx

    @property
    def last_hash(self) -> str:
        return self._last_hash

    def close(self) -> None:
        """Close the file descriptor."""
        if self._fd != -1:
            try:
                os.fsync(self._fd)
            except OSError:
                pass
            os.close(self._fd)
            self._fd = -1
`

### src/agentguard/executors/docker.py
`python
import asyncio
import os
import docker
from typing import Optional
from agentguard.protocols import Executor, ExecutionResult
from agentguard.models.run import Run
from agentguard.models.action import ActionRecord

class DockerExecutor(Executor):
    def __init__(self, workspace_dir: str):
        self.workspace_dir = workspace_dir
        # Only init client if Docker is available
        try:
            self.client = docker.from_env()
        except Exception:
            self.client = None

    @property
    def id(self) -> str:
        return "docker"

    @property
    def handles(self) -> set[str]:
        return {"cli.exec"}

    async def execute(self, run: Run, action: ActionRecord, grant: Optional[any] = None) -> ExecutionResult:
        if not self.client:
            return ExecutionResult(status="FAILED", exit_code=-1, stdout="", stderr="Docker unavailable", truncated=False, duration_ms=0.0, output_tainted=False, taint_reasons=[], meta={})
            
        if isinstance(action.params, dict):
            command = action.params.get("command", "")
            timeout_s = action.params.get("timeout_s", 60.0)
        else:
            command = getattr(action.params, "command", "")
            timeout_s = getattr(action.params, "timeout_s", 60.0)
            
        container_name = f"agentguard_sandbox_{run.run_id}"
        
        try:
            # Check if container exists, else create it
            try:
                container = self.client.containers.get(container_name)
                if container.status != "running":
                    container.start()
            except docker.errors.NotFound:
                # 2.9.2 Container Hardening
                container = self.client.containers.run(
                    "python:3.11-slim",
                    name=container_name,
                    command="sleep infinity", # keep alive
                    detach=True,
                    network="agentguard_internal", # Ensure this network exists in compose
                    # Security options from 2.9.2
                    user="10001",
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges:true"],
                    read_only=True,
                    tmpfs={"/tmp": "size=256m,exec,mode=1777", "/home/agent": "size=64m,exec,mode=0700"},
                    volumes={self.workspace_dir: {"bind": "/workspace", "mode": "rw"}},
                    working_dir="/workspace",
                    pids_limit=128,
                    mem_limit="512m",
                    dns=["127.0.0.1"]
                )

            # Build argv according to 2.9.3 Execution
            cmd = ["/bin/sh", "-c", f"setsid bash --noprofile --norc -o pipefail -c {command}"]

            start_time = asyncio.get_event_loop().time()
            
            # Execute
            # In a real async implementation we'd use aio-docker or run_in_executor
            # Using synchronous docker-py in a thread for prototype
            loop = asyncio.get_running_loop()
            
            def run_sync():
                exec_instance = container.client.api.exec_create(
                    container.id, cmd, workdir="/workspace", user="10001", tty=False
                )
                
                output = container.client.api.exec_start(exec_instance['Id'])
                inspect = container.client.api.exec_inspect(exec_instance['Id'])
                return output, inspect
            
            # Simplified timeout handling
            try:
                output_bytes, inspect = await asyncio.wait_for(loop.run_in_executor(None, run_sync), timeout=timeout_s)
                exit_code = inspect.get("ExitCode", -1)
                status = "SUCCEEDED" if exit_code == 0 else "FAILED"
                stdout = output_bytes.decode("utf-8", errors="replace")
                
                # Cap output
                truncated = False
                if len(stdout) > 65536:
                    stdout = stdout[:65536] + "\n[...truncated bytes by AgentGuard]"
                    truncated = True
                    
                duration = (asyncio.get_event_loop().time() - start_time) * 1000
                
                return ExecutionResult(
                    status=status,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr="",
                    truncated=truncated,
                    duration_ms=duration,
                    output_tainted=False,
                    taint_reasons=[],
                    meta={"exec_id": inspect.get("Id", "")}
                )
                
            except asyncio.TimeoutError:
                duration = (asyncio.get_event_loop().time() - start_time) * 1000
                # Kill process group as per 2.9.3
                pid = inspect.get("Pid", 0)
                if pid > 0:
                    def kill_pg():
                        container.client.api.exec_create(
                            container.id, 
                            ["/bin/sh", "-c", f"kill -KILL -- -$(awk '{{print $5}}' /proc/{pid}/stat)"], 
                            user="0"
                        )
                    await loop.run_in_executor(None, kill_pg)
                
                return ExecutionResult(
                    status="TIMED_OUT", exit_code=124, stdout="", stderr="Timed out",
                    truncated=False, duration_ms=duration, output_tainted=False, taint_reasons=[], meta={}
                )
                
        except Exception as e:
            return ExecutionResult(status="FAILED", exit_code=-1, stdout="", stderr=str(e), truncated=False, duration_ms=0.0, output_tainted=False, taint_reasons=[], meta={})
`

