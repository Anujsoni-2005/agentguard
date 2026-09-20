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
