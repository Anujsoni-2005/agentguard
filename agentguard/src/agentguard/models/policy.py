"""
AgentGuard Policy Models (§7.2, §10.3)
"""
from __future__ import annotations

from typing import Literal, Dict, List, Optional, Any
from pydantic import BaseModel, Field, ConfigDict, model_validator
from agentguard.registry import ActionType
from agentguard.models.run import Budgets
from agentguard.policy.predicate import Predicate
from agentguard.decision.impact import ImpactClass

class HumanPolicy(BaseModel):
    available_default: bool = Field(default=True, json_schema_extra={"merge": "base_only"})
    # UI slider caps at 1h for usability; API validation allows up to 24h per spec §7.2
    approval_ttl_s: int = Field(default=900, ge=30, le=86400, json_schema_extra={"merge": "min", "ui": {"control": "slider", "min": 30, "max": 3600}})
    max_unanswered_approvals: int = Field(default=2, ge=1, le=100, json_schema_extra={"merge": "min"})

class ConfidencePolicy(BaseModel):
    min_confidence: float = Field(default=0.5, ge=0.0, le=1.0, json_schema_extra={"merge": "max", "ui": {"control": "slider", "min": 0.0, "max": 1.0, "step": 0.05}})
    apply_to: List[ActionType] = Field(
        default=[ActionType.CLI_EXEC, ActionType.NET_HTTP, ActionType.FS_WRITE, ActionType.FS_DELETE,
                 ActionType.GUI_CLICK, ActionType.GUI_TYPE, ActionType.GUI_SELECT, ActionType.GUI_PRESS, ActionType.GUI_NAVIGATE],
        json_schema_extra={"merge": "union"}
    )

class BudgetCaps(BaseModel):
    max_steps_cap: int = Field(default=500, ge=1, le=10_000, json_schema_extra={"merge": "min", "ui": {"control": "number"}})
    max_wall_seconds_cap: int = Field(default=3600, ge=10, le=86_400, json_schema_extra={"merge": "min"})
    max_egress_bytes_cap: int = Field(default=52_428_800, ge=0, le=1073741824, json_schema_extra={"merge": "min"})
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
    default_ttl_s: int = Field(default=300, ge=30, le=86400, json_schema_extra={"merge": "min"})
    default_uses: int = Field(default=1, ge=1, le=10000, json_schema_extra={"merge": "min"})
    max_ttl_s: int = Field(default=3600, ge=30, le=86400, json_schema_extra={"merge": "min", "ui": {"control": "number"}})
    max_uses: int = Field(default=100, ge=1, le=10000, json_schema_extra={"merge": "min"})
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
    when: Predicate
    
    @model_validator(mode="after")
    def validate_predicate_limits(self) -> 'CustomRule':
        def count_nodes(pred: Any, depth: int) -> tuple[int, int]:
            if depth > 6:
                raise ValueError("Predicate nesting depth exceeds 6")
            
            c = 1
            max_d = depth
            
            if hasattr(pred, 'op'):
                if pred.op in ("all", "any"):
                    for child in pred.conditions:
                        child_c, child_d = count_nodes(child, depth + 1)
                        c += child_c
                        max_d = max(max_d, child_d)
                elif pred.op == "not":
                    child_c, child_d = count_nodes(pred.condition, depth + 1)
                    c += child_c
                    max_d = max(max_d, child_d)
            elif isinstance(pred, dict):
                op = pred.get("op")
                if op in ("all", "any"):
                    for child in pred.get("conditions", []):
                        child_c, child_d = count_nodes(child, depth + 1)
                        c += child_c
                        max_d = max(max_d, child_d)
                elif op == "not":
                    if "condition" in pred:
                        child_c, child_d = count_nodes(pred["condition"], depth + 1)
                        c += child_c
                        max_d = max(max_d, child_d)
            return c, max_d
            
        total_nodes, max_depth = count_nodes(self.when, 1)
        if total_nodes > 50:
            raise ValueError(f"Predicate exceeds max nodes of 50 (got {total_nodes})")
        return self
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
    require_evidence_for: List[ImpactClass] = Field(default=[ImpactClass.DELETE, ImpactClass.NET_WRITE, ImpactClass.GIT_PUSH, ImpactClass.GUI_STATE_CHANGE], json_schema_extra={"merge": "union"})
    strict_evidence: bool = Field(default=False, json_schema_extra={"merge": "or"})
    citation_max_age_actions: int = Field(default=30, json_schema_extra={"merge": "min"})
    quote_min_len: int = Field(default=8, json_schema_extra={"merge": "base_only"})
    blind_overwrite: Literal["off","warn","ask"] = Field(default="warn", json_schema_extra={"merge": "stricter_enum", "order": ["off", "warn", "ask"]})
    stale_read: Literal["off","warn","ask"] = Field(default="ask", json_schema_extra={"merge": "stricter_enum", "order": ["off", "warn", "ask"]})
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
    
    @model_validator(mode="after")
    def validate_sum(self) -> 'UncertaintyWeights':
        total = self.confidence + self.grounding + self.ambiguity + self.novelty + self.failure
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"Uncertainty weights must sum to 1.0, got {total}")
        return self

class UncertaintyPolicy(BaseModel):
    enabled: bool = Field(default=True, json_schema_extra={"merge": "or"})
    weights: UncertaintyWeights = Field(default_factory=UncertaintyWeights, json_schema_extra={"merge": "base_only"})
    default_confidence: float = Field(default=0.6, json_schema_extra={"merge": "min"})
    advise_above: float = Field(default=0.45, json_schema_extra={"merge": "min"})
    ask_above: float = Field(default=0.65, json_schema_extra={"merge": "min"})
    apply_to_impact: Literal["high_impact_only","all"] = Field(default="high_impact_only", json_schema_extra={"merge": "stricter_enum", "order": ["high_impact_only", "all"]})
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
    workspace_root: str = Field(default="/workspace", json_schema_extra={"merge": "base_only"})
    read_allow_paths: List[str] = Field(default_factory=list, json_schema_extra={"merge": "intersect"})
    sensitive_path_globs: List[str] = Field(default_factory=list, json_schema_extra={"merge": "union"})
    deny_paths: List[str] = Field(default=[".agentguard.yaml","**/.agentguard.yaml","policies/**","**/agentguard*.yaml","**/.agentguard/**"], json_schema_extra={"merge": "union"})
    protected_path_globs: List[str] = Field(default=[".git/hooks/**",".git/config",".github/workflows/**",".gitlab-ci.yml",".circleci/**",
                                       "Jenkinsfile",".pre-commit-config.yaml",".husky/**","**/authorized_keys"], json_schema_extra={"merge": "union"})
    executable_ext: List[str] = Field(default=[".sh",".bash",".py",".js",".mjs",".rb",".pl",".php",".ps1",".bat"], json_schema_extra={"merge": "union"})
    max_read_bytes: int = Field(default=1_048_576, json_schema_extra={"merge": "min"})
    max_write_bytes: int = Field(default=5_242_880, json_schema_extra={"merge": "min"})
    max_workspace_growth_bytes: int = Field(default=209_715_200, json_schema_extra={"merge": "min"})
    max_list_entries: int = Field(default=1000, json_schema_extra={"merge": "min"})
    max_path_len: int = Field(default=4096, json_schema_extra={"merge": "min"})
    max_component_len: int = Field(default=255, json_schema_extra={"merge": "min"})
    max_depth: int = Field(default=32, json_schema_extra={"merge": "min"})
    mass_delete_threshold_files: int = Field(default=50, json_schema_extra={"merge": "min"})
    wipe_shrink_ratio: float = Field(default=0.8, json_schema_extra={"merge": "min"})
    copy_exclude_globs: List[str] = Field(default_factory=list, json_schema_extra={"merge": "union"})
    auto_promote_safe: bool = Field(default=False, json_schema_extra={"merge": "and"})
    honeytokens_enabled: bool = Field(default=True, json_schema_extra={"merge": "or"})
    scan_script_content: bool = Field(default=True, json_schema_extra={"merge": "or"})

from typing import Literal

class GuiPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    lexicon: dict[str, list[str]] = Field(default_factory=lambda: {
        "destructive": ["delete", "remove", "erase", "destroy", "wipe", "terminate", "deactivate", "close account", "drop", "purge", "reset", "revoke", "uninstall", "format", "discard all", "clear all", "unsubscribe all"],
        "financial": ["pay", "purchase", "buy", "buy now", "checkout", "place order", "confirm payment", "transfer", "send money", "withdraw", "subscribe", "upgrade", "donate", "refund", "top up"],
        "admin": ["admin", "administrator", "permissions", "grant access", "add user", "invite", "invite member", "roles", "api key", "access token", "personal access token", "secret", "ssh keys", "deploy key", "webhook", "transfer ownership", "make public", "visibility"],
        "publish": ["publish", "post", "tweet", "share", "send", "submit", "deploy", "release", "merge", "push", "approve", "confirm"],
        "auth_change": ["change password", "update password", "change email", "two-factor", "2fa", "disable mfa", "recovery codes", "security settings"]
    })
    category_verdicts: dict[str, tuple[Literal["ASK_HUMAN", "DENY"], int]] = Field(default_factory=lambda: {
        "destructive": ("ASK_HUMAN", 65),
        "financial": ("ASK_HUMAN", 75),
        "admin": ("ASK_HUMAN", 60),
        "publish": ("ASK_HUMAN", 55),
        "auth_change": ("ASK_HUMAN", 70)
    })
    block_financial: bool = False
    risk_url_globs: list[str] = Field(default=["*/admin*", "*/settings/security*", "*/billing*", "*/account/delete*", "*/oauth/authorize*", "*/checkout*", "*/payment*", "*/api-keys*", "*/tokens*"])
    max_tabs: int = 3
    allow_downloads: bool = False
    allow_credential_typing: bool = False
    typed_text_max: int = 2000
    snapshot_max_age_s: int = 120
    settle_ms: int = 3000

class AnomalyPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    window_size: int = 200
    repeat_fail_consecutive_warn: int = 3
    repeat_fail_window_s: int = 60
    repeat_fail_trip_count: int = 5
    repeat_same_output_warn: int = 3
    repeat_same_output_trip: int = 6
    velocity_warn_count: int = 10
    velocity_warn_window_s: int = 5
    velocity_trip_count: int = 20
    velocity_trip_window_s: int = 10
    periodic_lookback: int = 24
    periodic_max_period: int = 4
    periodic_warn_cycles: int = 2
    periodic_trip_cycles: int = 4
    deny_streak_warn: int = 4
    deny_streak_trip: int = 8
    deny_streak_window_s: int = 300
    failure_ratio_warn_window: int = 10
    failure_ratio_warn: float = 0.7
    failure_ratio_trip_window: int = 20
    failure_ratio_trip: float = 0.85
    failure_ratio_min_samples: int = 10
    timeout_warn_consecutive: int = 3
    timeout_trip_consecutive: int = 5
    domain_burst_window_s: int = 300
    domain_burst_warn: int = 6
    domain_burst_trip: int = 12
    evasion_ttl_s: int = 600
    critical_probe_escalate: int = 5
    critical_probe_trip: int = 8
    budget_warn_ratio: float = 0.8
    budget_escalate_ratio: float = 0.95
    output_secret_warn: int = 3
    latency_outlier_factor: float = 5.0
    latency_outlier_min_ms: int = 5000
    latency_outlier_min_samples: int = 5
    advisory_dedup_s: int = 30

class BreakerPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    probe_actions: int = 2
    cooldown_base_s: int = 30
    cooldown_max_s: int = 300
    max_trips_per_run: int = 3
    auto_half_open_after_s: int | None = None
    escalation_ttl_s: int = 1800
    pause_on_escalate: bool = True
    half_open_high_impact_asks: bool = True

class JudgePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    every_n_actions: int = 6
    min_interval_s: int = 15
    max_calls_per_run: int = 20
    max_tokens: int = 400
    timeout_s: int = 8
    escalate_after_consecutive_no: int = 2
    allow_domains: list[str] = []

class UncertaintyWeights(BaseModel):
    confidence: float = 0.40
    grounding: float = 0.20
    ambiguity: float = 0.15
    novelty: float = 0.10
    failure: float = 0.15

class UncertaintyPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    default_confidence: float = 0.8
    apply_to_impact: Literal["high", "all"] = "high"
    ask_above: float = 0.65
    advise_above: float = 0.40
    calibration_prior_strength: float = 10.0
    weights: UncertaintyWeights = Field(default_factory=UncertaintyWeights)

class GroundingPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    require_evidence_for: list[str] = ["execution", "fs_write", "net_out", "secrets"]
    strict_evidence: bool = True
    stale_read: Literal["ask", "warn", "off"] = "ask"
    blind_overwrite: Literal["ask", "warn", "off"] = "ask"
    citation_max_age_actions: int = 50

class DecisionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    auto_reject_asks: bool = False
    ungrounded_streak_escalate: int = 3
    ungrounded_streak_window: int = 10
    low_conf_streak: int = 3

class ProgressPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    stall_warn_actions: int = 6
    stall_escalate_actions: int = 12
    stall_warn_seconds: int = 180
    stall_escalate_seconds: int = 420
    plan_link_window: int = 10
    plan_link_min_ratio: float = 0.5
    milestone_overrun_warn_factor: float = 1.0
    milestone_overrun_escalate_factor: float = 2.0
    projection_check_after_ratio: float = 0.3
    claim_grace_actions: int = 2
    thrash_edits: int = 5
    thrash_window_s: int = 600
    verifier_timeout_ms: int = 500
    probe_timeout_ms: int = 3000
    judge: JudgePolicy = Field(default_factory=JudgePolicy)

# --- Import Phase 1 & 3 Policies ---
from agentguard.cli.ir import CliPolicy
from agentguard.net.models import NetPolicy

class PolicyDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal[1] = 1
    name: str = Field(default="default", max_length=60, json_schema_extra={"merge": "base_only"})
    description: str = Field(default="", max_length=500, json_schema_extra={"merge": "base_only"})
    mode: Literal["enforce","monitor"] = Field(default="enforce", json_schema_extra={"merge": "stricter_enum", "order": ["monitor", "enforce"], "ui": {"control": "toggle"}})
    monitor_hard_block_severity: int = Field(default=95, ge=80, le=100, json_schema_extra={"merge": "min"})
    human: HumanPolicy = Field(default_factory=HumanPolicy)
    confidence: ConfidencePolicy = Field(default_factory=ConfidencePolicy)
    # kept stricter_tier_map as requested and documented choice
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
    
    @model_validator(mode="after")
    def validate_cross_fields(self) -> 'PolicyDoc':
        if self.grants.max_ttl_s < self.grants.default_ttl_s:
            raise ValueError("grants.max_ttl_s cannot be less than grants.default_ttl_s")
        if self.grants.max_uses < self.grants.default_uses:
            raise ValueError("grants.max_uses cannot be less than grants.default_uses")
        if self.uncertainty.advise_above >= self.uncertainty.ask_above:
            raise ValueError("uncertainty.advise_above must be strictly less than uncertainty.ask_above")
            
        seen_ids = set()
        for r in self.custom_rules:
            if r.id in seen_ids:
                raise ValueError(f"custom_rules contains duplicate id: {r.id}")
            seen_ids.add(r.id)
            
        return self

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
