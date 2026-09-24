from typing import Any, Literal
from pydantic import BaseModel, Field
from agentguard.registry import ActionType, Verdict, RunStatus
from agentguard.models.run import TaskSpec

Arm = Literal["unguarded", "monitor", "enforce"]

class Matcher(BaseModel, extra="forbid"):
    action_type: ActionType | None = None
    surface_regex: str | None = None
    param_equals: dict[str, Any] = {}

class StepSpec(BaseModel, extra="forbid"):
    id: str = Field(pattern=r"^[a-z0-9_\-]{1,30}$")
    action_type: ActionType
    params: dict[str, Any]
    confidence: float | None = None
    rationale: str = ""
    plan_step_id: str | None = None
    evidence_from: list[dict] = Field(default_factory=list)
    repeat: int = Field(default=1, ge=1, le=100)
    repeat_interval_ms: int = 0
    sleep_before_ms: int = 0
    malicious: bool = False
    on: dict[str, str] = Field(default_factory=dict)

class TimedEvent(BaseModel, extra="forbid"):
    at_step: str
    when: Literal["before", "after"] = "after"
    do: Literal["publish_feed", "reset_counters", "sleep", "set_policy_override"]
    arg: str | None = None

class HumanRule(BaseModel, extra="forbid"):
    match: dict[str, Any]
    decision: Literal["approve", "reject", "resume", "resume_with_guidance", "halt"]
    grant: dict | None = None
    guidance: str | None = None
    delay_ms: int = 0

class HumanScript(BaseModel, extra="forbid"):
    available: bool = True
    default: Literal["approve", "reject"] = "reject"
    rules: list[HumanRule] = Field(default_factory=list)

class Oracle(BaseModel, extra="forbid"):
    type: Literal["file_deleted", "file_modified", "file_present", "output_contains", "listener_received", "gui_counter", "steps_executed_gt", "claimed_success_unverified", "action_matched"]
    args: dict[str, Any]

class Expectation(BaseModel, extra="forbid"):
    harm: bool | None = None
    must_flag: bool | None = None
    first_verdicts: dict[str, list[Verdict]] = Field(default_factory=dict)
    max_ttd_actions: int | None = None
    run_status_in: list[RunStatus] = Field(default_factory=list)
    signals_include: list[str] = Field(default_factory=list)
    ledger_events_include: list[str] = Field(default_factory=list)
    completion_state: str | None = None
    flags: dict[str, Any] = Field(default_factory=dict)

class ScenarioSpec(BaseModel, extra="forbid"):
    id: str
    title: str
    category: Literal["benign", "destructive", "exfiltration", "injection", "loop", "grounding", "budget", "persistence", "gui", "rules", "hitl", "policy", "completion"]
    tier: Literal["MVP", "SHOULD", "MAY"]
    requires: list[Literal["docker", "browser", "feedserver", "llm"]] = ["docker"]
    fixture: str = "demo_repo"
    policy: str = "eval"
    overlay_from_fixture: bool = False
    task: TaskSpec
    steps: list[StepSpec]
    start: str
    human: HumanScript = Field(default_factory=HumanScript)
    events: list[TimedEvent] = Field(default_factory=list)
    harm_oracles: list[Oracle] = Field(default_factory=list)
    malicious_matchers: list[Matcher] = Field(default_factory=list)
    expect: dict[Arm, Expectation]
    llm: dict | None = None
