"""
AgentGuard Registry — §0.5 + Part 2 §A4 + Part 3 §B8

All enums use StrEnum so later parts can extend without editing this file.
Reason codes are registered as sets per group for O(1) membership checks.
Ledger event types are a flat set.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum


# ═══════════════════════════════════════════════════════════════════════
# VERDICTS
# ═══════════════════════════════════════════════════════════════════════

class Verdict(StrEnum):
    ALLOW = "ALLOW"
    ALLOW_WITH_GRANT = "ALLOW_WITH_GRANT"
    ASK_HUMAN = "ASK_HUMAN"
    DENY = "DENY"
    HALT = "HALT"


VERDICT_ORDER: dict[Verdict, int] = {
    Verdict.ALLOW: 0,
    Verdict.ALLOW_WITH_GRANT: 1,
    Verdict.ASK_HUMAN: 2,
    Verdict.DENY: 3,
    Verdict.HALT: 4,
}


class NextStep(StrEnum):
    PROCEED = "PROCEED"
    RETRY_AFTER = "RETRY_AFTER"
    REPLAN = "REPLAN"
    AWAIT_HUMAN = "AWAIT_HUMAN"
    ABORT = "ABORT"


# NEXT_STEP_TABLE mapping verdicts → default next_step (§1.5.3)
NEXT_STEP_TABLE: dict[Verdict, NextStep] = {
    Verdict.ALLOW: NextStep.PROCEED,
    Verdict.ALLOW_WITH_GRANT: NextStep.PROCEED,
    Verdict.ASK_HUMAN: NextStep.AWAIT_HUMAN,
    Verdict.DENY: NextStep.REPLAN,
    Verdict.HALT: NextStep.ABORT,
}


# ═══════════════════════════════════════════════════════════════════════
# ACTION TYPES  (Part 1 §0.5 + Part 2 §A4)
# ═══════════════════════════════════════════════════════════════════════

class ActionType(StrEnum):
    CLI_EXEC = "cli.exec"
    NET_HTTP = "net.http"
    FS_READ = "fs.read"
    FS_WRITE = "fs.write"
    FS_DELETE = "fs.delete"
    FS_LIST = "fs.list"
    GUI_CLICK = "gui.click"
    GUI_TYPE = "gui.type"
    GUI_NAVIGATE = "gui.navigate"
    # Part 2 §A4 additions
    GUI_SNAPSHOT = "gui.snapshot"
    GUI_SELECT = "gui.select"
    GUI_PRESS = "gui.press"


# High-impact action types for taint escalation (§3.8.3)
HIGH_IMPACT_TYPES: frozenset[ActionType] = frozenset({
    ActionType.CLI_EXEC,
    ActionType.NET_HTTP,
    ActionType.FS_WRITE,
    ActionType.FS_DELETE,
    ActionType.GUI_CLICK,
    ActionType.GUI_TYPE,
    ActionType.GUI_NAVIGATE,
    ActionType.GUI_SELECT,
    ActionType.GUI_PRESS,
})


# ═══════════════════════════════════════════════════════════════════════
# RUN / ACTION STATUS
# ═══════════════════════════════════════════════════════════════════════

class RunStatus(StrEnum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    HALTED = "HALTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ABANDONED = "ABANDONED"


class ActionStatus(StrEnum):
    RECEIVED = "RECEIVED"
    EVALUATING = "EVALUATING"
    DENIED = "DENIED"
    HALTED = "HALTED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    INDETERMINATE = "INDETERMINATE"


class ApprovalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


# ═══════════════════════════════════════════════════════════════════════
# SEVERITY BANDS
# ═══════════════════════════════════════════════════════════════════════

class Severity(IntEnum):
    INFO = 0
    LOW = 20
    MEDIUM = 40
    HIGH = 60
    CRITICAL = 80


# ═══════════════════════════════════════════════════════════════════════
# REASON CODES — §0.5 + Part 2 §A4 + Part 3 §B8
# Grouped by component. Union is REASON_CODES.
# ═══════════════════════════════════════════════════════════════════════

HUB_REASON_CODES: frozenset[str] = frozenset({
    "SCHEMA_INVALID", "RUN_NOT_ACTIVE", "RUN_PAUSED",
    "BUDGET_EXHAUSTED", "CIRCUIT_OPEN", "CIRCUIT_HALF_OPEN",
    "LOW_CONFIDENCE", "TAINTED_CONTEXT_ESCALATION",
    "ANALYZER_ERROR", "ANALYZER_TIMEOUT",
    "HUMAN_UNAVAILABLE", "APPROVAL_REQUIRED",
    "APPROVAL_REJECTED", "APPROVAL_EXPIRED",
    "PARAMS_HASH_MISMATCH", "KILL_SWITCH",
    "EXECUTOR_UNAVAILABLE", "IDEMPOTENCY_CONFLICT",
    "POLICY_ALWAYS_ASK", "GRANT_APPLIED",
    "TRANSIENT_FAILURE", "PERMANENT_FAILURE",
    "COMPROMISE_SUSPECTED", "WORKSPACE_TOO_LARGE", "HOST_PATH_NOT_ALLOWED",
    "POLICY_CUSTOM", "POLICY_PLUGIN", "EVASION_SUSPECTED",
})

CLI_REASON_CODES: frozenset[str] = frozenset({
    "CLI_PARSE_ERROR", "CLI_TOO_LONG", "CLI_CONTROL_CHARS",
    "CLI_CONFUSABLE_UNICODE", "CLI_DYNAMIC_COMMAND", "CLI_PIPE_TO_SHELL",
    "CLI_EVAL", "CLI_ENCODED_EXEC", "CLI_NESTED_TOO_DEEP",
    "CLI_DESTRUCTIVE_DELETE", "CLI_CATASTROPHIC_DELETE", "CLI_DISK_DESTRUCTIVE",
    "CLI_PERMISSION_CHANGE", "CLI_SENSITIVE_PATH", "CLI_CREDENTIAL_ACCESS",
    "CLI_PRIV_ESC", "CLI_DIRECT_NETWORK_TOOL", "CLI_PKG_UNVERIFIED_SOURCE",
    "CLI_PERSISTENCE", "CLI_BACKGROUND", "CLI_DEV_TCP", "CLI_FORK_BOMB",
    "CLI_GIT_DESTRUCTIVE", "CLI_CONTAINER_ESCAPE", "CLI_SYSTEM_CONTROL",
    "CLI_INLINE_CODE", "CLI_ENV_TAMPER", "CLI_NOT_ALLOWLISTED",
    "CLI_OUTSIDE_WORKSPACE", "CLI_GLOB_UNBOUNDED",
})

NET_REASON_CODES: frozenset[str] = frozenset({
    "NET_SCHEME_DENIED", "NET_USERINFO_IN_URL", "NET_HOMOGRAPH",
    "NET_IP_LITERAL", "NET_PRIVATE_RANGE", "NET_PORT_DENIED",
    "NET_DOMAIN_DENIED", "NET_DOMAIN_NOT_ALLOWLISTED",
    "NET_METHOD_REQUIRES_APPROVAL", "NET_REDIRECT_DENIED",
    "NET_REDIRECT_LIMIT", "NET_PII_EGRESS", "NET_SECRET_EGRESS",
    "NET_CANARY_EGRESS", "NET_HIGH_ENTROPY_EGRESS", "NET_RATE_LIMITED",
    "NET_BYTES_QUOTA", "NET_BODY_TOO_LARGE", "NET_DOH_BLOCKED",
    "NET_SNI_MISMATCH", "NET_UPGRADE_DENIED", "NET_INJECTION_SUSPECTED",
    "NET_PROXY_AUTH_FAILED", "NET_POLICY_STALE",
})

FS_REASON_CODES: frozenset[str] = frozenset({
    "FS_PATH_INVALID", "FS_OUTSIDE_WORKSPACE", "FS_SYMLINK_ESCAPE",
    "FS_SENSITIVE_PATH", "FS_PROTECTED_PATH", "FS_SELF_PROTECTION",
    "FS_HONEYTOKEN_ACCESS", "FS_WIPE_SUSPECTED", "FS_MASS_CHANGE",
    "FS_QUOTA", "FS_SECRET_IN_CONTENT", "FS_SCRIPT_SUSPECT",
    "FS_EXECUTABLE_BINARY", "FS_INTEGRITY_REVERTED", "FS_CONFLICT",
})

GUI_REASON_CODES: frozenset[str] = frozenset({
    "GUI_RED_ZONE_DESTRUCTIVE", "GUI_RED_ZONE_FINANCIAL",
    "GUI_RED_ZONE_ADMIN", "GUI_RED_ZONE_PUBLISH",
    "GUI_CREDENTIAL_FIELD", "GUI_DECEPTIVE_ELEMENT", "GUI_OCCLUDED",
    "GUI_ELEMENT_CHANGED", "GUI_STALE_SNAPSHOT", "GUI_FILE_UPLOAD",
    "GUI_DOWNLOAD_BLOCKED", "GUI_CROSS_ORIGIN_SUBMIT", "GUI_RISKY_PAGE",
    "GUI_SCHEME_DENIED", "GUI_TYPED_SECRET", "GUI_KEYBOARD_SHORTCUT",
    "GUI_POPUP_BLOCKED", "GUI_NAV_BLOCKED",
})

RULES_REASON_CODES: frozenset[str] = frozenset({
    "RULEPACK_MATCH", "RULEPACK_STALE", "RULEPACK_ERROR",
})

GROUNDING_REASON_CODES: frozenset[str] = frozenset({
    "UNGROUNDED_ACTION", "INVALID_EVIDENCE", "STALE_INFORMATION",
    "CONTRADICTORY_RATIONALE", "BLIND_OVERWRITE", "HIGH_UNCERTAINTY",
    "CAPACITY_EXCEEDED",
})

REASON_CODES: frozenset[str] = (
    HUB_REASON_CODES | CLI_REASON_CODES | NET_REASON_CODES
    | FS_REASON_CODES | GUI_REASON_CODES | RULES_REASON_CODES
    | GROUNDING_REASON_CODES
)

REASON_TEXT: dict[str, str] = {
    "UNGROUNDED_ACTION": "The action targets something the agent never observed in this run.",
    "INVALID_EVIDENCE": "The evidence the agent cited does not exist or does not support the action.",
    "STALE_INFORMATION": "The file changed after the agent last read it.",
    "CONTRADICTORY_RATIONALE": "The agent's stated reason contradicts the latest observed result.",
}


# ═══════════════════════════════════════════════════════════════════════
# LEDGER EVENT TYPES — §0.7 + Part 2 §A4 + Part 3 §B8
# ═══════════════════════════════════════════════════════════════════════

LEDGER_EVENT_TYPES: frozenset[str] = frozenset({
    # Part 1
    "run.created", "run.status_changed", "run.completed",
    "thought.recorded",
    "action.received", "action.verdict",
    "approval.requested", "approval.resolved",
    "action.executing", "action.executed",
    "taint.raised", "taint.cleared",
    "net.egress", "breaker.state_changed",
    "progress.updated", "policy.reloaded",
    "rulefeed.updated", "ledger.checkpoint",
    # Part 2
    "workspace.created", "workspace.integrity_violation",
    "workspace.promoted", "workspace.discarded",
    "honeytoken.triggered", "gui.dialog", "gui.popup_blocked",
    "rulepack.state_changed", "trust.key_changed",
    # Part 3
    "grant.created", "grant.consumed", "grant.revoked",
    "policy.rejected", "anomaly.signal",
    "escalation.raised", "escalation.resolved",
    "run.resumed", "ledger.recovered",
    "milestone.state_changed", "progress.judged",
    "probe.executed",
    # Part 4
    "insight.snapshot", "eval.scenario.started", "eval.scenario.finished",
})


# ═══════════════════════════════════════════════════════════════════════
# HTTP ERROR CODES — §0.6 + Part 3 §B8
# ═══════════════════════════════════════════════════════════════════════

HTTP_ERROR_STATUS: dict[str, int] = {
    "UNAUTHENTICATED": 401,
    "FORBIDDEN": 403,
    "RUN_NOT_FOUND": 404,
    "ACTION_NOT_FOUND": 404,
    "APPROVAL_NOT_FOUND": 404,
    "GRANT_NOT_FOUND": 404,
    "ESCALATION_NOT_FOUND": 404,
    "MILESTONE_NOT_FOUND": 404,
    "SCHEMA_INVALID": 422,
    "POLICY_INVALID": 422,
    "IDEMPOTENCY_CONFLICT": 409,
    "INVALID_STATE": 409,
    "COMPLETION_UNVERIFIED": 409,
    "PAYLOAD_TOO_LARGE": 413,
    "CAPACITY_EXCEEDED": 429,
    "INTERNAL": 500,
    "LEDGER_INTEGRITY": 500,
}
