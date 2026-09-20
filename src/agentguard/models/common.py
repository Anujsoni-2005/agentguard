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
