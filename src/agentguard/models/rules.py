"""
AgentGuard Rule Packs Models (§6.2)
"""
from __future__ import annotations

from typing import Literal, List, Dict, Union, Optional
from pydantic import BaseModel, Field, ConfigDict
from agentguard.registry import ActionType


class Signature(BaseModel):
    alg: Literal["ed25519"]
    key_id: str = Field(pattern=r"^[a-z0-9][a-z0-9\-_.]{2,60}$")
    sig_b64: str


class TestVector(BaseModel):
    surface: str  # Surface is a Literal string type, simplifying as str here
    input: str = Field(max_length=4096)
    expect: Literal["match", "nomatch"]


class RuleBase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str = Field(pattern=r"^[A-Za-z0-9_]{1,40}$")
    enabled: bool = True
    verdict: Literal["ASK_HUMAN", "DENY", "HALT"]
    severity: int = Field(ge=40, le=100)
    reason_code: str = "RULEPACK_MATCH"
    message: str = Field(max_length=300)
    action_types: Optional[List[ActionType]] = None
    tags: List[str] = []
    references: List[str] = []
    test_vectors: List[TestVector] = Field(min_length=1)


class LiteralRule(RuleBase):
    type: Literal["literal"]
    surfaces: List[str]
    values: List[str] = Field(max_length=20000)
    match: Literal["substring", "word"] = "substring"


class RegexRule(RuleBase):
    type: Literal["regex"]
    surfaces: List[str]
    pattern: str = Field(max_length=512)
    flags: List[Literal["i", "m", "s"]] = []
    validators: List[Literal["luhn", "verhoeff", "entropy>=4.0", "entropy>=4.5", "min_len_16"]] = []


class DomainRule(RuleBase):
    type: Literal["domain"]
    patterns: List[str] = Field(max_length=20000)
    applies_to: List[Literal["net.host", "gui.url"]] = ["net.host", "gui.url"]


class ArgvRule(RuleBase):
    type: Literal["argv"]
    command: str
    flags_any: List[str] = []
    args_glob_any: List[str] = []
    require_pipeline_next: List[str] = []


class PathRule(RuleBase):
    type: Literal["path_glob"]
    globs: List[str]
    ops: List[Literal["read", "write", "delete", "any"]] = ["any"]


class GuiLabelRule(RuleBase):
    type: Literal["gui_label"]
    terms: List[str]
    category: str


from typing import Annotated

# Discriminator for Rule
Rule = Annotated[
    Union[LiteralRule, RegexRule, DomainRule, ArgvRule, PathRule, GuiLabelRule],
    Field(discriminator="type")
]


class TaintPattern(BaseModel):
    id: str
    pattern: str
    weight: int = Field(ge=1, le=3)
    test_vectors: List[TestVector]


class RedactPattern(BaseModel):
    kind: str = Field(pattern=r"^[a-z0-9_]{2,30}$")
    pattern: str
    test_vectors: List[TestVector]


class AllowAdditions(BaseModel):
    domains: List[str] = []
    commands: List[str] = []
    pkg_indexes: List[str] = []


class RulePack(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    pack_id: str = Field(pattern=r"^[a-z0-9][a-z0-9\-]{2,40}$")
    name: str = Field(max_length=100)
    description: str = Field(default="", max_length=1000)
    version: str
    channel: Literal["stable", "beta"] = "stable"
    publisher: str = Field(max_length=100)
    published_at: str
    expires_at: Optional[str] = None
    min_agentguard: str = "1.0.0"
    rules: List[Rule] = Field(max_length=5000)
    lexicon_additions: Dict[str, List[str]] = {}
    taint_patterns: List[TaintPattern] = []
    redact_patterns: List[RedactPattern] = []
    allow_additions: Optional[AllowAdditions] = None
    tags: List[str] = []


class RulePackEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    payload: RulePack
    signature: Signature


class TrustKey(BaseModel):
    key_id: str
    publisher: str
    public_key_b64: str
    capabilities: set[Literal["ask", "deny", "halt", "allow", "lexicon", "taint", "redact"]] = {"ask", "deny", "lexicon", "taint", "redact"}
    allowed_pack_ids: Union[List[str], Literal["*"]] = "*"
    not_before: str
    not_after: Optional[str] = None
    revoked: bool = False
    revoked_at: Optional[str] = None
    added_by: str
    added_at: str


class FeedSubscription(BaseModel):
    feed_id: str
    url: str
    pack_id: str
    channel: Literal["stable", "beta"] = "stable"
    interval_s: int = Field(default=3600, ge=300, le=86400)
    enabled: bool = True
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    last_checked_at: Optional[str] = None
    last_success_at: Optional[str] = None
    last_error: Optional[str] = None
    consecutive_failures: int = 0
    status: Literal["OK", "STALE", "ERROR", "DISABLED"] = "OK"
