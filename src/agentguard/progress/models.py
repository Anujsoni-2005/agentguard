"""
Progress data models — §9.3
"""

from __future__ import annotations
from typing import Literal, Any, Union, List, Annotated
from enum import StrEnum
from pydantic import BaseModel, ConfigDict, Field
from agentguard.registry import ActionType

class VerifierBase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    watch: list[Literal["fs","cli","net","gui","any"]] = ["any"]
    regression_check: bool = True

class FileExists(VerifierBase):
    type: Literal["file_exists"]
    path: str

class FileContains(VerifierBase):
    type: Literal["file_contains"]
    path: str
    pattern: str = Field(max_length=256)
    min_matches: int = 1

class FileChanged(VerifierBase):
    type: Literal["file_changed"]
    path: str

class CliSucceeded(VerifierBase):
    type: Literal["cli_succeeded"]
    argv_prefix: list[str]
    exit_code: int = 0
    output_regex: str | None = None
    after_last_write: bool = False

class ActionMatched(VerifierBase):
    type: Literal["action_matched"]
    action_type: ActionType
    params_match: dict[str, Any] = {}

class OutputRegex(VerifierBase):
    type: Literal["output_regex"]
    stream: Literal["stdout","stderr"] = "stdout"
    pattern: str
    scope: Literal["any","last_cli"] = "any"

class GitCommit(VerifierBase):
    type: Literal["git_commit"]
    message_regex: str | None = None
    min_new_commits: int = 1

class Manual(VerifierBase):
    type: Literal["manual"]

class AllOf(VerifierBase):
    type: Literal["all_of"]
    items: list[VerifierSpec] = Field(min_length=1, max_length=10)

class AnyOf(VerifierBase):
    type: Literal["any_of"]
    items: list[VerifierSpec] = Field(min_length=1, max_length=10)

VerifierSpec = Annotated[
    Union[
        FileExists, FileContains, FileChanged, CliSucceeded,
        ActionMatched, OutputRegex, GitCommit, Manual,
        AllOf, AnyOf
    ],
    Field(discriminator="type")
]

class MilestoneState(StrEnum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    DONE_CLAIMED = "DONE_CLAIMED"
    DONE_VERIFIED = "DONE_VERIFIED"
    REGRESSED = "REGRESSED"
    OVERRUN = "OVERRUN"
    SKIPPED = "SKIPPED"

class MilestoneStatus(BaseModel):
    milestone_id: str
    state: MilestoneState
    steps_used: int = 0
    started_at: str | None = None
    verified_at: str | None = None
    claimed_at: str | None = None
    updated_at: str
    evidence: dict[str, Any] = {}
    dependency_blocked: bool = False

class ProgressEvent(BaseModel):
    kind: Literal["action_decided", "action_executed", "thought", "claim", "ws_changed", "tick"]
    run_id: str
    ts: str
    action_id: str | None = None
    payload: dict[str, Any] = {}
