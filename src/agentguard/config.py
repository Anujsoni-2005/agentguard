"""
AgentGuard Configuration — §0.8

All settings are loaded from environment variables with the AG_ prefix.
Tokens are **required** and the hub MUST refuse to start if missing.
"""

from __future__ import annotations

import os
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Hub configuration loaded from AG_* environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="AG_",
        env_file=".env",
        extra="ignore",
    )

    # ── Storage ──────────────────────────────────────────────────────────
    data_dir: str = "./data"
    db_path: str = ""          # computed in validator
    ledger_path: str = ""      # computed in validator
    workspaces_dir: str = "./workspaces"

    # ── Authentication (required, no defaults — startup fails) ─────────
    agent_token: str = Field(..., min_length=1)
    admin_token: str = Field(..., min_length=1)
    internal_token: str = Field(..., min_length=1)
    server_secret: str = Field(..., min_length=32)

    # ── Analyzer / pipeline ──────────────────────────────────────────────
    analyzer_timeout_ms: int = 50
    cli_analyzer_timeout_ms: int = 100
    min_confidence: float = 0.5
    max_param_bytes: int = 1_048_576

    # ── Ledger ───────────────────────────────────────────────────────────
    ledger_fsync: Literal["always", "batch"] = "always"
    ledger_signing_key: str = ""   # computed from data_dir if empty
    ledger_segment_bytes: int = 268_435_456
    ledger_group_commit_ms: int = 2
    checkpoint_every_n: int = 100
    checkpoint_every_s: int = 60

    # ── Approvals ────────────────────────────────────────────────────────
    approval_ttl_s: int = 900
    max_unanswered_approvals: int = 2
    human_available_default: bool = True

    # ── Sandbox / proxy ──────────────────────────────────────────────────
    sandbox_image: str = "agentguard/sandbox:latest"
    sandbox_lazy: bool = False
    proxy_host: str = "proxy"
    proxy_port: int = 8899

    # ── Server ───────────────────────────────────────────────────────────
    cors_origins: str = "http://localhost:3000"
    log_level: str = "INFO"
    max_concurrent_runs: int = 10
    scan_workers: int = 4
    span_retention_days: int = 14
    env: str = "dev"           # "dev" | "prod"
    eval_mode: bool = False
    dev_mode: bool = False

    # ── Policy ───────────────────────────────────────────────────────────
    policy_dir: str = "./policies"
    policy_watch: bool = False

    # ── Optional integrations ────────────────────────────────────────────
    otlp_endpoint: str | None = None
    judge_provider: str = "none"
    judge_model: str | None = None
    judge_api_key: str | None = None
    judge_base_url: str | None = None

    @field_validator("db_path", mode="before")
    @classmethod
    def _default_db_path(cls, v: str, info: object) -> str:  # type: ignore[override]
        if v:
            return v
        data_dir = os.environ.get("AG_DATA_DIR", "./data")
        return os.path.join(data_dir, "agentguard.db")

    @field_validator("ledger_path", mode="before")
    @classmethod
    def _default_ledger_path(cls, v: str, info: object) -> str:  # type: ignore[override]
        if v:
            return v
        data_dir = os.environ.get("AG_DATA_DIR", "./data")
        return os.path.join(data_dir, "ledger")

    @field_validator("ledger_signing_key", mode="before")
    @classmethod
    def _default_signing_key(cls, v: str, info: object) -> str:  # type: ignore[override]
        if v:
            return v
        data_dir = os.environ.get("AG_DATA_DIR", "./data")
        return os.path.join(data_dir, "ledger_signing.key")
