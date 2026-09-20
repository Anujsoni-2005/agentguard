"""
AgentGuard Network Data Models (§3.3)
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal, Optional, List, Dict

from pydantic import BaseModel, Field
from agentguard.models.common import Finding


class NetPolicy(BaseModel):
    """Network egress policy defined in §3.3"""
    allow_domains: List[str] = Field(default=["pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "github.com", "api.github.com",
                                "raw.githubusercontent.com", "docs.python.org", "developer.mozilla.org", "en.wikipedia.org"], json_schema_extra={"merge": "intersect_domains", "ui": {"control": "tag-list"}})
    write_allow_domains: List[str] = Field(default_factory=list, json_schema_extra={"merge": "intersect_domains", "ui": {"control": "tag-list"}})
    deny_domains: List[str] = Field(default=["*.onion", "*.ngrok.io", "*.ngrok-free.app", "webhook.site", "requestbin.com", "pipedream.net",
                               "transfer.sh", "file.io", "0x0.st", "pastebin.com", "paste.ee", "*.trycloudflare.com",
                               "dns.google", "cloudflare-dns.com", "*.cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com"], json_schema_extra={"merge": "union", "ui": {"control": "tag-list"}})
    allowed_schemes: List[Literal["http", "https"]] = Field(default=["https", "http"], json_schema_extra={"merge": "intersect"})
    allowed_ports: List[int] = Field(default=[80, 443], json_schema_extra={"merge": "intersect"})
    read_methods: List[str] = Field(default=["GET", "HEAD", "OPTIONS"], json_schema_extra={"merge": "intersect"})
    block_ip_literals: bool = Field(default=True, json_schema_extra={"merge": "or"})
    allow_ip_cidrs: List[str] = Field(default_factory=list, json_schema_extra={"merge": "intersect_cidrs"})
    max_redirects: int = Field(default=5, json_schema_extra={"merge": "min"})
    max_request_body_bytes: int = Field(default=1_048_576, json_schema_extra={"merge": "min"})
    max_response_bytes: int = Field(default=5_242_880, json_schema_extra={"merge": "min"})
    rate_limit_run_per_min: int = Field(default=60, json_schema_extra={"merge": "min", "ui": {"control": "slider", "min": 1, "max": 600}})
    rate_limit_run_burst: int = Field(default=15, json_schema_extra={"merge": "min"})
    rate_limit_domain_per_min: int = Field(default=20, json_schema_extra={"merge": "min", "ui": {"control": "slider", "min": 1, "max": 120}})
    rate_limit_domain_burst: int = Field(default=8, json_schema_extra={"merge": "min"})
    scan_request_bodies: bool = Field(default=True, json_schema_extra={"merge": "or"})
    canary_secrets_enabled: bool = Field(default=True, json_schema_extra={"merge": "or"})
    pii_rules_enabled: List[str] = Field(default=["ssn", "credit_card", "aadhaar", "pan_in", "jwt", "aws_access_key", "aws_secret_key", "private_key", "github_token", "slack_token", "generic_api_key", "email_bulk"], json_schema_extra={"merge": "union"})
    pii_verdicts: Dict[str, Literal["ASK_HUMAN", "DENY"]] = Field(default={
        "ssn": "ASK_HUMAN", "credit_card": "ASK_HUMAN", "aadhaar": "ASK_HUMAN", "pan_in": "ASK_HUMAN",
        "jwt": "DENY", "aws_access_key": "DENY", "aws_secret_key": "DENY", "private_key": "DENY",
        "github_token": "DENY", "slack_token": "DENY", "generic_api_key": "DENY", "email_bulk": "ASK_HUMAN"
    }, json_schema_extra={"merge": "stricter_verdict"})
    entropy_threshold_bits: float = Field(default=4.5, json_schema_extra={"merge": "min"})
    entropy_min_len: int = Field(default=32, json_schema_extra={"merge": "min"})
    injection_detection: bool = Field(default=True, json_schema_extra={"merge": "or"})
    upgrade_websocket: bool = Field(default=False, json_schema_extra={"merge": "and"})
    policy_max_stale_s: int = Field(default=3600, json_schema_extra={"merge": "min"})


@dataclass(frozen=True)
class NormalizedUrl:
    """Normalized URL components §3.3"""
    original: str
    scheme: str
    host: str
    port: int
    path: str
    query: str
    is_ip: bool
    ip: Optional[ipaddress._BaseAddress]
    canonical: str


class EgressEvent(BaseModel):
    """JSONL / ingestion contract §3.3"""
    event_id: str
    ts: str
    run_id: Optional[str]
    source: Literal["proxy", "hub_executor"]
    method: str
    url: str
    host: str
    port: int
    scheme: str
    decision: Literal["ALLOW", "ASK_HUMAN", "DENY"]
    reason_codes: List[str]
    rule_ids: List[str]
    request_bytes: int
    response_bytes: Optional[int]
    status_code: Optional[int]
    duration_ms: Optional[float]
    sni: Optional[str]
    resolved_ip: Optional[str]
    redirect_hop: int = 0
    tainted: bool = False
    taint_reasons: List[str] = []
    findings: List[Finding] = []
    action_id: Optional[str] = None
    policy_hash: str
