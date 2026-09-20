from dataclasses import dataclass
from typing import Literal, Optional, List, Dict, Tuple, FrozenSet, Set
from pydantic import BaseModel, Field

@dataclass(frozen=True)
class RWord:
    text: str
    static: bool
    has_glob: bool
    kinds: FrozenSet[str]
    span: Tuple[int, int]

@dataclass
class Redirect:
    op: str
    target: Optional[RWord]
    heredoc_body: Optional[str]

@dataclass
class CmdCtx:
    pipeline_id: Optional[int]
    pipeline_pos: Optional[int]
    pipeline_len: Optional[int]
    in_subshell: bool
    in_cmdsub: bool
    in_procsub: bool
    negated: bool
    background: bool
    conditional: Literal["none", "and", "or", "seq"]
    depth: int
    origin: Literal["top", "bash_c", "eval", "heredoc", "cmdsub", "func_body"]

@dataclass
class SimpleCmd:
    name: RWord
    name_raw: RWord
    basename: str
    argv: List[RWord]
    env_assign: Dict[str, RWord]
    redirects: List[Redirect]
    wrappers: List[str]
    ctx: CmdCtx
    span: Tuple[int, int]

@dataclass
class CommandIR:
    commands: List[SimpleCmd]
    functions: Dict[str, List[SimpleCmd]]
    parse_ok: bool
    error_spans: List[Tuple[int, int]]
    max_depth: int
    node_count: int
    assigned_vars: Dict[str, RWord]

class CliPolicy(BaseModel):
    mode: Literal["allowlist", "denylist"] = Field(default="allowlist", json_schema_extra={"merge": "or_allowlist"})
    allowed_commands: Set[str] = Field(default={
        "ls","cat","grep","rg","head","tail","wc","pwd","echo","printf","rev","tr","sed","awk",
        "git","python","python3","pytest","pip","node","npm","make","tar","gzip","gunzip","zip","unzip","jq","curl","sha256sum","md5sum","stat","file","xargs","sleep"
    }, json_schema_extra={"merge": "intersect", "ui": {"control": "tag-list"}})
    denied_commands: Set[str] = Field(default_factory=set, json_schema_extra={"merge": "union"})
    max_command_len: int = Field(default=8192, json_schema_extra={"merge": "min"})
    max_nesting_depth: int = Field(default=3, json_schema_extra={"merge": "min"})
    workspace_root: str = Field(default="/workspace", json_schema_extra={"merge": "base_only"})
    sandbox_home: str = Field(default="/home/agent", json_schema_extra={"merge": "base_only"})
    scratch_paths: List[str] = Field(default=["/tmp"], json_schema_extra={"merge": "intersect"})
    sensitive_path_globs: List[str] = Field(default=[
        "**/.ssh/**", "**/.aws/**", "**/.config/gcloud/**", "**/.git-credentials", "**/.netrc",
        "**/id_rsa*", "**/id_ed25519*", "**/*.pem", "**/*.key", "**/*.p12", "**/.env", "**/.env.*",
        "/etc/shadow", "/etc/sudoers*", "/proc/*/environ"
    ], json_schema_extra={"merge": "union"})
    ask_on_workspace_secret_files: bool = Field(default=True, json_schema_extra={"merge": "or"})
    allowed_pkg_indexes: List[str] = Field(default=["https://pypi.org/simple", "https://files.pythonhosted.org", "https://registry.npmjs.org"], json_schema_extra={"merge": "intersect"})
    env_allowlist_patterns: List[str] = Field(default=["^LANG$", "^LC_[A-Z]+$", "^TZ$", "^PYTHONUNBUFFERED$", "^CI$", "^NODE_ENV$", "^[A-Z][A-Z0-9_]{0,40}$"], json_schema_extra={"merge": "intersect"})
    env_forbidden: Set[str] = Field(default={
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "BASH_ENV", "ENV", "PROMPT_COMMAND", "IFS", "PATH",
        "SHELLOPTS", "BASHOPTS", "PYTHONPATH", "PYTHONSTARTUP", "NODE_OPTIONS", "HOME", "GIT_SSH_COMMAND",
        "GIT_ASKPASS", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy",
        "all_proxy", "no_proxy"
    }, json_schema_extra={"merge": "union"})
    inline_code_ask: bool = Field(default=True, json_schema_extra={"merge": "or"})
    background_ask: bool = Field(default=True, json_schema_extra={"merge": "or"})
