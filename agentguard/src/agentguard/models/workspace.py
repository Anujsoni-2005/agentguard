"""
AgentGuard Workspace Data Models (§4.2)
"""
from __future__ import annotations

from typing import Literal, Optional, List, Dict
from pydantic import BaseModel

class WorkspaceState(BaseModel):
    run_id: str
    mode: Literal["copy", "empty"]
    host_path: Optional[str]
    scratch_dir: str                       # host absolute path; mounted at task.workspace_root
    baseline_dir: Optional[str]            # host absolute path; None if mode == "empty"
    created_at: str
    file_count: int
    total_bytes: int
    excluded: List[str]                    # relative paths excluded from copy (secrets etc.), capped 200
    skipped_symlinks: List[str]
    honeytoken_paths: List[str]            # relative paths inside workspace
    baseline_snapshot_id: str
    last_snapshot_id: str
    promoted_at: Optional[str] = None

class ManifestEntry(BaseModel):            # persisted compactly as list [k, sha256|"", size, mode, link_target|None]
    k: Literal["f", "d", "l"]
    s: str
    z: int
    m: int
    l: Optional[str] = None

# Manifest = Dict[str, ManifestEntry] # key = POSIX relative path (NFC-normalized, no leading "./")

class FileChange(BaseModel):
    path: str
    change: Literal["added", "modified", "deleted", "mode_changed", "symlink_added"]
    old_sha256: Optional[str] = None
    new_sha256: Optional[str] = None
    old_size: Optional[int] = None
    new_size: Optional[int] = None
    protected: bool
    sensitive: bool
    honeytoken: bool
    binary: bool

class ChangeSet(BaseModel):
    base_snapshot_id: str
    head_snapshot_id: str
    files: List[FileChange]
    totals: Dict[str, int]      # {"added":n,"modified":n,"deleted":n,...}

class FsFacts(BaseModel):
    rel_path: Optional[str]                    # normalized relative path inside scratch, None if lexically outside
    exists: bool
    kind: Literal["file", "dir", "symlink", "other", "missing"]
    symlink_escape: bool                    # any component (or final) is a symlink whose target leaves scratch
    size: Optional[int] = None
    mode: Optional[int] = None
    sha256: Optional[str] = None                      # only when size <= max_read_bytes
    old_text: Optional[str] = None                    # <= 512 KiB decoded text for diff (fs.write / fs.delete of text file)
    is_binary: Optional[bool] = None
    dir_file_count: Optional[int] = None              # for fs.delete recursive / fs.list: capped count (stop at 10_000)
    workspace_growth_bytes: int             # current total_bytes - baseline total_bytes
    vetted_script: bool                     # path in run.vetted_scripts and hash matches
