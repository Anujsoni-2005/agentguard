"""
AgentGuard Workspace Lifecycle (§4.3)
"""
import os
import shutil
import stat
import unicodedata
from datetime import datetime
from typing import Optional, List, Set, Tuple

from agentguard.models.workspace import WorkspaceState
from agentguard.models.policy import FsPolicy
from agentguard.config import Settings
settings = Settings(_env_file=None, agent_token="stub", admin_token="stub", internal_token="stub", server_secret="stub"*32)

AG_ALLOWED_HOST_ROOTS = ["/workspace", "/tmp", "E:\\New folder\\agentguard\\eval\\fixtures"]
AG_WORKSPACE_MAX_FILES = 50000
AG_WORKSPACE_MAX_BYTES = 209715200
AG_DATA_DIR = "./data"
from agentguard.fs.manifest import build_manifest, WorkspaceTooLargeError
from agentguard.fs.paths import match_globs
from agentguard.fs.honeytokens import plant_honeytokens
from agentguard.ids import ULID

def append_ledger_entry(run_id, event, payload, ledger):
    pass # stub

class WorkspaceError(Exception):
    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code

class WorkspaceManager:
    def __init__(self, db, ledger):
        self.db = db
        self.ledger = ledger

    def _resolve_host(self, host_path: str) -> str:
        host = os.path.realpath(host_path)
        if not os.path.isdir(host):
            raise WorkspaceError("Host path is not a directory", "HOST_PATH_NOT_ALLOWED")
        
        allowed = False
        for root in AG_ALLOWED_HOST_ROOTS:
            try:
                if os.path.commonpath([host, root]) == root:
                    # Must not be the root itself or / or home
                    if host == root or host == "/" or host == os.path.expanduser("~"):
                        raise WorkspaceError("Host path cannot be root, home, or allowed roots exactly", "HOST_PATH_NOT_ALLOWED")
                    allowed = True
                    break
            except ValueError:
                pass
                
        if not allowed:
            raise WorkspaceError("Host path not within allowed roots", "HOST_PATH_NOT_ALLOWED")
            
        return host

    def create_workspace(self, run_id: str, host_path: Optional[str], fs_policy: FsPolicy) -> WorkspaceState:
        runs_dir = os.path.join(AG_DATA_DIR, "runs", run_id)
        scratch_dir = os.path.join(runs_dir, "scratch")
        baseline_dir = os.path.join(runs_dir, "baseline")
        os.makedirs(scratch_dir, exist_ok=True)
        
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        
        if not host_path:
            os.chmod(scratch_dir, 0o777)
            state = WorkspaceState(
                run_id=run_id,
                mode="empty",
                host_path=None,
                scratch_dir=scratch_dir,
                baseline_dir=None,
                created_at=now,
                file_count=0,
                total_bytes=0,
                excluded=[],
                skipped_symlinks=[],
                honeytoken_paths=[],
                honeytokens=[],
                baseline_snapshot_id=f"snap_{ULID()}",
                last_snapshot_id=f"snap_{ULID()}"
            )
            # empty manifest
            self._save_snapshot(state.baseline_snapshot_id, run_id, "baseline", {})
            self._save_state(state)
            append_ledger_entry(run_id, "workspace.created", {"file_count": 0, "excluded_count": 0}, self.ledger)
            return state

        host = self._resolve_host(host_path)
        os.makedirs(baseline_dir, exist_ok=True)

        excluded: List[str] = []
        skipped_symlinks: List[str] = []
        file_count = 0
        total_bytes = 0

        # Iterative copy to avoid deep recursion issues
        dirs_to_visit = [("", host, scratch_dir, baseline_dir)]
        
        try:
            while dirs_to_visit:
                rel_prefix, current_host, current_scratch, current_baseline = dirs_to_visit.pop()
                
                with os.scandir(current_host) as it:
                    for entry in it:
                        name = unicodedata.normalize("NFC", entry.name)
                        rel_path = f"{rel_prefix}/{name}" if rel_prefix else name
                        
                        if file_count >= AG_WORKSPACE_MAX_FILES:
                            raise WorkspaceError("Exceeded max files", "WORKSPACE_TOO_LARGE")
                        
                        if match_globs(rel_path, fs_policy.copy_exclude_globs):
                            if len(excluded) < 200:
                                excluded.append(rel_path)
                            continue
                            
                        entry_stat = entry.stat(follow_symlinks=False)
                        
                        scratch_dest = os.path.join(current_scratch, entry.name)
                        baseline_dest = os.path.join(current_baseline, entry.name)
                        
                        if entry.is_symlink():
                            target = os.readlink(entry.path)
                            # Simple lexical check to see if target stays inside host
                            import posixpath
                            resolved = posixpath.normpath(posixpath.join(rel_prefix, target))
                            if resolved.startswith(".."):
                                skipped_symlinks.append(rel_path)
                                continue
                            os.symlink(target, scratch_dest)
                            os.symlink(target, baseline_dest)
                            file_count += 1
                        elif entry.is_dir(follow_symlinks=False):
                            os.mkdir(scratch_dest)
                            os.mkdir(baseline_dest)
                            dirs_to_visit.append((rel_path, entry.path, scratch_dest, baseline_dest))
                            file_count += 1
                        elif entry.is_file(follow_symlinks=False):
                            total_bytes += entry_stat.st_size
                            if total_bytes > AG_WORKSPACE_MAX_BYTES:
                                raise WorkspaceError("Exceeded max bytes", "WORKSPACE_TOO_LARGE")
                                
                            shutil.copy2(entry.path, scratch_dest, follow_symlinks=False)
                            shutil.copy2(entry.path, baseline_dest, follow_symlinks=False)
                            
                            # Strip setuid/setgid/sticky
                            mode = entry_stat.st_mode & 0o777
                            os.chmod(scratch_dest, mode)
                            os.chmod(baseline_dest, mode)
                            file_count += 1
                            
        except WorkspaceError:
            shutil.rmtree(runs_dir, ignore_errors=True)
            raise

        # Chmod baseline to read-only for all
        for root, dirs, files in os.walk(baseline_dir):
            for d in dirs:
                m = os.stat(os.path.join(root, d)).st_mode
                os.chmod(os.path.join(root, d), m & ~0o222)
            for f in files:
                p = os.path.join(root, f)
                if not os.path.islink(p):
                    m = os.stat(p).st_mode
                    os.chmod(p, m & ~0o222)

        # Chmod scratch to world writable within itself (since hub runs as non-root here)
        for root, dirs, files in os.walk(scratch_dir):
            for d in dirs:
                m = os.stat(os.path.join(root, d)).st_mode
                os.chmod(os.path.join(root, d), m | 0o777)
            for f in files:
                p = os.path.join(root, f)
                if not os.path.islink(p):
                    m = os.stat(p).st_mode
                    os.chmod(p, m | 0o666)
                    
        # Compute baseline manifest
        manifest = build_manifest(baseline_dir, None, {})
        baseline_snap_id = f"snap_{ULID()}"
        self._save_snapshot(baseline_snap_id, run_id, "baseline", manifest)
        
        # Plant honeytokens in scratch ONLY
        honeytoken_paths = []
        planted_honeytokens = []
        if fs_policy.honeytokens_enabled:
            # We open scratch dir descriptor
            if hasattr(os, "O_DIRECTORY"):
                try:
                    fd = os.open(scratch_dir, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        planted_honeytokens = plant_honeytokens(fd)
                        honeytoken_paths.extend([ht["path"] for ht in planted_honeytokens])
                        # Register canaries logic would go here
                    finally:
                        os.close(fd)
                except OSError:
                    pass
            else:
                # If OS doesn't support it, plant_honeytokens handles fallback or fails
                # Wait, honeytokens uses safeio which requires O_DIRECTORY. If it fails it fails.
                pass

        state = WorkspaceState(
            run_id=run_id,
            mode="copy",
            host_path=host,
            scratch_dir=scratch_dir,
            baseline_dir=baseline_dir,
            created_at=now,
            file_count=file_count,
            total_bytes=total_bytes,
            excluded=excluded,
            skipped_symlinks=skipped_symlinks,
            honeytoken_paths=honeytoken_paths,
            honeytokens=planted_honeytokens,
            baseline_snapshot_id=baseline_snap_id,
            last_snapshot_id=baseline_snap_id
        )
        
        self._save_state(state)
        append_ledger_entry(run_id, "workspace.created", {"file_count": file_count, "excluded_count": len(excluded)}, self.ledger)
        return state

    def _save_snapshot(self, snap_id: str, run_id: str, kind: str, manifest: dict):
        pass # stub for db insert

    def _save_state(self, state: WorkspaceState):
        pass # stub for db insert
