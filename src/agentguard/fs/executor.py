"""
AgentGuard Filesystem Executor (§4.7)
"""
import os
import hashlib
from typing import Optional, Dict, Any

from agentguard.models.common import ExecutionResult
from agentguard.models.workspace import FsFacts
from agentguard.fs.safeio import open_no_follow, safe_write_replace, safe_recursive_delete, SymlinkRefused
from agentguard.fs.paths import FsPathValidator
from agentguard.registry import ActionType

class FsExecutor:
    handles = {ActionType.FS_READ, ActionType.FS_LIST, ActionType.FS_WRITE, ActionType.FS_DELETE}

    @classmethod
    async def execute(cls, action_type: str, params: dict, policy: Any, scratch_dir: str, facts: Optional[FsFacts]) -> ExecutionResult:
        path = params.get("path", "")
        rel_path, findings = FsPathValidator.normalize(path, policy.workspace_root, policy, is_read=(action_type in (ActionType.FS_READ, ActionType.FS_LIST)))
        
        if findings or rel_path is None:
            return ExecutionResult(status="FAILED", meta={"error": "FS_PATH_INVALID"})

        root_fd = -1
        try:
            root_fd = os.open(scratch_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0x00010000))
        except OSError:
            return ExecutionResult(status="FAILED", meta={"error": "IO_ERROR"})

        try:
            if action_type == ActionType.FS_WRITE:
                return cls._execute_write(root_fd, rel_path, params, facts)
            elif action_type == ActionType.FS_READ:
                return cls._execute_read(root_fd, rel_path, params, facts, policy.max_read_bytes)
            elif action_type == ActionType.FS_DELETE:
                return cls._execute_delete(root_fd, rel_path, params, facts)
            elif action_type == ActionType.FS_LIST:
                return cls._execute_list(root_fd, rel_path, params, facts)
        except SymlinkRefused:
            return ExecutionResult(status="FAILED", meta={"error": "SYMLINK_REFUSED"})
        except OSError as e:
            return ExecutionResult(status="FAILED", meta={"error": "IO_ERROR", "details": str(e)})
        finally:
            if root_fd >= 0:
                os.close(root_fd)
                
        return ExecutionResult(status="FAILED", meta={"error": "UNKNOWN"})

    @classmethod
    def _execute_write(cls, root_fd: int, rel_path: str, params: dict, facts: Optional[FsFacts]) -> ExecutionResult:
        # Compare and swap (CAS)
        current_sha256 = None
        try:
            fd = open_no_follow(root_fd, rel_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0x00020000))
            try:
                # read chunk
                hasher = hashlib.sha256()
                while True:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    hasher.update(chunk)
                current_sha256 = hasher.hexdigest()
            finally:
                os.close(fd)
        except OSError:
            pass # File doesn't exist

        # Verification that we aren't writing over a file that changed since prefetch (unless we didn't prefetch a sha256 because it didn't exist)
        if facts and facts.sha256 and facts.sha256 != current_sha256:
            return ExecutionResult(status="FAILED", meta={"error": "CHANGED_SINCE_APPROVAL"})

        content = params.get("content", "").encode("utf-8")
        
        safe_write_replace(root_fd, rel_path, content, "exec_ulid_stub")
        
        # CAS Storage for protected paths would happen here
        
        return ExecutionResult(
            status="SUCCEEDED",
            stdout="",
            stderr="",
            meta={"path": rel_path, "bytes_written": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        )

    @classmethod
    def _execute_read(cls, root_fd: int, rel_path: str, params: dict, facts: Optional[FsFacts], max_read_bytes: int) -> ExecutionResult:
        try:
            fd = open_no_follow(root_fd, rel_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0x00020000))
        except OSError:
            return ExecutionResult(status="FAILED", meta={"error": "NOT_FOUND"})
            
        try:
            content = os.read(fd, max_read_bytes + 1)
            truncated = len(content) > max_read_bytes
            if truncated:
                content = content[:max_read_bytes]
                
            try:
                text = content.decode("utf-8")
                binary = False
            except UnicodeDecodeError:
                text = ""
                binary = True
                
            return ExecutionResult(
                status="SUCCEEDED",
                stdout=text,
                stderr="",
                meta={"path": rel_path, "size": len(content), "binary": binary, "truncated": truncated}
            )
        finally:
            os.close(fd)

    @classmethod
    def _execute_delete(cls, root_fd: int, rel_path: str, params: dict, facts: Optional[FsFacts]) -> ExecutionResult:
        recursive = params.get("recursive", False)
        if recursive:
            safe_recursive_delete(root_fd, rel_path)
        else:
            dirname, _, basename = rel_path.rpartition("/")
            parent_fd = open_no_follow(root_fd, dirname, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0x00010000)) if dirname else os.dup(root_fd)
            try:
                os.unlink(basename, dir_fd=parent_fd)
            except OSError as e:
                import errno
                if e.errno == errno.ENOENT:
                    return ExecutionResult(status="FAILED", meta={"error": "NOT_FOUND"})
                return ExecutionResult(status="FAILED", meta={"error": "IO_ERROR"})
            finally:
                os.close(parent_fd)
                
        return ExecutionResult(status="SUCCEEDED", stdout="", stderr="", meta={"path": rel_path})

    @classmethod
    def _execute_list(cls, root_fd: int, rel_path: str, params: dict, facts: Optional[FsFacts]) -> ExecutionResult:
        # Stub
        return ExecutionResult(status="SUCCEEDED", stdout="", stderr="", meta={"path": rel_path})
