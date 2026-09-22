"""
Probe executor — §9.5.3
"""

import asyncio
import re
import shlex
from typing import Literal, Tuple
import docker
from agentguard.models.run import Run
from agentguard.fs.path import FsPathValidator
from pydantic import BaseModel

class ProbeResult(BaseModel):
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    error: str | None = None

class ProbeExecutor:
    def __init__(self, workspace_dir: str):
        self.workspace_dir = workspace_dir
        self.path_validator = FsPathValidator()
        try:
            self.client = docker.from_env()
        except Exception:
            self.client = None

    def _validate_rev(self, rev: str) -> bool:
        return bool(re.match(r"^[0-9a-f]{7,40}$|^HEAD$", rev))

    async def execute(self, run: Run, template: Literal[
        "git_rev_parse", "git_count", "git_log", "git_status", "git_diff", "test_f", "test_d", "sha256sum"
    ], args: dict[str, str], timeout_ms: int = 3000) -> ProbeResult:
        
        cmd = []
        # Base git hardened command
        git_base = [
            "env", "-i", "PATH=/usr/bin:/bin", "HOME=/home/agent",
            "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
            "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0", "GIT_PAGER=cat",
            "git", "-C", "/workspace",
            "-c", "core.fsmonitor=", "-c", "core.hooksPath=/dev/null",
            "-c", "core.sshCommand=/bin/false", "-c", "core.pager=cat",
            "-c", "protocol.allow=never", "-c", "include.path=/dev/null",
            "--no-pager"
        ]

        if template == "git_rev_parse":
            cmd = git_base + ["rev-parse", "HEAD"]
        elif template == "git_count":
            rev = args.get("rev", "")
            if not self._validate_rev(rev):
                return ProbeResult(exit_code=-1, stdout="", stderr="Invalid rev", duration_ms=0.0, error="invalid_arg")
            cmd = git_base + ["rev-list", "--count", f"{rev}..HEAD"]
        elif template == "git_log":
            rev = args.get("rev", "")
            if not self._validate_rev(rev):
                return ProbeResult(exit_code=-1, stdout="", stderr="Invalid rev", duration_ms=0.0, error="invalid_arg")
            cmd = git_base + ["log", "--format=%s", f"{rev}..HEAD"]
        elif template == "git_status":
            cmd = git_base + ["status", "--porcelain"]
        elif template == "git_diff":
            cmd = git_base + ["diff", "--stat"]
        elif template in ("test_f", "test_d", "sha256sum"):
            path = args.get("path", "")
            if not self.path_validator.is_valid(path):
                return ProbeResult(exit_code=-1, stdout="", stderr="Invalid path", duration_ms=0.0, error="invalid_arg")
            safe_path = self.path_validator.normalize(path)
            # Ensure it resolves correctly
            if template == "test_f":
                cmd = ["test", "-f", safe_path]
            elif template == "test_d":
                cmd = ["test", "-d", safe_path]
            elif template == "sha256sum":
                cmd = ["sha256sum", safe_path]
        else:
            return ProbeResult(exit_code=-1, stdout="", stderr="Unknown template", duration_ms=0.0, error="unknown_template")

        if not self.client:
            # Fallback or mock for testing
            return ProbeResult(exit_code=-1, stdout="", stderr="Docker unavailable", duration_ms=0.0, error="no_docker")

        container_name = f"agentguard_sandbox_{run.run_id}"
        start_time = asyncio.get_event_loop().time()
        
        loop = asyncio.get_running_loop()
        
        def run_sync() -> Tuple[int, str]:
            try:
                container = self.client.containers.get(container_name)
                exec_instance = container.client.api.exec_create(
                    container.id, cmd, workdir="/workspace", user="10001", tty=False,
                    environment={"PATH": "/usr/bin:/bin", "HOME": "/home/agent"}
                )
                output = container.client.api.exec_start(exec_instance['Id'])
                inspect = container.client.api.exec_inspect(exec_instance['Id'])
                exit_code = inspect.get("ExitCode", -1)
                
                # cap output to 16 KiB
                stdout = output.decode("utf-8", errors="replace")
                if len(stdout) > 16384:
                    stdout = stdout[:16384]
                return exit_code, stdout
            except Exception as e:
                return -1, str(e)
                
        try:
            exit_code, stdout = await asyncio.wait_for(loop.run_in_executor(None, run_sync), timeout=timeout_ms / 1000.0)
            duration = (asyncio.get_event_loop().time() - start_time) * 1000
            
            if exit_code == -1 and "docker.errors" in stdout:
                 return ProbeResult(exit_code=-1, stdout="", stderr=stdout, duration_ms=duration, error="docker_error")
                 
            return ProbeResult(
                exit_code=exit_code,
                stdout=stdout,
                stderr="",
                duration_ms=duration
            )
            
        except asyncio.TimeoutError:
            duration = (asyncio.get_event_loop().time() - start_time) * 1000
            return ProbeResult(exit_code=-1, stdout="", stderr="Timeout", duration_ms=duration, error="timeout")
