import asyncio
import os
import docker
from typing import Optional
from agentguard.protocols import Executor, ExecutionResult
from agentguard.models.run import Run
from agentguard.models.action import ActionRecord

class DockerExecutor(Executor):
    def __init__(self, workspace_dir: str):
        self.workspace_dir = workspace_dir
        # Only init client if Docker is available
        try:
            self.client = docker.from_env()
        except Exception:
            self.client = None

    @property
    def id(self) -> str:
        return "docker"

    @property
    def handles(self) -> set[str]:
        return {"cli.exec"}

    async def execute(self, run: Run, action: ActionRecord, grant: Optional[any] = None) -> ExecutionResult:
        if not self.client:
            return ExecutionResult(status="FAILED", exit_code=-1, stdout="", stderr="Docker unavailable", truncated=False, duration_ms=0.0, output_tainted=False, taint_reasons=[], meta={})
            
        if isinstance(action.params, dict):
            command = action.params.get("command", "")
            timeout_s = action.params.get("timeout_s", 60.0)
        else:
            command = getattr(action.params, "command", "")
            timeout_s = getattr(action.params, "timeout_s", 60.0)
            
        container_name = f"agentguard_sandbox_{run.run_id}"
        
        try:
            # Check if container exists, else create it
            try:
                print(f"DEBUG CONTAINER NAME: {container_name}")
                container = self.client.containers.get(container_name)
                if container.status != "running":
                    container.start()
            except docker.errors.NotFound:
                import os
                def _to_docker_mount_path(path: str) -> str:
                    abs_path = os.path.abspath(path)
                    res = abs_path.replace("\\", "/")
                    print(f"DEBUG MOUNT: {res}")
                    return res

                # 2.9.2 Container Hardening
                container = self.client.containers.run(
                    "python:3.11",
                    name=container_name,
                    command="sleep infinity", # keep alive
                    detach=True,
                    network="agentguard_internal", # Ensure this network exists in compose
                    # Security options from 2.9.2
                    user="10001",
                    cap_drop=["ALL"],
                    security_opt=["no-new-privileges:true"],
                    read_only=True,
                    tmpfs={"/tmp": "size=256m,exec,mode=1777", "/home/agent": "size=64m,exec,mode=0700"},
                    volumes={_to_docker_mount_path(self.workspace_dir): {"bind": "/workspace", "mode": "rw"}},
                    working_dir="/workspace",
                    pids_limit=128,
                    mem_limit="512m",
                    dns=["127.0.0.1"]
                )

            # Build argv according to 2.9.3 Execution
            import shlex
            cmd = ["/bin/sh", "-c", f"setsid bash --noprofile --norc -o pipefail -c {shlex.quote(command)}"]

            start_time = asyncio.get_event_loop().time()
            
            # Execute
            # In a real async implementation we'd use aio-docker or run_in_executor
            # Using synchronous docker-py in a thread for prototype
            loop = asyncio.get_running_loop()
            
            def run_sync():
                exec_instance = container.client.api.exec_create(
                    container.id, cmd, workdir="/workspace", user="10001", tty=False
                )
                
                output = container.client.api.exec_start(exec_instance['Id'])
                inspect = container.client.api.exec_inspect(exec_instance['Id'])
                return output, inspect
            
            # Simplified timeout handling
            try:
                output_bytes, inspect = await asyncio.wait_for(loop.run_in_executor(None, run_sync), timeout=timeout_s)
                exit_code = inspect.get("ExitCode", -1)
                status = "SUCCEEDED" if exit_code == 0 else "FAILED"
                stdout = output_bytes.decode("utf-8", errors="replace")
                
                # Cap output
                truncated = False
                if len(stdout) > 65536:
                    stdout = stdout[:65536] + "\n[...truncated bytes by AgentGuard]"
                    truncated = True
                    
                duration = (asyncio.get_event_loop().time() - start_time) * 1000
                
                return ExecutionResult(
                    status=status,
                    exit_code=exit_code,
                    stdout=stdout,
                    stderr="",
                    truncated=truncated,
                    duration_ms=duration,
                    output_tainted=False,
                    taint_reasons=[],
                    meta={"exec_id": inspect.get("Id", "")}
                )
                
            except asyncio.TimeoutError:
                duration = (asyncio.get_event_loop().time() - start_time) * 1000
                # Kill process group as per 2.9.3
                pid = inspect.get("Pid", 0)
                if pid > 0:
                    def kill_pg():
                        container.client.api.exec_create(
                            container.id, 
                            ["/bin/sh", "-c", f"kill -KILL -- -$(awk '{{print $5}}' /proc/{pid}/stat)"], 
                            user="0"
                        )
                    await loop.run_in_executor(None, kill_pg)
                
                return ExecutionResult(
                    status="TIMED_OUT", exit_code=124, stdout="", stderr="Timed out",
                    truncated=False, duration_ms=duration, output_tainted=False, taint_reasons=[], meta={}
                )
                
        except Exception as e:
            return ExecutionResult(status="FAILED", exit_code=-1, stdout="", stderr=str(e), truncated=False, duration_ms=0.0, output_tainted=False, taint_reasons=[], meta={})
