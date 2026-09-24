import os
import shutil
import asyncio
from typing import Dict, Any

from agentguard.eval.models import StepSpec
from agentguard.executors.docker import DockerExecutor
from agentguard.fs.executor import FsExecutor
from agentguard.net.executor import execute_http
# For GUI, we can mock or skip since direct executor doesn't usually use gui but let's include if needed
# from agentguard.gui.executor import BrowserExecutor

class MockRun:
    def __init__(self, run_id: str):
        self.run_id = run_id

class MockActionRecord:
    def __init__(self, action_id: str, action_type: str, params: dict):
        self.action_id = action_id
        self.action_type = action_type
        self.params = params

class DirectExecutor:
    def __init__(self, workspace_dir: str, run_id: str = "test"):
        self.run_id = run_id
        self.workspace_dir = workspace_dir
        self.docker_executor = DockerExecutor(workspace_dir=os.path.dirname(workspace_dir), run_id=getattr(self, "run_id", "test"))
        self.fs_executor = FsExecutor(workspace_dir=workspace_dir, config=None)
        self.run = MockRun("eval-run")
        
    async def execute(self, step: StepSpec, action_id: str) -> Dict[str, Any]:
        action_type = step.action_type
        params = step.params
        
        record = MockActionRecord(action_id, action_type, params)
        
        execution = None
        if action_type.startswith("cli."):
            res = await self.docker_executor.execute(self.run, record, grant=None)
            execution = {
                "status": "SUCCEEDED" if res.status == "SUCCEEDED" else "FAILED",
                "stdout": res.stdout,
                "stderr": res.stderr,
                "exit_code": res.meta.get("exit_code"),
                "error": res.meta.get("error")
            }
        elif action_type.startswith("fs."):
            res = await self.fs_executor.execute(self.run, record, grant=None)
            execution = {
                "status": "SUCCEEDED" if res.status == "SUCCEEDED" else "FAILED",
                "stdout": res.stdout,
                "stderr": res.stderr,
                "error": res.meta.get("error")
            }
        elif action_type.startswith("net."):
            status, meta, is_text, findings, text_preview, taint_flag = await execute_http(self.run, record)
            execution = {
                "status": status,
                "stdout": text_preview,
                "stderr": "",
                "status_code": meta.get("status_code"),
                "error": meta.get("error")
            }
        else:
            execution = {"status": "FAILED", "error": f"Unsupported direct executor action {action_type}"}
            
        return execution
