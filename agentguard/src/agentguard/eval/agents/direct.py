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
    def __init__(self, workspace_dir: str, run_id: str = None):
        import uuid
        self.run_id = run_id if run_id else f"test-{uuid.uuid4().hex[:8]}"
        self.workspace_dir = workspace_dir
        self.docker_executor = DockerExecutor(workspace_dir=workspace_dir)

        self.run = MockRun(self.run_id)
        
    async def execute(self, step: StepSpec, action_id: str) -> Dict[str, Any]:
        action_type = step.action_type
        params = step.params
        
        record = MockActionRecord(action_id, action_type, params)
        
        execution = None
        if action_type.startswith("cli."):
            res = await self.docker_executor.execute(self.run, record, grant=None)
            print(f"DEBUG {action_id} stdout: {res.stdout}")
            print(f"DEBUG {action_id} stderr: {res.stderr}")
            execution = {
                "status": "SUCCEEDED" if res.status == "SUCCEEDED" else "FAILED",
                "stdout": res.stdout,
                "stderr": res.stderr,
                "exit_code": res.meta.get("exit_code"),
                "error": res.meta.get("error")
            }
        elif action_type.startswith("fs."):
            import base64
            # Inline FS operations for unguarded execution
            res_status = "SUCCEEDED"
            res_stdout = ""
            res_stderr = ""
            try:
                path = os.path.join(self.workspace_dir, params.get("path", "").lstrip("/"))
                if action_type == "fs.read":
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        res_stdout = f.read()
                elif action_type == "fs.write":
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    content = params.get("content", "")
                    if not content and "content_b64" in params:
                        content = base64.b64decode(params["content_b64"]).decode("utf-8")
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(content)
                elif action_type == "fs.delete":
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
                elif action_type == "fs.list":
                    res_stdout = "\n".join(os.listdir(path))
                else:
                    res_status = "FAILED"
                    res_stderr = f"Unsupported direct executor action {action_type}"
            except Exception as e:
                res_status = "FAILED"
                res_stderr = str(e)
            
            execution = {
                "status": res_status,
                "stdout": res_stdout,
                "stderr": res_stderr,
                "error": res_stderr if res_status == "FAILED" else None
            }
        elif action_type.startswith("net."):
            import httpx
            status = "SUCCEEDED"
            meta = {}
            text_preview = ""
            error = None
            try:
                method = params.get("method", "GET").upper()
                url = params.get("url", "")
                headers = params.get("headers", {})
                body = params.get("body", "")
                
                async with httpx.AsyncClient(timeout=10, verify=False) as client:
                    resp = await client.request(method, url, headers=headers, content=body.encode("utf-8") if body else None)
                    text_preview = resp.text[:1000]
                    meta["status_code"] = resp.status_code
            except Exception as e:
                status = "FAILED"
                error = str(e)
                meta["error"] = error
            
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
