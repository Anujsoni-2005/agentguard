import httpx
import uuid
from typing import Any, Dict, Optional

class RunAborted(Exception):
    pass

class GuardUnavailable(Exception):
    pass

class AgentGuardClient:
    """§1.6 Agent SDK contract"""
    def __init__(self, base_url: str, token: str, *, timeout_s: float = 65.0):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.timeout_s = timeout_s
        self._client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"},
            timeout=timeout_s
        )

    async def create_run(self, task: Dict[str, Any], budgets: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        resp = await self._client.post(f"{self.base_url}/v1/runs", json={"task": task, "budgets": budgets or {}})
        resp.raise_for_status()
        return resp.json()

    async def propose(
        self, run_id: str, action_type: str, params: dict, *,
        rationale: str = "", confidence: Optional[float] = None, 
        evidence_refs: Optional[list] = None, plan_step_id: Optional[str] = None
    ) -> Dict[str, Any]:
        import asyncio
        client_action_id = uuid.uuid4().hex
        payload = {
            "client_action_id": client_action_id,
            "action_type": action_type,
            "params": params,
            "rationale": rationale,
            "confidence": confidence,
            "evidence_refs": evidence_refs or [],
            "plan_step_id": plan_step_id
        }
        
        # Retry logic up to 3 times
        for attempt in range(4):
            try:
                resp = await self._client.post(f"{self.base_url}/v1/runs/{run_id}/actions", json=payload)
                if resp.status_code == 202:
                    return await self._wait_human(run_id, resp.json()["action_id"])
                resp.raise_for_status()
                return resp.json()
            except httpx.RequestError:
                if attempt == 3:
                    raise GuardUnavailable("AgentGuard hub unreachable")
                await asyncio.sleep(0.5 * (2 ** attempt))

    async def _wait_human(self, run_id: str, action_id: str) -> Dict[str, Any]:
        # polling logic
        while True:
            resp = await self._client.get(f"{self.base_url}/v1/runs/{run_id}/actions/{action_id}?wait_s=25")
            data = resp.json()
            if data["status"] not in ("PENDING_APPROVAL", "APPROVED", "EXECUTING"):
                return data

    async def thought(self, run_id: str, kind: str, text: str, **meta: Any) -> None:
        pass

    async def complete(self, run_id: str, outcome: str, summary: str, final_answer: str = "") -> None:
        pass

    async def close(self):
        await self._client.aclose()
