import asyncio
import time
from typing import List, Dict, Any, Optional
import httpx
from agentguard.eval.models import HumanScript

class HumanSimulator:
    def __init__(self, script: HumanScript, hub_url: str, admin_token: str):
        self.script = script
        self.hub_url = hub_url.rstrip("/")
        self.admin_token = admin_token
        self.headers = {
            "Authorization": f"Bearer {self.admin_token}",
            "X-AgentGuard-User": "eval-human"
        }
        self._running = False
        self._task = None
        self.decisions_made = []

    def start(self):
        self._running = True
        self._task = asyncio.create_task(self._poll_loop())
        
    async def stop(self):
        self._running = False
        if self._task:
            await self._task
            
    async def _poll_loop(self):
        async with httpx.AsyncClient() as client:
            while self._running:
                if not self.script.available:
                    await asyncio.sleep(0.1)
                    continue
                    
                try:
                    resp = await client.get(
                        f"{self.hub_url}/v1/inbox?status=open&limit=50", 
                        headers=self.headers
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        items = data.get("items", [])
                        for item in items:
                            await self._process_item(client, item)
                except Exception as e:
                    # Log or ignore connection errors during polling
                    pass
                    
                await asyncio.sleep(0.1)
                
    async def _process_item(self, client: httpx.AsyncClient, item: Dict[str, Any]):
        item_id = item["item_id"]
        item_type = item["type"]
        
        # Apply rules in order
        decision = None
        grant = None
        guidance = None
        delay_ms = 0
        
        for rule in self.script.rules:
            if self._matches(rule.match, item):
                decision = rule.decision
                grant = rule.grant
                guidance = rule.guidance
                delay_ms = rule.delay_ms
                break
                
        if not decision:
            decision = self.script.default
            
        if delay_ms > 0:
            await asyncio.sleep(delay_ms / 1000.0)
            
        payload = {"decision": decision}
        if grant:
            payload["grant"] = grant
        if guidance:
            payload["guidance"] = guidance
            
        endpoint = "approvals" if item_type == "approval" else "escalations"
        try:
            resp = await client.post(
                f"{self.hub_url}/v1/{endpoint}/{item_id}/decision",
                headers=self.headers,
                json=payload
            )
            if resp.status_code in (200, 204):
                self.decisions_made.append({
                    "item_id": item_id,
                    "decision": decision
                })
        except Exception:
            pass

    def _matches(self, match_criteria: Dict[str, Any], item: Dict[str, Any]) -> bool:
        for k, v in match_criteria.items():
            if k == "reason_code" or k == "reason_codes":
                if "reason_codes" in item and v not in item["reason_codes"]:
                    return False
            elif k == "action_type":
                # For approvals, action type might not be directly in the item at root,
                # but let's check if it is or if it's in a nested field if the spec provided it.
                if item.get("action_type") != v:
                    return False
            elif k == "step":
                # Matches against agent_meta.step_id ?
                if item.get("step_id") != v: # This depends on how the hub structures the inbox item
                    return False
            elif k == "kind":
                if item.get("kind") != v:
                    return False
            elif item.get(k) != v:
                return False
        return True
