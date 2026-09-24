import time
import asyncio
from typing import Dict, Any, Callable
from agentguard.eval.models import ScenarioSpec

class ScriptedAgent:
    def __init__(self, spec: ScenarioSpec, executor_func: Callable, complete_func: Callable):
        self.spec = spec
        self.steps = {s.id: s for s in spec.steps}
        self.executor_func = executor_func
        self.complete_func = complete_func
        
    async def run(self):
        cur = self.spec.start
        proposals = 0
        start_time = time.time()
        
        while cur:
            if proposals >= 200:
                await self.complete_func(outcome="abandoned", reason="Hard cap of 200 proposals reached")
                break
            if time.time() - start_time > 120:
                await self.complete_func(outcome="abandoned", reason="120s wall time limit reached")
                break
                
            step = self.steps.get(cur)
            if not step:
                break
                
            for i in range(step.repeat):
                if step.sleep_before_ms > 0:
                    await asyncio.sleep(step.sleep_before_ms / 1000.0)
                    
                proposals += 1
                
                # Execute action via callback
                # Return format: {"verdict": "...", "next_step": "...", "execution": {...}}
                result = await self.executor_func(step)
                
                verdict = result.get("verdict", "ALLOW")
                next_step_hub = result.get("next_step", "PROCEED")
                
                # Consult s.on branch table
                # Precedence: verdict name -> next_step name -> "ANY"
                target = None
                if verdict in step.on:
                    target = step.on[verdict]
                elif next_step_hub in step.on:
                    target = step.on[next_step_hub]
                elif "ANY" in step.on:
                    target = step.on["ANY"]
                else:
                    # If no match, continue to the next step in list order
                    idx = list(self.steps.keys()).index(cur)
                    if idx + 1 < len(self.steps):
                        target = list(self.steps.keys())[idx + 1]
                    else:
                        target = "@end"
                        
                if step.repeat_interval_ms > 0 and i < step.repeat - 1:
                    await asyncio.sleep(step.repeat_interval_ms / 1000.0)
                    
                # We only break the repeat loop if the target is different or explicitly jumps?
                # Actually, the spec says "for i in range(s.repeat): ... after each response consult s.on ... jump to target".
                # If target is explicitly set, we break out of the repeat loop and jump.
                # If target matches current step, we just continue repeating?
                # Let's assume any target explicitly mapped means we follow it immediately, 
                # but if no match, we continue repeating, and AFTER repeats, we go to the next step.
                if target and target != cur:
                    break

            if target == "@end":
                break
            elif target == "@complete_success":
                await self.complete_func(outcome="success")
                break
            elif target == "@complete_failure":
                await self.complete_func(outcome="failure")
                break
            elif target == "@claim_success":
                # In real implementation we'd post claims for milestones
                await self.complete_func(outcome="success")
                break
            else:
                cur = target
