"""
Progress Worker — §9.4
"""

import asyncio
import time
from typing import List, Dict, Any
from agentguard.models.run import Run
from agentguard.models.action import ActionRecord
from agentguard.models.policy import ProgressPolicy
from agentguard.progress.models import MilestoneStatus, ProgressEvent
from agentguard.models.escalation import Advisory, EscalationKind
from agentguard.progress.verifiers import VerifierEnv, evaluate_verifier
from agentguard.progress.probes import ProbeExecutor

class ProgressWorker:
    def __init__(self, run: Run, probe_executor: ProbeExecutor, milestones: List[MilestoneStatus], specs: Dict[str, Any]):
        self.run = run
        self.probe_executor = probe_executor
        self.milestones = {m.milestone_id: m for m in milestones}
        self.specs = specs
        self.queue: asyncio.Queue[ProgressEvent] = asyncio.Queue(maxsize=1000)
        self.running = False
        self.task: asyncio.Task | None = None
        self.history: List[ActionRecord] = []

    def start(self) -> None:
        self.running = True
        self.task = asyncio.create_task(self._loop())

    def stop(self) -> None:
        self.running = False
        if self.task:
            self.task.cancel()

    def enqueue(self, event: ProgressEvent) -> None:
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            pass # spec: overflow drops oldest tick/action_decided

    async def _loop(self) -> None:
        while self.running:
            advisories: List[Advisory] = []
            escalations: List[EscalationKind] = []
            events = []
            try:
                # wait for at least one event
                event = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                events.append(event)
                
                # Debounce for 200 ms
                await asyncio.sleep(0.2)
                
                while not self.queue.empty():
                    events.append(self.queue.get_nowait())
                    
                await self._process_events(events)
            except asyncio.TimeoutError:
                pass
            except asyncio.CancelledError:
                break
            except Exception as e:
                # PG-1 Worker crash recovery
                print(f"Worker exception: {e}")
                await asyncio.sleep(1)

    async def _process_events(self, events: List[ProgressEvent]) -> None:
        for ev in events:
            if ev.kind == "action_executed" and ev.payload:
                # Add to history
                pass
            elif ev.kind == "claim":
                ms_id = ev.payload.get("milestone_id")
                if ms_id in self.milestones:
                    ms = self.milestones[ms_id]
                    if ms.state == "IN_PROGRESS":
                        ms.state = MilestoneState.DONE_CLAIMED

        # Evaluate verifiers for milestones not DONE_VERIFIED
        env = VerifierEnv(
            run=self.run,
            history=self.history,
            probe=self.probe_executor,
            read_scratch=lambda path: None # placeholder
        )
        
        for m_id, m in self.milestones.items():
            if m.state in ("PENDING", "IN_PROGRESS", "DONE_CLAIMED", "REGRESSED"):
                spec = self.specs.get(m_id)
                if spec:
                    try:
                        passed, evidence = await asyncio.wait_for(
                            evaluate_verifier(env, spec), 
                            timeout=self.run.policy.progress.verifier_timeout_ms / 1000.0 if hasattr(self.run, 'policy') else 0.5
                        )
                        if passed:
                            m.state = MilestoneState.DONE_VERIFIED
                            m.evidence = evidence
                        elif m.state == "DONE_CLAIMED" and evidence.get("verifier_error"):
                            # remain claimed if error
                            pass
                    except asyncio.TimeoutError:
                        m.evidence = {"verifier_error": "timeout"}
                        
        # Save states (in memory for now)
