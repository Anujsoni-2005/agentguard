"""
Run Routes — §1.4.1

POST /v1/runs          — create run
GET  /v1/runs/{run_id} — get run
GET  /v1/runs          — list runs
POST /v1/runs/{run_id}/thoughts  — record thought
POST /v1/runs/{run_id}/complete  — complete run
POST /v1/runs/{run_id}/halt      — kill switch
POST /v1/runs/{run_id}/taint/clear — clear taint
"""

from __future__ import annotations

import os
import hmac
import json
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field

from agentguard.hub.auth import require_role
from agentguard.hub.errors import AgentGuardError
from agentguard.ids import request_id as gen_request_id, run_id as gen_run_id
from agentguard.models.run import Budgets, Run, RunCounters, TaskSpec
from agentguard.registry import RunStatus
from agentguard.timeutil import utcnow

router = APIRouter(tags=["runs"])


# ═══════════════════════════════════════════════════════════════════════
# REQUEST / RESPONSE MODELS
# ═══════════════════════════════════════════════════════════════════════

class CreateRunRequest(BaseModel):
    task: TaskSpec
    budgets: Budgets = Budgets()


class ThoughtRequest(BaseModel):
    kind: Literal["thought", "plan", "observation", "final_answer"]
    text: str
    meta: dict[str, Any] = {}


class CompleteRequest(BaseModel):
    outcome: Literal["success", "failure", "abandoned"]
    summary: str = ""
    final_answer: str = ""
    override: bool = False
    justification: str | None = Field(default=None, max_length=500)


class HaltRequest(BaseModel):
    reason: str = "operator stop"


class TaintClearRequest(BaseModel):
    note: str = ""


# ═══════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════

@router.post("/runs", status_code=201)
async def create_run(
    body: CreateRunRequest,
    request: Request,
    role: str = require_role("agent", "admin"),
) -> dict[str, Any]:
    """Create a new run. §1.4.1"""
    settings = request.app.state.settings
    repo = request.app.state.repo
    ledger = request.app.state.ledger

    new_run_id = gen_run_id()
    now = utcnow()
    
    # 13.5 Admission Control 
    if len(request.app.state.run_locks) >= settings.max_concurrent_runs and os.environ.get("AG_EVAL_MODE") != "true":
        from fastapi import HTTPException
        raise HTTPException(status_code=429, detail="CAPACITY_EXCEEDED")

    # Resolve human_available
    human_available = body.task.human_available
    if human_available is None:
        human_available = settings.human_available_default

    # Compute per-run proxy token (§3.4)
    proxy_token = hmac.new(
        settings.server_secret.encode(),
        new_run_id.encode(),
        "sha256",
    ).hexdigest()[:32]

    run = Run(
        run_id=new_run_id,
        status=RunStatus.RUNNING,
        task=body.task,
        budgets=body.budgets,
        created_at=now,
        started_at=now,
        counters=RunCounters(),
    )

    # Persist
    await repo.insert_run(run)

    # ── Eager Workspace Creation ──
    try:
        from agentguard.models.policy import FsPolicy
        fs_policy = FsPolicy() # Use defaults
        workspace_state = request.app.state.workspace_manager.create_workspace(
            run_id=run.run_id,
            host_path=body.task.workspace_host_path,
            fs_policy=fs_policy
        )
        if workspace_state.honeytokens:
            run.flags["honeytokens"] = workspace_state.honeytokens
            await repo.update_run(run)
    except Exception as e:
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail=str(e))

    # Ledger: run.created (durable=False per §0.7)
    ledger_rec = await ledger.append(
        run_id=new_run_id,
        event_type="run.created",
        actor="hub",
        action_id=None,
        payload={
            "objective": body.task.objective[:200],
            "policy_id": body.task.policy_id,
            "budgets": body.budgets.model_dump(mode="json"),
        },
        durable=False,
    )

    # Publish event
    request.app.state.bus.publish({
        "type": "event",
        "idx": ledger_rec.idx,
        "record": ledger_rec.model_dump(mode="json"),
    })

    return {
        "run_id": new_run_id,
        "status": RunStatus.RUNNING.value,
        "created_at": now,
        "proxy": {
            "url": f"http://{new_run_id}:{proxy_token}@{settings.proxy_host}:{settings.proxy_port}",
            "note": "already injected in sandbox env",
        },
        "policy_hash": "stub",  # TODO(spec-gap): compute from loaded policy
        "ledger_idx": ledger_rec.idx,
    }


@router.get("/runs/{run_id}")
async def get_run(
    run_id: str,
    request: Request,
    wait_status_change_s: int = Query(default=0, ge=0, le=30),
    role: str = require_role("agent", "admin"),
) -> dict[str, Any]:
    """Get run details. §1.4.1"""
    repo = request.app.state.repo
    run = await repo.get_run(run_id)
    if run is None:
        raise AgentGuardError("RUN_NOT_FOUND", f"Run {run_id} does not exist")

    # TODO: long-poll for wait_status_change_s (§B3)
    result = run.model_dump(mode="json")
    # Add pending_approvals count
    pending = await repo.list_pending_approvals(run_id=run_id)
    result["pending_approvals"] = len(pending)
    return result


@router.get("/runs")
async def list_runs(
    request: Request,
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = None,
    role: str = require_role("agent", "admin"),
) -> dict[str, Any]:
    """List runs. §1.4.1"""
    repo = request.app.state.repo
    runs = await repo.list_runs(status=status, limit=limit, cursor=cursor)
    items = [r.model_dump(mode="json") for r in runs]
    next_cursor = items[-1]["created_at"] if items else None
    return {"items": items, "next_cursor": next_cursor}


@router.post("/runs/{run_id}/thoughts", status_code=202)
async def record_thought(
    run_id: str,
    body: ThoughtRequest,
    request: Request,
    role: str = require_role("agent"),
) -> dict[str, str]:
    """Record agent thought. §1.4.1"""
    repo = request.app.state.repo
    ledger = request.app.state.ledger

    run = await repo.get_run(run_id)
    if run is None:
        raise AgentGuardError("RUN_NOT_FOUND", f"Run {run_id} does not exist")
    if run.status != RunStatus.RUNNING:
        raise AgentGuardError("INVALID_STATE", f"Run {run_id} is {run.status}")

    now = utcnow()

    # Insert thought
    await repo.insert_thought(
        run_id=run_id, ts=now, kind=body.kind,
        text=body.text, meta_json=json.dumps(body.meta),
    )

    # Update counters (tokens, cost)
    if "tokens_in" in body.meta or "tokens_out" in body.meta:
        run.counters.tokens += body.meta.get("tokens_in", 0) + body.meta.get("tokens_out", 0)
    if "cost_usd" in body.meta:
        run.counters.cost_usd += body.meta["cost_usd"]
    await repo.update_run(run)

    # Budget check on tokens/cost
    if run.budgets.max_tokens and run.counters.tokens >= run.budgets.max_tokens:
        run.status = RunStatus.HALTED
        run.halt_reason = "BUDGET_EXHAUSTED"
        await repo.update_run(run)

    if run.budgets.max_cost_usd and run.counters.cost_usd >= run.budgets.max_cost_usd:
        run.status = RunStatus.HALTED
        run.halt_reason = "BUDGET_EXHAUSTED"
        await repo.update_run(run)

    # Ledger: thought.recorded (text truncated to 4KB in payload)
    await ledger.append(
        run_id=run_id,
        event_type="thought.recorded",
        actor="agent",
        action_id=None,
        payload={"kind": body.kind, "text": body.text[:4096]},
        durable=False,
    )

    return {"status": "accepted"}


@router.post("/runs/{run_id}/complete")
async def complete_run(
    run_id: str,
    body: CompleteRequest,
    request: Request,
    role: str = require_role("agent"),
) -> dict[str, Any]:
    """Complete a run. §1.4.1. Idempotent."""
    repo = request.app.state.repo
    ledger = request.app.state.ledger

    run = await repo.get_run(run_id)
    if run is None:
        raise AgentGuardError("RUN_NOT_FOUND", f"Run {run_id} does not exist")

    # Idempotent
    if run.status in {RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.ABANDONED}:
        return {"run_id": run_id, "status": run.status.value, "ended_at": run.ended_at}

    now = utcnow()
    status_map = {"success": RunStatus.COMPLETED, "failure": RunStatus.FAILED, "abandoned": RunStatus.ABANDONED}
    run.status = status_map[body.outcome]
    run.ended_at = now
    await repo.update_run(run)

    # Ledger: run.completed
    await ledger.append(
        run_id=run_id,
        event_type="run.completed",
        actor="agent",
        action_id=None,
        payload={"outcome": body.outcome, "summary": body.summary[:500]},
        durable=False,
    )

    return {"run_id": run_id, "status": run.status.value, "ended_at": now}


@router.post("/runs/{run_id}/halt")
async def halt_run(
    run_id: str,
    body: HaltRequest,
    request: Request,
    role: str = require_role("admin"),
) -> dict[str, Any]:
    """Kill switch — halt a run. §1.4.1"""
    repo = request.app.state.repo
    ledger = request.app.state.ledger

    run = await repo.get_run(run_id)
    if run is None:
        raise AgentGuardError("RUN_NOT_FOUND", f"Run {run_id} does not exist")

    now = utcnow()
    run.status = RunStatus.HALTED
    run.halt_reason = body.reason
    run.ended_at = now
    await repo.update_run(run)

    # Reject all pending approvals
    pending = await repo.list_pending_approvals(run_id=run_id)
    for apr in pending:
        await repo.update_approval_decision(
            apr["approval_id"],
            status="REJECTED",
            decided_at=now,
            decided_by="system",
            note="KILL_SWITCH",
            grant_request_json=None,
        )

    # Ledger
    await ledger.append(
        run_id=run_id,
        event_type="run.status_changed",
        actor="hub",
        action_id=None,
        payload={"status": "HALTED", "reason": body.reason},
        durable=True,
    )

    return {"run_id": run_id, "status": "HALTED", "halt_reason": body.reason}


@router.post("/runs/{run_id}/taint/clear")
async def clear_taint(
    run_id: str,
    body: TaintClearRequest,
    request: Request,
    role: str = require_role("admin"),
) -> dict[str, bool]:
    """Clear run taint. §1.4.1"""
    repo = request.app.state.repo
    ledger = request.app.state.ledger

    run = await repo.get_run(run_id)
    if run is None:
        raise AgentGuardError("RUN_NOT_FOUND", f"Run {run_id} does not exist")

    from agentguard.models.run import Taint
    run.taint = Taint(level=0, sources=[])
    await repo.update_run(run)

    # Ledger: taint.cleared
    decided_by = request.headers.get("X-AgentGuard-User", "admin")
    await ledger.append(
        run_id=run_id,
        event_type="taint.cleared",
        actor=f"human:{decided_by}",
        action_id=None,
        payload={"note": body.note},
        durable=True,
    )

    return {"cleared": True}

@router.post("/runs/{run_id}/resume")
async def resume_run(
    run_id: str,
    request: Request,
    role: str = require_role("admin"),
) -> dict[str, Any]:
    """Resume a PAUSED run (e.g. after a circuit breaker trip). §8.6"""
    repo = request.app.state.repo
    ledger = request.app.state.ledger

    run = await repo.get_run(run_id)
    if run is None:
        raise AgentGuardError("RUN_NOT_FOUND", f"Run {run_id} does not exist")
    if run.status != RunStatus.PAUSED:
        raise AgentGuardError("INVALID_STATE", f"Run is not paused (status={run.status})")

    breaker = request.app.state.anomaly_hook._get_breaker(run_id)
    breaker.resume(run)
    await repo.update_run(run)

    await ledger.append(
        run_id=run_id, event_type="run.resumed", actor="human",
        action_id=None, payload={}, durable=True,
    )

    return {"run_id": run_id, "status": run.status.value}
