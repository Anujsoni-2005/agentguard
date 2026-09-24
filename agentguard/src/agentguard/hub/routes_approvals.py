"""
Approval Routes — §1.4.3

GET  /v1/approvals                      — list approvals
GET  /v1/approvals/{id}                 — get approval
POST /v1/approvals/{id}/decision        — approve/reject
"""

from __future__ import annotations

import json
from typing import Any, Literal

from fastapi import APIRouter, Query, Request
from pydantic import BaseModel, Field

from agentguard.hub.auth import require_role
from agentguard.hub.errors import AgentGuardError
from agentguard.models.approval import GrantRequest
from agentguard.timeutil import utcnow

router = APIRouter(tags=["approvals"])


class ApprovalDecisionRequest(BaseModel):
    decision: Literal["approve", "reject"]
    decided_by: str = "admin"
    note: str | None = None
    grant: GrantRequest | None = None


@router.get("/approvals")
async def list_approvals(
    request: Request,
    status: str = Query(default="PENDING"),
    run_id: str | None = None,
    role: str = require_role("admin"),
) -> dict[str, Any]:
    """List approvals. §1.4.3"""
    repo = request.app.state.repo
    if status == "PENDING":
        items = await repo.list_pending_approvals(run_id=run_id)
    else:
        # TODO: support other status filters
        items = await repo.list_pending_approvals(run_id=run_id)
    return {"items": items}


@router.get("/approvals/{approval_id}")
async def get_approval(
    approval_id: str,
    request: Request,
    role: str = require_role("admin"),
) -> dict[str, Any]:
    """Get approval. §1.4.3"""
    repo = request.app.state.repo
    approval = await repo.get_approval(approval_id)
    if approval is None:
        raise AgentGuardError("APPROVAL_NOT_FOUND", f"Approval {approval_id} not found")
    return approval


@router.post("/approvals/{approval_id}/decision")
async def decide_approval(
    approval_id: str,
    body: ApprovalDecisionRequest,
    request: Request,
    role: str = require_role("admin"),
) -> dict[str, Any]:
    """
    Approve or reject. §1.4.3 + §1.5.4

    Race detection: UPDATE WHERE status='PENDING'; check rows_affected.
    """
    repo = request.app.state.repo
    ledger = request.app.state.ledger

    approval = await repo.get_approval(approval_id)
    if approval is None:
        raise AgentGuardError("APPROVAL_NOT_FOUND", f"Approval {approval_id} not found")

    if approval["status"] != "PENDING":
        raise AgentGuardError(
            "INVALID_STATE",
            f"Approval is {approval['status']}, not PENDING",
            details={"reason": "expired" if approval["status"] == "EXPIRED" else approval["status"]},
        )

    now = utcnow()

    # Check expiry
    if approval["expires_at"] < now:
        await repo.update_approval_decision(
            approval_id, status="EXPIRED", decided_at=now,
            decided_by=None, note=None, grant_request_json=None,
        )
        raise AgentGuardError(
            "INVALID_STATE",
            "Approval has expired",
            details={"reason": "expired"},
        )

    new_status = "APPROVED" if body.decision == "approve" else "REJECTED"

    # Race detection (§1.7 F-12)
    rows = await repo.update_approval_decision(
        approval_id,
        status=new_status,
        decided_at=now,
        decided_by=body.decided_by,
        note=body.note,
        grant_request_json=json.dumps(body.grant.model_dump(mode="json")) if body.grant else None,
    )

    if rows == 0:
        raise AgentGuardError("INVALID_STATE", "Approval already decided by another admin")

    # Ledger: approval.resolved (durable=True)
    await ledger.append(
        run_id=approval["run_id"],
        event_type="approval.resolved",
        actor=f"human:{body.decided_by}",
        action_id=approval["action_id"],
        payload={
            "approval_id": approval_id,
            "decision": body.decision,
            "note": body.note or "",
        },
        durable=True,
    )

    # If approved → run P8/P9 in background (§1.5.4 step 5)
    if body.decision == "approve":
        # TODO: asyncio.create_task for P8/P9 execution
        pass

    # If rejected → update action status
    if body.decision == "reject":
        await repo.update_action_verdict(
            approval["action_id"],
            status="REJECTED", verdict="DENY", next_step="REPLAN",
            risk_score=approval["risk_score"],
            reason_codes=json.dumps(["APPROVAL_REJECTED"]),
            findings_json=approval["findings_json"],
            decided_at=now, decision_ms=0,
        )

    return {
        "approval_id": approval_id,
        "status": new_status,
        "decided_at": now,
        "decided_by": body.decided_by,
    }
