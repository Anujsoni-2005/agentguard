"""
Internal Routes — §1.4.4

POST /internal/v1/egress-events    — proxy → hub (§3.6)
GET  /internal/v1/runs/{id}/status — proxy polling (§1.4.4)
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from agentguard.hub.auth import require_role
from agentguard.hub.errors import AgentGuardError

router = APIRouter(tags=["internal"])


@router.post("/egress-events")
async def egress_events(
    request: Request,
    role: str = require_role("internal"),
) -> dict[str, str]:
    """Receive egress events from the proxy. §3.6"""
    # TODO(spec-gap): implement when §3 is built
    return {"status": "accepted"}


@router.get("/runs/{run_id}/status")
async def run_status(
    run_id: str,
    request: Request,
    role: str = require_role("internal"),
) -> dict[str, Any]:
    """
    Proxy polling endpoint. §1.4.4

    Returns minimal run status for the proxy. Cacheable 2 s.
    """
    repo = request.app.state.repo
    run = await repo.get_run(run_id)
    if run is None:
        raise AgentGuardError("RUN_NOT_FOUND", f"Run {run_id} does not exist")

    return {
        "status": run.status.value,
        "taint_level": run.taint.level,
        "egress_bytes": run.counters.egress_bytes,
    }
