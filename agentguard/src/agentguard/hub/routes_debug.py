"""
Debug Routes — §1.4.4

POST /v1/debug/evaluate  — dry-run action analysis (admin only)
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Request
from pydantic import ValidationError

from agentguard.canon import canonical_json, sha256_hex
from agentguard.hub.auth import require_role
from agentguard.hub.errors import AgentGuardError
from agentguard.hub.merge import merge_findings
from agentguard.ids import action_id as gen_action_id, finding_id as gen_finding_id
from agentguard.models.action import PARAMS_MODELS, ActionProposal, Timing
from agentguard.models.common import Finding
from agentguard.registry import NEXT_STEP_TABLE, ActionStatus, Verdict
from agentguard.timeutil import duration_ms, perf_counter_ns

router = APIRouter(tags=["debug"])


@router.post("/debug/evaluate")
async def debug_evaluate(
    request: Request,
    role: str = require_role("admin"),
) -> dict[str, Any]:
    """
    Dry-run evaluation — never executes, never persists. §1.4.4

    Returns an ActionDecision-shaped response. Does not consume grants
    or advance next_seq. Used by eval harness (§11) and UI policy tester.
    """
    settings = request.app.state.settings
    t_start = perf_counter_ns()

    body = await request.json()

    try:
        proposal = ActionProposal.model_validate(body)
    except ValidationError as e:
        raise AgentGuardError("SCHEMA_INVALID", str(e)[:500])

    param_model_cls = PARAMS_MODELS.get(proposal.action_type)
    if param_model_cls is None:
        raise AgentGuardError("SCHEMA_INVALID", f"Unsupported action type: {proposal.action_type}")

    try:
        params = param_model_cls.model_validate(proposal.params)
    except ValidationError as e:
        raise AgentGuardError("SCHEMA_INVALID", f"Invalid params: {str(e)[:500]}")

    params_hash = sha256_hex(canonical_json(params.model_dump(mode="json")))

    # Run analyzers on a stub context
    findings: list[Finding] = []
    # TODO: run registered analyzers

    verdict, risk_score, reason_codes = merge_findings(findings, True)
    next_step = NEXT_STEP_TABLE[verdict]

    t_end = perf_counter_ns()

    status_map = {
        Verdict.ALLOW: ActionStatus.APPROVED,
        Verdict.ALLOW_WITH_GRANT: ActionStatus.APPROVED,
        Verdict.ASK_HUMAN: ActionStatus.PENDING_APPROVAL,
        Verdict.DENY: ActionStatus.DENIED,
        Verdict.HALT: ActionStatus.HALTED,
    }

    return {
        "action_id": gen_action_id(),
        "run_id": "debug",
        "seq": 0,
        "status": status_map[verdict].value,
        "verdict": verdict.value,
        "next_step": next_step.value,
        "reason_codes": reason_codes,
        "risk_score": risk_score,
        "findings": [f.model_dump(mode="json") for f in findings],
        "execution": None,
        "timing": {
            "total_ms": duration_ms(t_start, t_end),
            "validate_ms": duration_ms(t_start, t_end),
            "prechecks_ms": 0,
            "analyzers_ms": {},
            "merge_ms": 0,
            "ledger_ms": 0,
        },
        "ledger_idx": -1,
        "ledger_hash": "",
        "fingerprint": "",
        "params_hash": params_hash,
        "advisories": [],
        "enforced": True,
        "would_have_verdict": None,
    }
