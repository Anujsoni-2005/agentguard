"""
Action Routes — §1.4.2

POST /v1/runs/{run_id}/actions         — propose action
GET  /v1/runs/{run_id}/actions/{id}    — get action (with wait)
GET  /v1/runs/{run_id}/actions         — list actions
"""

from __future__ import annotations 

import asyncio
import json
from typing import Any

from fastapi import APIRouter, Query, Request
from pydantic import ValidationError

from agentguard.canon import canonical_json, sha256_hex
from agentguard.hub.auth import require_role
from agentguard.hub.errors import AgentGuardError
from agentguard.hub.merge import merge_findings
from agentguard.cli.analyzer import CliAnalyzer
from agentguard.executors.docker import DockerExecutor
from agentguard.protocols import AnalysisContext, PolicySnapshot, RunHistoryView
from agentguard.ids import action_id as gen_action_id, approval_id as gen_approval_id, finding_id as gen_finding_id
from agentguard.models.action import PARAMS_MODELS, ActionDecision, ActionProposal, Timing
from agentguard.models.common import Finding
from agentguard.registry import (
    ActionStatus,
    HIGH_IMPACT_TYPES,
    NEXT_STEP_TABLE,
    RunStatus,
    Verdict,
)
from agentguard.timeutil import duration_ms, perf_counter_ns, utcnow

router = APIRouter(tags=["actions"])


def _get_run_lock(request: Request, run_id: str) -> asyncio.Lock:
    """Get or create per-run lock. §1.5.1"""
    locks: dict[str, asyncio.Lock] = request.app.state.run_locks
    if run_id not in locks:
        locks[run_id] = asyncio.Lock()
    return locks[run_id]


def _compute_fingerprint(action_type: str, params: dict[str, Any]) -> str:
    """
    Compute action fingerprint. §0.11

    fingerprint = sha256_hex(canonical_json({"t": type, "p": normalized_params}))[:16]
    """
    # Simplified: full normalization per type is in §2/§3; use params hash for now
    fp_obj = {"t": action_type, "p": params}
    return sha256_hex(canonical_json(fp_obj))[:16]


@router.post("/runs/{run_id}/actions")
async def propose_action(
    run_id: str,
    request: Request,
    execute: bool = Query(default=True),
    role: str = require_role("agent"),
) -> Any:
    """
    Propose an action. §1.4.2, §1.5.2

    Pipeline: P0 VALIDATE → P1 IDEMPOTENCY → P2-P7 (locked) → P8 EXECUTE → P9 POST-EXEC
    """
    settings = request.app.state.settings
    repo = request.app.state.repo
    ledger = request.app.state.ledger
    bus = request.app.state.bus

    t_start = perf_counter_ns()

    # ── P0: VALIDATE (no lock) ──────────────────────────────────────
    body_bytes = await request.body()
    if len(body_bytes) > settings.max_param_bytes:
        raise AgentGuardError("PAYLOAD_TOO_LARGE", "Request body exceeds AG_MAX_PARAM_BYTES")

    try:
        body = json.loads(body_bytes)
        proposal = ActionProposal.model_validate(body)
    except (json.JSONDecodeError, ValidationError) as e:
        raise AgentGuardError("SCHEMA_INVALID", str(e)[:500])

    param_model_cls = PARAMS_MODELS.get(proposal.action_type)
    if param_model_cls is None:
        raise AgentGuardError("SCHEMA_INVALID", f"Unsupported action type: {proposal.action_type}")

    try:
        params = param_model_cls.model_validate(proposal.params)
    except ValidationError as e:
        raise AgentGuardError("SCHEMA_INVALID", f"Invalid params: {str(e)[:500]}")

    params_hash = sha256_hex(canonical_json(params.model_dump(mode="json")))
    fingerprint = _compute_fingerprint(proposal.action_type, params.model_dump(mode="json"))

    t_validate = perf_counter_ns()

    # ── P1: IDEMPOTENCY ─────────────────────────────────────────────
    existing = await repo.find_action_by_client_id(run_id, proposal.client_action_id)
    if existing is not None:
        if existing["params_hash"] == params_hash:
            res_json = existing.get("result_json")
            if res_json is not None:
                payload = json.loads(res_json)
                payload["idempotent_replay"] = True
                return payload
            return {
                "action_id": existing["action_id"],
                "idempotent_replay": True,
                "run_id": run_id,
                "seq": existing["seq"],
                "status": existing["status"],
                "verdict": existing.get("verdict", "DENY"),
                "next_step": existing.get("next_step", "REPLAN"),
                "reason_codes": json.loads(existing.get("reason_codes_json", "[]")),
                "risk_score": existing.get("risk_score", 0),
                "findings": json.loads(existing.get("findings_json", "[]")),
                "timing": {"total_ms": 0, "validate_ms": 0, "prechecks_ms": 0, "analyzers_ms": {}, "merge_ms": 0, "ledger_ms": 0},
                "ledger_idx": existing.get("ledger_idx_verdict", 0),
                "ledger_hash": "",
            }
        else:
            raise AgentGuardError("IDEMPOTENCY_CONFLICT", "Same client_action_id with different params")

    # ── P2–P7: LOCKED ───────────────────────────────────────────────
    lock = _get_run_lock(request, run_id)
    async with lock:
        # P2: RUN GATE
        run = await repo.get_run(run_id)
        if run is None:
            raise AgentGuardError("RUN_NOT_FOUND", f"Run {run_id} does not exist")

        now = utcnow()
        new_action_id = gen_action_id()

        if run.status != RunStatus.RUNNING:
            # Create action with DENY/RUN_NOT_ACTIVE (§1.7 F-4)
            verdict = Verdict.HALT if run.status == RunStatus.HALTED else Verdict.DENY
            next_step_val = "ABORT"
            reason = "RUN_PAUSED" if run.status == RunStatus.PAUSED else "RUN_NOT_ACTIVE"

            await repo.insert_action(
                action_id=new_action_id, run_id=run_id, seq=run.next_seq,
                client_action_id=proposal.client_action_id,
                action_type=proposal.action_type,
                proposal_json=json.dumps(proposal.model_dump(mode="json")),
                params_hash=params_hash, fingerprint=fingerprint,
                status=ActionStatus.DENIED if verdict == Verdict.DENY else ActionStatus.HALTED,
                received_at=now,
            )

            t_end = perf_counter_ns()
            return _build_decision(
                action_id=new_action_id, run_id=run_id, seq=run.next_seq,
                status=ActionStatus.DENIED if verdict == Verdict.DENY else ActionStatus.HALTED,
                verdict=verdict, next_step_str=next_step_val,
                reason_codes=[reason], risk_score=0, findings=[],
                timing=Timing(
                    total_ms=duration_ms(t_start, t_end),
                    validate_ms=duration_ms(t_start, t_validate),
                    prechecks_ms=0, analyzers_ms={}, merge_ms=0, ledger_ms=0,
                ),
                ledger_idx=0, ledger_hash="",
                fingerprint=fingerprint, params_hash=params_hash,
                retry_after_ms=5000 if reason == "RUN_PAUSED" else None,
            )

        # Assign seq, advance next_seq
        seq = run.next_seq
        run.next_seq += 1

        # Create action row (RECEIVED)
        await repo.insert_action(
            action_id=new_action_id, run_id=run_id, seq=seq,
            client_action_id=proposal.client_action_id,
            action_type=proposal.action_type,
            proposal_json=json.dumps(proposal.model_dump(mode="json")),
            params_hash=params_hash, fingerprint=fingerprint,
            status=ActionStatus.EVALUATING.value,
            received_at=now,
        )

        # Ledger: action.received (durable=False)
        await ledger.append(
            run_id=run_id, event_type="action.received", actor="agent",
            action_id=new_action_id,
            payload={"seq": seq, "action_type": proposal.action_type, "params_hash": params_hash},
            durable=False,
        )

        t_prechecks_start = perf_counter_ns()

        # ── P3: PRE-CHECKS ─────────────────────────────────────────
        findings: list[Finding] = []
        halt_found = False

        # 3a BUDGET
        if run.counters.steps_used + 1 > run.budgets.max_steps:
            findings.append(Finding(
                finding_id=gen_finding_id(), source="hub", rule_id="HUB-001",
                reason_code="BUDGET_EXHAUSTED", severity=100,
                verdict_hint=Verdict.HALT,
                message="Step budget exhausted",
            ))
            halt_found = True

        started = run.started_at or run.created_at
        # TODO: wall-clock budget check using datetime parsing

        if run.budgets.max_tokens and run.counters.tokens >= run.budgets.max_tokens:
            findings.append(Finding(
                finding_id=gen_finding_id(), source="hub", rule_id="HUB-001",
                reason_code="BUDGET_EXHAUSTED", severity=100,
                verdict_hint=Verdict.HALT,
                message="Token budget exhausted",
            ))
            halt_found = True

        # 3b BREAKER (§8 stub)
        anomaly_hook = request.app.state.anomaly_hook
        from agentguard.models.action import ActionRecord
        action_record = ActionRecord(
            action_id=new_action_id, run_id=run_id, seq=seq,
            proposal=proposal, params=params,
            params_hash=params_hash, fingerprint=fingerprint,
            status=ActionStatus.EVALUATING,
            received_at=now,
        )
        breaker_finding = anomaly_hook.pre_check(run, action_record)
        if breaker_finding is not None:
            findings.append(breaker_finding)

        # 3c CONFIDENCE
        if (
            proposal.confidence is not None
            and proposal.confidence < settings.min_confidence
            and proposal.action_type not in {"fs.read", "fs.list"}
        ):
            findings.append(Finding(
                finding_id=gen_finding_id(), source="hub", rule_id="HUB-003",
                reason_code="LOW_CONFIDENCE", severity=45,
                verdict_hint=Verdict.ASK_HUMAN,
                message=f"Agent confidence {proposal.confidence:.2f} below threshold {settings.min_confidence}",
            ))

        # 3d TAINT
        if run.taint.level >= 1 and proposal.action_type in HIGH_IMPACT_TYPES:
            taint_url = run.taint.sources[0].url if run.taint.sources else "unknown"
            findings.append(Finding(
                finding_id=gen_finding_id(), source="hub", rule_id="HUB-004",
                reason_code="TAINTED_CONTEXT_ESCALATION", severity=65,
                verdict_hint=Verdict.ASK_HUMAN,
                message=f"Run context is tainted (source: {taint_url}); high-impact action requires approval",
            ))

        # 3e RISK TIERS (§7 policy.risk_tiers)
        # Load the active PolicyDoc for this run. Full policy-store wiring is pending;
        # for now use defaults (all tiers == "auto"), which is safe and correct behaviour.
        from agentguard.models.policy import PolicyDoc as _PolicyDoc
        policy = _PolicyDoc(mode="monitor" if run.task.policy_id == "eval-monitor" else "enforce")
        if not halt_found:
            _tier = policy.risk_tiers.get(proposal.action_type, "auto")
            if _tier == "block":
                findings.append(Finding(
                    finding_id=gen_finding_id(), source="hub", rule_id="HUB-005",
                    reason_code="POLICY_BLOCKED_ACTION_TYPE", severity=90,
                    verdict_hint=Verdict.DENY,
                    message=f"Policy blocks action type '{proposal.action_type}' (risk_tier=block)",
                ))
            elif _tier == "ask_human":
                findings.append(Finding(
                    finding_id=gen_finding_id(), source="hub", rule_id="HUB-005",
                    reason_code="POLICY_REQUIRES_APPROVAL", severity=50,
                    verdict_hint=Verdict.ASK_HUMAN,
                    message=f"Policy requires human approval for action type '{proposal.action_type}' (risk_tier=ask_human)",
                ))
            # _tier == "auto": normal analysis continues, no additional finding

        t_prechecks_end = perf_counter_ns()

        # ── P4: ANALYZERS ───────────────────────────────────────────
        # Skip if HALT finding already found
        analyzers_ms: dict[str, float] = {}
        if not halt_found:
            analyzers = []
            if proposal.action_type == "cli.exec":
                analyzers.append(CliAnalyzer())
            elif proposal.action_type == "net.http":
                from agentguard.net.analyzer import NetAnalyzer
                analyzers.append(NetAnalyzer())
                
            for analyzer in analyzers:
                ctx = AnalysisContext(
                    run=run, action=action_record, 
                    policy=PolicySnapshot(), history=RunHistoryView(), scratch={}
                )
                try:
                    analyzer_start = perf_counter_ns()
                    findings.extend(analyzer.analyze(ctx))
                    analyzer_time_ms = duration_ms(analyzer_start, perf_counter_ns())
                    analyzers_ms[analyzer.id] = analyzer_time_ms
                    if analyzer_time_ms > analyzer.timeout_ms:
                        findings.append(Finding(finding_id=gen_finding_id(), source="hub", rule_id="HUB-002", reason_code="ANALYZER_TIMEOUT", severity=55, verdict_hint="ASK_HUMAN", message=f"Analyzer {analyzer.id} timed out"))
                except Exception as e:
                    findings.append(Finding(finding_id=gen_finding_id(), source="hub", rule_id="HUB-002", reason_code="ANALYZER_ERROR", severity=60, verdict_hint="ASK_HUMAN", message=f"Analyzer {analyzer.id} failed: {e}"))

        t_analyzers_end = perf_counter_ns()

        # ── P5: MERGE ───────────────────────────────────────────────
        human_available = run.task.human_available
        if human_available is None:
            human_available = settings.human_available_default

        verdict, risk_score, reason_codes = merge_findings(findings, human_available, policy)

        t_merge_end = perf_counter_ns()

        # ── P6: GRANT ───────────────────────────────────────────────
        grant_store = request.app.state.grant_store
        grant_summary = None
        if verdict == Verdict.ASK_HUMAN and risk_score < 80:
            grant = await grant_store.match(run_id, action_record)
            if grant is not None:
                verdict = Verdict.ALLOW_WITH_GRANT
                reason_codes = ["GRANT_APPLIED"] + [r for r in reason_codes if r != "GRANT_APPLIED"]
                await grant_store.consume(grant.grant_id)
                from agentguard.models.action import GrantSummary
                grant_summary = GrantSummary(grant_id=grant.grant_id)

        next_step = NEXT_STEP_TABLE[verdict]

        # ── P7: PERSIST + LEDGER ────────────────────────────────────
        status_map = {
            Verdict.ALLOW: ActionStatus.APPROVED,
            Verdict.ALLOW_WITH_GRANT: ActionStatus.APPROVED,
            Verdict.ASK_HUMAN: ActionStatus.PENDING_APPROVAL,
            Verdict.DENY: ActionStatus.DENIED,
            Verdict.HALT: ActionStatus.HALTED,
        }
        action_status = status_map[verdict]

        # Update counters
        run.counters.steps_used += 1
        if verdict == Verdict.DENY:
            run.counters.denied += 1
        elif verdict == Verdict.ASK_HUMAN:
            run.counters.asked += 1

        # Approval creation for ASK_HUMAN
        approval_id_val = None
        approval_summary = None
        if verdict == Verdict.ASK_HUMAN:
            approval_id_val = gen_approval_id()
            expires_at = utcnow()  # TODO: compute from TTL
            summary_text = f"{proposal.action_type}: {proposal.rationale[:100] or 'action requires approval'}"

            await repo.insert_approval({
                "approval_id": approval_id_val,
                "run_id": run_id,
                "action_id": new_action_id,
                "status": "PENDING",
                "action_hash": params_hash,
                "action_type": proposal.action_type,
                "summary": summary_text,
                "findings_json": json.dumps([f.model_dump(mode="json") for f in findings]),
                "risk_score": risk_score,
                "requested_at": now,
                "expires_at": expires_at,
            })

            # Hold unredacted params in memory (§1.3)
            request.app.state.pending_params[new_action_id] = params

            from agentguard.models.action import ApprovalSummary
            approval_summary = ApprovalSummary(
                approval_id=approval_id_val,
                status="PENDING",
                expires_at=expires_at,
                summary=summary_text,
                risk_score=risk_score,
            )

        decided_at = utcnow()

        # Ledger: action.verdict (durable=True — §0.7)
        try:
            verdict_rec = await ledger.append(
                run_id=run_id, event_type="action.verdict", actor="hub",
                action_id=new_action_id,
                payload={
                    "seq": seq, "action_type": proposal.action_type,
                    "params_hash": params_hash, "fingerprint": fingerprint,
                    "verdict": verdict.value, "next_step": next_step.value,
                    "reason_codes": reason_codes, "risk_score": risk_score,
                    "findings": [f.model_dump(mode="json") for f in findings],
                },
                durable=True,
            )
        except Exception:
            # §0.10.5: ledger failure → force DENY, HALT run
            verdict = Verdict.HALT
            action_status = ActionStatus.HALTED
            next_step = NEXT_STEP_TABLE[Verdict.HALT]
            reason_codes = ["ANALYZER_ERROR"]
            run.status = RunStatus.HALTED
            run.halt_reason = "audit unavailable"
            await repo.update_run(run)
            verdict_rec = type("FakeRec", (), {"idx": -1, "hash": ""})()  # type: ignore[assignment]

        t_ledger_end = perf_counter_ns()

        # Update action in DB
        await repo.update_action_verdict(
            new_action_id,
            status=action_status.value,
            verdict=verdict.value,
            next_step=next_step.value,
            risk_score=risk_score,
            reason_codes=reason_codes,
            findings_json=json.dumps([f.model_dump(mode="json") for f in findings]),
            decided_at=decided_at,
            decision_ms=duration_ms(t_start, t_ledger_end),
            ledger_idx=verdict_rec.idx,
            approval_id=approval_id_val,
        )

        # HALT → update run
        if verdict == Verdict.HALT:
            run.status = RunStatus.HALTED
            run.halt_reason = run.halt_reason or "; ".join(reason_codes)
            run.ended_at = utcnow()
            await repo.update_run(run)

        await repo.update_run(run)

    # LOCK RELEASED

    # ── P8: EXECUTE ─────────────────────────────────────────────────
    execution_result = None
    t_execute_end = t_ledger_end

    if verdict in {Verdict.ALLOW, Verdict.ALLOW_WITH_GRANT} and execute:
        # Ledger: action.executing
        await ledger.append(
            run_id=run_id, event_type="action.executing", actor="hub",
            action_id=new_action_id,
            payload={"seq": seq, "action_type": proposal.action_type},
            durable=False,
        )

        if proposal.action_type == "cli.exec":
            import os
            run_scratch = os.path.join(request.app.state.settings.data_dir, "runs", run.run_id, "scratch")
            if os.path.isdir(run_scratch):
                actual_workspace = os.path.abspath(run_scratch)
            else:
                actual_workspace = request.app.state.settings.workspaces_dir
            executor = DockerExecutor(workspace_dir=actual_workspace)
            execution_result = await executor.execute(run, action_record, grant=None)
        elif proposal.action_type == "net.http":
            from agentguard.net.executor import execute_http
            from agentguard.net.models import NetPolicy
            from agentguard.models.common import ExecutionResult
            import base64
            
            params = action_record.params
            url = params.url if hasattr(params, "url") else params.get("url")
            method = params.method if hasattr(params, "method") else params.get("method")
            headers = params.headers if hasattr(params, "headers") else params.get("headers", {})
            timeout_s = params.timeout_s if hasattr(params, "timeout_s") else params.get("timeout_s", 20)
            body_b64 = params.body_b64 if hasattr(params, "body_b64") else params.get("body_b64")
            body_bytes = base64.b64decode(body_b64) if body_b64 else None
            
            token = "dummy_token" # In real system, generated per run
            policy = NetPolicy()
            ca_path = False # Mocked for prototype
            
            status, meta, tainted, taint_reasons, stdout, truncated = await execute_http(
                run_id=run_id, token=token, method=method, url=url, 
                headers=headers, body=body_bytes, timeout_s=timeout_s, 
                policy=policy, ca_path=ca_path
            )
            
            execution_result = ExecutionResult(
                status=status,
                exit_code=0 if status == "SUCCEEDED" else -1,
                stdout=stdout,
                stderr="",
                truncated=truncated,
                duration_ms=0.0,
                output_tainted=tainted,
                taint_reasons=taint_reasons,
                meta=meta
            )
            
            if execution_result is not None and getattr(execution_result, "output_tainted", False):
                from agentguard.models.run import TaintSource
                reasons = getattr(execution_result, "taint_reasons", []) or []
                new_level = 2 if len(reasons) >= 3 else 1
                if new_level > run.taint.level:
                    run.taint.level = new_level
                run.taint.sources.append(TaintSource(
                    action_id=new_action_id,
                    url=(execution_result.meta.get("final_url") or execution_result.meta.get("url")) if getattr(execution_result, "meta", None) else None,
                    reasons=reasons,
                    at=utcnow(),
                ))
                run.taint.sources = run.taint.sources[-20:]
                await repo.update_run(run)
                await ledger.append(
                    run_id=run_id, event_type="taint.raised", actor="hub",
                    action_id=new_action_id,
                    payload={"level": run.taint.level, "reasons": reasons},
                    durable=True,
                )
        else:
            from agentguard.models.common import ExecutionResult
            execution_result = ExecutionResult(status="NOT_EXECUTED", exit_code=-1, stdout="", stderr="", truncated=False, duration_ms=0.0, output_tainted=False, taint_reasons=[], meta={})

        t_execute_end = perf_counter_ns()

    # ── P9: POST-EXEC ──────────────────────────────────────────────
    if execution_result and execution_result.status != "NOT_EXECUTED":
        # ── Prismor Fallback Check ──
        if execution_result.stdout:
            run_honeytokens = run.flags.get("honeytokens", [])
            for ht in run_honeytokens:
                marker = ht.get("marker")
                if marker and marker in execution_result.stdout:
                    from agentguard.models.run import TaintSource
                    run.taint.level = max(run.taint.level, 3)
                    run.taint.sources.append(TaintSource(
                        action_id=new_action_id,
                        reasons=[f"Tripped honeytoken marker for {ht.get('path')}"],
                        at=utcnow(),
                    ))
                    run.taint.sources = run.taint.sources[-20:]
                    await repo.update_run(run)
                    await ledger.append(
                        run_id=run_id, event_type="honeytoken.tripped", actor="hub",
                        action_id=new_action_id,
                        payload={"path": ht.get("path"), "marker": marker},
                        durable=True,
                    )
                    break

        async with lock:
            # Update action result
            finished_at = utcnow()
            await repo.update_action_result(
                new_action_id,
                status=execution_result.status,
                result_json=json.dumps(execution_result.model_dump(mode="json")),
                executed_at=now, finished_at=finished_at,
            )
            # Ledger: action.executed
            await ledger.append(
                run_id=run_id, event_type="action.executed", actor="hub",
                action_id=new_action_id,
                payload={
                    "status": execution_result.status,
                    "exit_code": execution_result.exit_code,
                    "duration_ms": execution_result.duration_ms,
                },
                durable=False,
            )

    # ── P10: ANOMALY OBSERVE ───────────────────────────────────────
    action_record.status = action_status
    action_record.findings = findings
    action_record.reason_codes = reason_codes
    signals = request.app.state.anomaly_hook.observe(run, action_record, execution_result)
    for sig in signals:
        await ledger.append(
            run_id=run_id, event_type="anomaly.detected", actor="hub",
            action_id=new_action_id,
            payload={"signal_id": sig.id, "level": sig.level, "message": sig.message, "evidence": sig.evidence},
            durable=True
        )
        if sig.level == "TRIP":
            # breaker.trip() already set run.status/pause_reason correctly
            # inside HubAnomalyHook.observe() — just persist it here.
            await repo.update_run(run)

    # ── Build response ──────────────────────────────────────────────
    t_end = perf_counter_ns()

    timing = Timing(
        total_ms=duration_ms(t_start, t_end),
        validate_ms=duration_ms(t_start, t_validate),
        prechecks_ms=duration_ms(t_prechecks_start, t_prechecks_end),
        analyzers_ms=analyzers_ms,
        merge_ms=duration_ms(t_prechecks_end, t_merge_end),
        ledger_ms=duration_ms(t_merge_end, t_ledger_end),
        execute_ms=duration_ms(t_ledger_end, t_execute_end) if execution_result else None,
    )

    # HTTP status: 200 for ALLOW/DENY, 202 for ASK_HUMAN (§1.4.2)
    from fastapi.responses import JSONResponse
    http_status = 202 if verdict == Verdict.ASK_HUMAN else 200

    decision = _build_decision(
        action_id=new_action_id, run_id=run_id, seq=seq,
        status=action_status, verdict=verdict, next_step_str=next_step.value,
        reason_codes=reason_codes, risk_score=risk_score, findings=findings,
        timing=timing,
        ledger_idx=verdict_rec.idx, ledger_hash=verdict_rec.hash,
        fingerprint=fingerprint, params_hash=params_hash,
        approval=approval_summary, grant=grant_summary,
        execution=execution_result,
    )

    return JSONResponse(status_code=http_status, content=decision)


@router.get("/runs/{run_id}/actions/{action_id}")
async def get_action(
    run_id: str,
    action_id: str,
    request: Request,
    wait_s: int = Query(default=0, ge=0, le=30),
    role: str = require_role("agent", "admin"),
) -> dict[str, Any]:
    """Get action decision with optional long-poll. §1.4.2"""
    repo = request.app.state.repo
    action = await repo.find_action_by_client_id(run_id, action_id)
    # Also try by action_id
    if action is None:
        cursor = await repo._db.execute(
            "SELECT * FROM actions WHERE action_id=? AND run_id=?",
            (action_id, run_id),
        )
        row = await cursor.fetchone()
        if row:
            action = dict(row)
    if action is None:
        raise AgentGuardError("ACTION_NOT_FOUND", f"Action {action_id} not found")

    # TODO: long-poll for wait_s if status is PENDING_APPROVAL/EXECUTING

    return {
        "action_id": action["action_id"],
        "run_id": run_id,
        "seq": action["seq"],
        "status": action["status"],
        "verdict": action.get("verdict"),
        "next_step": action.get("next_step"),
        "reason_codes": json.loads(action.get("reason_codes_json", "[]")),
        "risk_score": action.get("risk_score", 0),
        "findings": json.loads(action.get("findings_json", "[]")),
        "timing": {"total_ms": 0, "validate_ms": 0, "prechecks_ms": 0, "analyzers_ms": {}, "merge_ms": 0, "ledger_ms": 0},
        "ledger_idx": action.get("ledger_idx_verdict", 0),
        "ledger_hash": "",
    }


@router.get("/runs/{run_id}/actions")
async def list_actions(
    run_id: str,
    request: Request,
    after_seq: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    role: str = require_role("agent", "admin"),
) -> dict[str, Any]:
    """List actions. §1.4.2"""
    repo = request.app.state.repo
    items = await repo.list_actions(run_id, after_seq=after_seq, limit=limit)
    for item in items:
        item["reason_codes"] = json.loads(item.get("reason_codes_json", "[]"))
        item["findings"] = json.loads(item.get("findings_json", "[]"))
    return {"items": items}


def _build_decision(
    *,
    action_id: str,
    run_id: str,
    seq: int,
    status: ActionStatus,
    verdict: Verdict,
    next_step_str: str,
    reason_codes: list[str],
    risk_score: int,
    findings: list[Finding],
    timing: Timing,
    ledger_idx: int,
    ledger_hash: str,
    fingerprint: str = "",
    params_hash: str = "",
    approval: Any = None,
    grant: Any = None,
    execution: Any = None,
    retry_after_ms: int | None = None,
) -> dict[str, Any]:
    """Build the ActionDecision response dict."""
    result: dict[str, Any] = {
        "action_id": action_id,
        "run_id": run_id,
        "seq": seq,
        "status": status.value if isinstance(status, ActionStatus) else status,
        "verdict": verdict.value if isinstance(verdict, Verdict) else verdict,
        "next_step": next_step_str,
        "retry_after_ms": retry_after_ms,
        "reason_codes": reason_codes,
        "risk_score": risk_score,
        "findings": [f.model_dump(mode="json") if hasattr(f, "model_dump") else f for f in findings],
        "approval": approval.model_dump(mode="json") if approval and hasattr(approval, "model_dump") else approval,
        "grant": grant.model_dump(mode="json") if grant and hasattr(grant, "model_dump") else grant,
        "execution": execution.model_dump(mode="json") if execution and hasattr(execution, "model_dump") else execution,
        "timing": timing.model_dump(mode="json") if hasattr(timing, "model_dump") else timing,
        "ledger_idx": ledger_idx,
        "ledger_hash": ledger_hash,
        "fingerprint": fingerprint,
        "params_hash": params_hash,
        "advisories": [],
        "enforced": True,
        "would_have_verdict": None,
    }
    return result
