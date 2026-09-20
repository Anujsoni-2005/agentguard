"""
Database Repository — §1.3

Async data access for runs, actions, approvals, and thoughts.
All reads/writes go through this module — no raw SQL elsewhere.
"""

from __future__ import annotations

import json
from typing import Any

import aiosqlite
import structlog

from agentguard.models.run import Budgets, Run, RunCounters, Taint, TaskSpec
from agentguard.registry import ActionStatus, ApprovalStatus, RunStatus
from agentguard.timeutil import utcnow

logger = structlog.get_logger(__name__)


class Repository:
    """Async repository wrapping aiosqlite."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    # ── RUNS ─────────────────────────────────────────────────────────

    async def insert_run(self, run: Run) -> None:
        """Insert a new run row."""
        await self._db.execute(
            """INSERT INTO runs
               (run_id, status, task_json, budgets_json, policy_id, created_at, started_at,
                next_seq, counters_json, taint_json, halt_reason, unanswered_approvals, sandbox_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run.run_id, run.status.value,
                json.dumps(run.task.model_dump(mode="json")),
                json.dumps(run.budgets.model_dump(mode="json")),
                run.task.policy_id,
                run.created_at, run.started_at,
                run.next_seq,
                json.dumps(run.counters.model_dump(mode="json")),
                json.dumps(run.taint.model_dump(mode="json")),
                run.halt_reason,
                run.unanswered_approvals,
                json.dumps(run.sandbox),
            ),
        )
        await self._db.commit()

    async def get_run(self, run_id: str) -> Run | None:
        """Load a run by ID, or return None."""
        cursor = await self._db.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return self._row_to_run(row)

    async def list_runs(
        self, *, status: str | None = None, limit: int = 50, cursor: str | None = None
    ) -> list[Run]:
        """List runs with optional status filter and cursor pagination."""
        conditions = []
        params: list[Any] = []
        if status:
            conditions.append("status = ?")
            params.append(status)
        if cursor:
            conditions.append("created_at < ?")
            params.append(cursor)
        where = " AND ".join(conditions) if conditions else "1=1"
        params.append(limit)
        query = f"SELECT * FROM runs WHERE {where} ORDER BY created_at DESC LIMIT ?"
        cursor_obj = await self._db.execute(query, params)
        rows = await cursor_obj.fetchall()
        return [self._row_to_run(r) for r in rows]

    async def update_run(self, run: Run) -> None:
        """Update mutable run fields."""
        await self._db.execute(
            """UPDATE runs SET
               status=?, started_at=?, ended_at=?, next_seq=?,
               counters_json=?, taint_json=?, halt_reason=?, pause_reason=?,
               unanswered_approvals=?, sandbox_json=?, ws_epoch=?,
               pending_advisories_json=?
               WHERE run_id=?""",
            (
                run.status.value, run.started_at, run.ended_at, run.next_seq,
                json.dumps(run.counters.model_dump(mode="json")),
                json.dumps(run.taint.model_dump(mode="json")),
                run.halt_reason, run.pause_reason,
                run.unanswered_approvals,
                json.dumps(run.sandbox),
                run.ws_epoch,
                run.pending_advisories_json,
                run.run_id,
            ),
        )
        await self._db.commit()

    def _row_to_run(self, row: aiosqlite.Row) -> Run:
        """Convert a DB row to a Run model."""
        return Run(
            run_id=row["run_id"],
            status=RunStatus(row["status"]),
            task=TaskSpec.model_validate(json.loads(row["task_json"])),
            budgets=Budgets.model_validate(json.loads(row["budgets_json"])),
            created_at=row["created_at"],
            started_at=row["started_at"],
            ended_at=row["ended_at"],
            next_seq=row["next_seq"],
            counters=RunCounters.model_validate(json.loads(row["counters_json"])),
            taint=Taint.model_validate(json.loads(row["taint_json"])),
            halt_reason=row["halt_reason"],
            pause_reason=row["pause_reason"],
            unanswered_approvals=row["unanswered_approvals"],
            sandbox=json.loads(row["sandbox_json"]),
            ws_epoch=row["ws_epoch"],
        )

    # ── ACTIONS ──────────────────────────────────────────────────────

    async def insert_action(
        self,
        action_id: str,
        run_id: str,
        seq: int,
        client_action_id: str,
        action_type: str,
        proposal_json: str,
        params_hash: str,
        fingerprint: str,
        status: str,
        received_at: str,
    ) -> None:
        """Insert a new action row."""
        await self._db.execute(
            """INSERT INTO actions
               (action_id, run_id, seq, client_action_id, action_type,
                proposal_json, params_hash, fingerprint, status, received_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (action_id, run_id, seq, client_action_id, action_type,
             proposal_json, params_hash, fingerprint, status, received_at),
        )
        await self._db.commit()

    async def update_action_verdict(
        self,
        action_id: str,
        *,
        status: str,
        verdict: str,
        next_step: str,
        risk_score: int,
        reason_codes: list[str],
        findings_json: str,
        decided_at: str,
        decision_ms: float,
        ledger_idx: int | None = None,
        approval_id: str | None = None,
        grant_id: str | None = None,
    ) -> None:
        """Update action with verdict details."""
        await self._db.execute(
            """UPDATE actions SET
               status=?, verdict=?, next_step=?, risk_score=?,
               reason_codes_json=?, findings_json=?,
               decided_at=?, decision_ms=?, ledger_idx_verdict=?,
               approval_id=?, grant_id=?
               WHERE action_id=?""",
            (status, verdict, next_step, risk_score,
             json.dumps(reason_codes), findings_json,
             decided_at, decision_ms, ledger_idx,
             approval_id, grant_id, action_id),
        )
        await self._db.commit()

    async def update_action_result(
        self,
        action_id: str,
        *,
        status: str,
        result_json: str,
        executed_at: str,
        finished_at: str,
    ) -> None:
        """Update action with execution result."""
        await self._db.execute(
            """UPDATE actions SET status=?, result_json=?, executed_at=?, finished_at=?
               WHERE action_id=?""",
            (status, result_json, executed_at, finished_at, action_id),
        )
        await self._db.commit()

    async def find_action_by_client_id(
        self, run_id: str, client_action_id: str
    ) -> dict[str, Any] | None:
        """Lookup action by (run_id, client_action_id) for idempotency. §1.5.2 P1"""
        cursor = await self._db.execute(
            "SELECT * FROM actions WHERE run_id=? AND client_action_id=?",
            (run_id, client_action_id),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    async def list_actions(
        self, run_id: str, *, after_seq: int = 0, limit: int = 100
    ) -> list[dict[str, Any]]:
        """List actions for a run after a given sequence number."""
        cursor = await self._db.execute(
            "SELECT * FROM actions WHERE run_id=? AND seq>? ORDER BY seq LIMIT ?",
            (run_id, after_seq, limit),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    # ── APPROVALS ────────────────────────────────────────────────────

    async def insert_approval(self, data: dict[str, Any]) -> None:
        """Insert an approval row."""
        await self._db.execute(
            """INSERT INTO approvals
               (approval_id, run_id, action_id, status, action_hash, action_type,
                summary, findings_json, risk_score, artifacts_json,
                requested_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                data["approval_id"], data["run_id"], data["action_id"],
                data["status"], data["action_hash"], data.get("action_type", ""),
                data["summary"], data["findings_json"], data["risk_score"],
                data.get("artifacts_json", "{}"),
                data["requested_at"], data["expires_at"],
            ),
        )
        await self._db.commit()

    async def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        """Get approval by ID."""
        cursor = await self._db.execute(
            "SELECT * FROM approvals WHERE approval_id=?", (approval_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def update_approval_decision(
        self,
        approval_id: str,
        *,
        status: str,
        decided_at: str,
        decided_by: str | None,
        note: str | None,
        grant_request_json: str | None,
    ) -> int:
        """
        Update approval status. Returns rows affected (for race detection §1.7 F-12).
        Uses WHERE status='PENDING' so only one admin wins.
        """
        cursor = await self._db.execute(
            """UPDATE approvals SET status=?, decided_at=?, decided_by=?, note=?, grant_request_json=?
               WHERE approval_id=? AND status='PENDING'""",
            (status, decided_at, decided_by, note, grant_request_json, approval_id),
        )
        await self._db.commit()
        return cursor.rowcount

    async def list_pending_approvals(
        self, *, run_id: str | None = None
    ) -> list[dict[str, Any]]:
        """List PENDING approvals, optionally filtered by run_id."""
        if run_id:
            cursor = await self._db.execute(
                "SELECT * FROM approvals WHERE status='PENDING' AND run_id=? ORDER BY requested_at",
                (run_id,),
            )
        else:
            cursor = await self._db.execute(
                "SELECT * FROM approvals WHERE status='PENDING' ORDER BY requested_at"
            )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def expire_approvals(self, now: str) -> list[dict[str, Any]]:
        """
        Expire PENDING approvals past their expires_at. §1.5.5

        Returns list of expired approval dicts.
        """
        cursor = await self._db.execute(
            "SELECT * FROM approvals WHERE status='PENDING' AND expires_at < ?",
            (now,),
        )
        rows = await cursor.fetchall()
        expired = [dict(r) for r in rows]

        if expired:
            ids = [a["approval_id"] for a in expired]
            placeholders = ",".join("?" * len(ids))
            await self._db.execute(
                f"UPDATE approvals SET status='EXPIRED', decided_at=? WHERE approval_id IN ({placeholders})",
                [now, *ids],
            )
            await self._db.commit()

        return expired

    # ── THOUGHTS ─────────────────────────────────────────────────────

    async def insert_thought(
        self,
        run_id: str,
        ts: str,
        kind: str,
        text: str,
        meta_json: str,
    ) -> None:
        """Insert a thought record."""
        await self._db.execute(
            "INSERT INTO thoughts (run_id, ts, kind, text, meta_json) VALUES (?, ?, ?, ?, ?)",
            (run_id, ts, kind, text, meta_json),
        )
        await self._db.commit()
