"""
FastAPI Application Factory — §1.1

Creates the app with all dependencies injected via app.state.
No global mutable state except through objects created here (§0.3).
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agentguard.config import Settings
from agentguard.hub.bus import EventBus
from agentguard.hub.errors import AgentGuardError, agentguard_exception_handler
from agentguard.protocols import StubAnomalyHook, StubGrantStore, StubProgressHook
from agentguard.store.db import apply_schema, get_connection
from agentguard.store.ledger import FileLedgerWriter
from agentguard.store.repo import Repository

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan — startup and shutdown.

    Startup: connect DB, apply schema, initialize ledger, start background tasks.
    Shutdown: close connections, stop tasks.
    """
    settings: Settings = app.state.settings

    if settings.eval_mode and settings.env == "prod":
        logger.error("hub.startup_failed", reason="AG_EVAL_MODE=true is forbidden when AG_ENV=prod")
        raise RuntimeError("AG_EVAL_MODE=true is forbidden when AG_ENV=prod")

    # ── Database ────────────────────────────────────────────────────
    db = await get_connection(settings.db_path)
    await apply_schema(db)
    app.state.db = db
    app.state.repo = Repository(db)

    # ── Ledger ──────────────────────────────────────────────────────
    ledger = FileLedgerWriter(
        settings.ledger_path,
        fsync_policy=settings.ledger_fsync,
        segment_max_bytes=settings.ledger_segment_bytes,
    )
    await ledger.initialize()
    app.state.ledger = ledger

    # ── Event Bus ───────────────────────────────────────────────────
    app.state.bus = EventBus()

    # ── Stubs for later sections ────────────────────────────────────
    app.state.grant_store = StubGrantStore()
    
    from agentguard.telemetry.anomaly import AnomalyEngine
    from agentguard.models.policy import AnomalyPolicy
    from agentguard.models.common import Finding
    
    class HubAnomalyHook:
        def __init__(self):
            self.engines = {}
            self.breakers = {}

        def _get_engine(self, run_id: str) -> AnomalyEngine:
            if run_id not in self.engines:
                self.engines[run_id] = AnomalyEngine(AnomalyPolicy())
            return self.engines[run_id]

        def _get_breaker(self, run_id: str):
            if run_id not in self.breakers:
                from agentguard.telemetry.breaker import CircuitBreaker
                from agentguard.models.policy import BreakerPolicy
                self.breakers[run_id] = CircuitBreaker(BreakerPolicy())
            return self.breakers[run_id]

        def _map_outcome(self, action, result) -> str:
            if result is None:
                pre_exec = action.status.name if hasattr(action.status, 'name') else str(action.status).split('.')[-1]
                mapping = {"DENIED": "DENIED", "HALTED": "DENIED", "REJECTED": "REJECTED", "EXPIRED": "EXPIRED"}
                return mapping.get(pre_exec, "DENIED")
            status_map = {"SUCCEEDED": "OK", "FAILED": "FAIL", "KILLED": "FAIL", "TIMED_OUT": "TIMEOUT"}
            return status_map.get(getattr(result, "status", None), "FAIL")

        def _compute_out_hash(self, result) -> str | None:
            if result is None or getattr(result, "status", None) != "SUCCEEDED":
                return None
            import hashlib
            raw = f"{result.stdout}|{result.stderr}|{getattr(result, 'exit_code', None)}".encode()
            return hashlib.sha256(raw).hexdigest()

        def pre_check(self, run, action) -> Finding | None:
            breaker = self._get_breaker(run.run_id)
            return breaker.pre_check(action, run)

        def observe(self, run, action, result) -> list:
            engine = self._get_engine(run.run_id)
            outcome = self._map_outcome(action, result)
            out_hash = self._compute_out_hash(result)
            dur_ms = getattr(result, "duration_ms", None) if result else None

            signals = engine.observe(
                action=action,
                scratch={},
                outcome=outcome,
                out_hash=out_hash,
                dur_ms=dur_ms,
                ws_epoch=0,
                run=run
            )

            breaker = self._get_breaker(run.run_id)
            for sig in signals:
                if sig.level == "TRIP":
                    breaker.trip(run, sig)
            breaker.observe(outcome, signals[0] if signals else None)

            return signals

    app.state.anomaly_hook = HubAnomalyHook()
    app.state.progress_hook = StubProgressHook()

    # ── Per-run locks (§1.5.1) ──────────────────────────────────────
    app.state.run_locks: dict[str, asyncio.Lock] = {}

    # ── In-memory params for pending approvals (§1.3) ───────────────
    app.state.pending_params: dict[str, object] = {}

    # ── In-memory run cache (§13.4.3) ───────────────────────────────
    app.state.run_cache: dict[str, object] = {}

    # ── Process Pool for Large Bodies (§13.5) ───────────────────────
    import concurrent.futures
    app.state.process_pool = concurrent.futures.ProcessPoolExecutor(max_workers=settings.scan_workers)

    # ── Approval expiry background task (§1.5.5) ────────────────────
    async def _expire_loop() -> None:
        while True:
            try:
                await asyncio.sleep(5)
                from agentguard.timeutil import utcnow
                expired = await app.state.repo.expire_approvals(utcnow())
                for apr in expired:
                    logger.info("approval.expired", approval_id=apr["approval_id"])
                    # TODO: update action status, unanswered_approvals, check halt
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("expire_loop.error")

    expiry_task = asyncio.create_task(_expire_loop())

    logger.info("hub.started", ledger_idx=ledger.next_idx)

    yield

    # ── Shutdown ────────────────────────────────────────────────────
    expiry_task.cancel()
    try:
        await expiry_task
    except asyncio.CancelledError:
        pass
    app.state.process_pool.shutdown(wait=False)
    ledger.close()
    await db.close()
    logger.info("hub.stopped")


def create_app(settings: Settings | None = None) -> FastAPI:
    """
    Create the AgentGuard Hub FastAPI application. §1.1

    All mutable state is attached to app.state (§0.3).
    """
    if settings is None:
        settings = Settings()  # type: ignore[call-arg]

    app = FastAPI(
        title="AgentGuard Hub",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.state.settings = settings

    # Error handlers
    app.add_exception_handler(AgentGuardError, agentguard_exception_handler)  # type: ignore[arg-type]

    # CORS
    origins = [o.strip() for o in settings.cors_origins.split(",")]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Routes ──────────────────────────────────────────────────────
    from agentguard.hub.routes_runs import router as runs_router
    from agentguard.hub.routes_actions import router as actions_router
    from agentguard.hub.routes_approvals import router as approvals_router
    from agentguard.hub.routes_internal import router as internal_router
    from agentguard.hub.routes_debug import router as debug_router
    from agentguard.hub.routes_ws import router as ws_router

    app.include_router(runs_router, prefix="/v1")
    app.include_router(actions_router, prefix="/v1")
    app.include_router(approvals_router, prefix="/v1")
    app.include_router(internal_router, prefix="/internal/v1")
    app.include_router(debug_router, prefix="/v1")
    app.include_router(ws_router, prefix="/v1")

    # ── Health endpoints (no auth) ──────────────────────────────────

    @app.get("/v1/health")
    async def health() -> dict[str, str]:
        """Health check — no auth required. §1.4.4"""
        return {"status": "ok"}

    @app.get("/v1/ready")
    async def ready() -> dict[str, str]:
        """
        Readiness check — verifies DB, ledger, Docker. §1.4.4
        Returns 503 if not ready.
        """
        # TODO: check Docker reachable, policy loaded
        try:
            repo: Repository = app.state.repo
            await repo._db.execute("SELECT 1")
        except Exception:
            from fastapi.responses import JSONResponse
            return JSONResponse(  # type: ignore[return-value]
                status_code=503,
                content={"status": "not_ready", "reason": "database"},
            )
        return {"status": "ok"}

    return app
