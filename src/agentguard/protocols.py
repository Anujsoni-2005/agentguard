"""
Cross-section Protocols — §0.11 + Part 2 §A1 + Part 3 §B4 + §B7

All protocols that connect hub ↔ analyzers ↔ executors ↔ hooks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from agentguard.models.action import ActionRecord
from agentguard.models.common import ExecutionResult, Finding
from agentguard.models.grant import Grant
from agentguard.models.ledger import LedgerRecord
from agentguard.models.run import Run
from agentguard.registry import ActionType, Verdict


# ═══════════════════════════════════════════════════════════════════════
# ANALYSIS CONTEXT — §0.11 + §B7
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class PolicySnapshot:
    """
    Immutable policy snapshot — stub until §7.

    Uses defaults from config for all values.
    """
    risk_tiers: dict[str, str] = field(default_factory=dict)  # action_type → "allow"|"ask_human"|"block"
    mode: str = "enforce"  # "enforce" | "monitor"
    monitor_hard_block_severity: int = 95


@dataclass
class RunHistoryView:
    """Read-only view of recent actions/outcomes for a run. §0.11"""

    recent: list[Any] = field(default_factory=list)           # list[ActionObs] from §8


@dataclass
class AnalysisContext:
    """Context passed to all analyzers. §0.11 + §B7"""

    run: Run
    action: ActionRecord
    policy: PolicySnapshot
    history: RunHistoryView
    scratch: dict[str, Any] = field(default_factory=dict)     # §A1 prefetch results; §B7 "now", "findings_so_far"


# ═══════════════════════════════════════════════════════════════════════
# ANALYZER — §0.11
# ═══════════════════════════════════════════════════════════════════════

class Analyzer(Protocol):
    """
    Synchronous, pure, I/O-free analyzer. §0.11

    analyze() is deterministic and unit-testable.
    """

    @property
    def id(self) -> str: ...

    @property
    def handles(self) -> frozenset[ActionType]: ...

    @property
    def timeout_ms(self) -> int: ...

    def analyze(self, ctx: AnalysisContext) -> list[Finding]: ...


# ═══════════════════════════════════════════════════════════════════════
# PREFETCHER — Part 2 §A1
# ═══════════════════════════════════════════════════════════════════════

class Prefetcher(Protocol):
    """Async prefetch stage between P3 and P4. Part 2 §A1"""

    @property
    def handles(self) -> frozenset[ActionType]: ...

    @property
    def timeout_ms(self) -> int: ...

    @property
    def key(self) -> str: ...

    async def prefetch(self, ctx: AnalysisContext) -> dict[str, Any]: ...


# ═══════════════════════════════════════════════════════════════════════
# ARTIFACT BUILDER — Part 2 §A2
# ═══════════════════════════════════════════════════════════════════════

class ArtifactBuilder(Protocol):
    """Builds approval artifacts (diff, screenshot, IR). Part 2 §A2"""

    @property
    def handles(self) -> frozenset[ActionType]: ...

    def build(self, ctx: AnalysisContext, findings: list[Finding]) -> dict[str, Any]: ...


# ═══════════════════════════════════════════════════════════════════════
# EXECUTOR — §0.11
# ═══════════════════════════════════════════════════════════════════════

class Executor(Protocol):
    """Async action executor (Docker sandbox, HTTP proxy, etc). §0.11"""

    @property
    def handles(self) -> frozenset[ActionType]: ...

    async def execute(
        self, run: Run, action: ActionRecord, grant: Grant | None
    ) -> ExecutionResult: ...


# ═══════════════════════════════════════════════════════════════════════
# GRANT STORE — §0.11 (stub until §7)
# ═══════════════════════════════════════════════════════════════════════

class GrantStore(Protocol):
    """Grant matching and consumption. §0.11"""

    async def match(self, run_id: str, action: ActionRecord) -> Grant | None: ...
    async def consume(self, grant_id: str) -> None: ...


# ═══════════════════════════════════════════════════════════════════════
# HOOKS — §0.11 + Part 3 §B4
# ═══════════════════════════════════════════════════════════════════════

class AnomalyHook(Protocol):
    """
    Anomaly detection hook — Part 3 §B4 amended signature.

    pre_check is synchronous, in-memory, ≤ 1 ms.
    observe returns list[Signal] (§8).
    """

    def pre_check(self, run: Run, action: ActionRecord) -> Finding | None: ...
    def observe(
        self, run: Run, action: ActionRecord, result: ExecutionResult | None
    ) -> list[Any]: ...


class ProgressHook(Protocol):
    """Progress monitoring hook — Part 3 §B4."""

    def enqueue(self, run_id: str, event: Any) -> None: ...


# ═══════════════════════════════════════════════════════════════════════
# LEDGER WRITER — §0.7
# ═══════════════════════════════════════════════════════════════════════

class LedgerWriterProtocol(Protocol):
    """
    Ledger writer interface — §0.7.

    durable=True → flush()+os.fsync() before returning.
    Hub MUST use durable=True for action.verdict and approval.resolved.
    """

    async def append(
        self,
        *,
        run_id: str | None,
        event_type: str,
        actor: str,
        action_id: str | None,
        payload: dict[str, Any],
        durable: bool,
    ) -> LedgerRecord: ...


# ═══════════════════════════════════════════════════════════════════════
# STUBS — for components not yet implemented
# ═══════════════════════════════════════════════════════════════════════

class StubGrantStore:
    """Stub GrantStore — always returns None. §0.11"""

    async def match(self, run_id: str, action: ActionRecord) -> Grant | None:
        return None

    async def consume(self, grant_id: str) -> None:
        pass


class StubAnomalyHook:
    """Stub AnomalyHook — no-op. §0.11"""

    def pre_check(self, run: Run, action: ActionRecord) -> Finding | None:
        return None

    def observe(
        self, run: Run, action: ActionRecord, result: ExecutionResult | None
    ) -> list[Any]:
        return []


class StubProgressHook:
    """Stub ProgressHook — no-op. §0.11"""

    def enqueue(self, run_id: str, event: Any) -> None:
        pass
