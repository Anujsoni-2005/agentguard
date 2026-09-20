-- AgentGuard schema — §1.3 + Part 3 §B10 + Part 4 §C1
-- PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

-- ═══════════════════════════════════════════════════════════════════════
-- RUNS — §1.3 + §B10
-- ═══════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    task_json TEXT NOT NULL CHECK (json_valid(task_json)),
    budgets_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(budgets_json)),
    policy_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    ended_at TEXT,
    next_seq INTEGER NOT NULL DEFAULT 1,
    counters_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(counters_json)),
    taint_json TEXT NOT NULL DEFAULT '{"level":0,"sources":[]}' CHECK (json_valid(taint_json)),
    halt_reason TEXT,
    pause_reason TEXT,
    unanswered_approvals INTEGER NOT NULL DEFAULT 0,
    sandbox_json TEXT NOT NULL DEFAULT '{}',
    -- Part 3 §B10
    policy_version INTEGER NOT NULL DEFAULT 1,
    overlay_yaml TEXT,
    overlay_sha256 TEXT,
    ws_epoch INTEGER NOT NULL DEFAULT 0,
    outcome_verified INTEGER,
    breaker_json TEXT NOT NULL DEFAULT '{}',
    pending_advisories_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status, created_at);

-- ═══════════════════════════════════════════════════════════════════════
-- ACTIONS — §1.3
-- ═══════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    seq INTEGER NOT NULL,
    client_action_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    proposal_json TEXT NOT NULL CHECK (json_valid(proposal_json)),
    params_hash TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    verdict TEXT,
    next_step TEXT,
    risk_score INTEGER,
    reason_codes_json TEXT NOT NULL DEFAULT '[]',
    findings_json TEXT NOT NULL DEFAULT '[]',
    decision_ms REAL,
    received_at TEXT NOT NULL,
    decided_at TEXT,
    executed_at TEXT,
    finished_at TEXT,
    approval_id TEXT,
    grant_id TEXT,
    result_json TEXT CHECK (result_json IS NULL OR json_valid(result_json)),
    ledger_idx_verdict INTEGER,
    UNIQUE (run_id, seq),
    UNIQUE (run_id, client_action_id)
);
CREATE INDEX IF NOT EXISTS idx_actions_run_seq ON actions(run_id, seq);
CREATE INDEX IF NOT EXISTS idx_actions_fp ON actions(run_id, fingerprint, seq);
CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(status);

-- ═══════════════════════════════════════════════════════════════════════
-- APPROVALS — §1.3
-- ═══════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    action_id TEXT NOT NULL REFERENCES actions(action_id),
    status TEXT NOT NULL,
    action_hash TEXT NOT NULL,
    action_type TEXT,
    summary TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    artifacts_json TEXT NOT NULL DEFAULT '{}',
    requested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    decided_at TEXT,
    decided_by TEXT,
    note TEXT,
    grant_request_json TEXT,
    grant_options_json TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status, expires_at);

-- ═══════════════════════════════════════════════════════════════════════
-- THOUGHTS — §1.3
-- ═══════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS thoughts (
    thought_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    ts TEXT NOT NULL,
    kind TEXT NOT NULL,
    text TEXT NOT NULL,
    meta_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_thoughts_run ON thoughts(run_id, thought_id);

-- ═══════════════════════════════════════════════════════════════════════
-- ACTION OUTPUTS — Part 4 §C1
-- ═══════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS action_outputs (
    action_id TEXT NOT NULL REFERENCES actions(action_id),
    stream TEXT NOT NULL CHECK (stream IN ('stdout','stderr','body')),
    text TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    truncated INTEGER NOT NULL DEFAULT 0,
    UNIQUE(action_id, stream)
);

-- ═══════════════════════════════════════════════════════════════════════
-- LEDGER INDEX — §8.3
-- ═══════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS ledger_index (
    idx INTEGER PRIMARY KEY,
    run_id TEXT,
    event_type TEXT NOT NULL,
    ts TEXT NOT NULL,
    action_id TEXT,
    segment_file TEXT NOT NULL,
    byte_offset INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_run ON ledger_index(run_id, idx);
CREATE INDEX IF NOT EXISTS idx_ledger_type ON ledger_index(event_type, idx);
