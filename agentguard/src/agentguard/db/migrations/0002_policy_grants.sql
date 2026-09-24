-- Migration 0002: Policy and Grants tables

CREATE TABLE policies (
    policy_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    yaml_text TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    comment TEXT,
    is_active INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (policy_id, version)
);

CREATE TABLE grants (
    grant_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    scope TEXT NOT NULL,
    match_json TEXT NOT NULL CHECK (json_valid(match_json)),
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    max_uses INTEGER NOT NULL,
    uses INTEGER NOT NULL DEFAULT 0,
    created_by TEXT NOT NULL,
    source TEXT NOT NULL,
    approval_id TEXT,
    note TEXT
);

CREATE INDEX idx_grants_run ON grants(run_id, status, expires_at);

-- Add runs columns for Policy and Grants
ALTER TABLE runs ADD COLUMN policy_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE runs ADD COLUMN overlay_yaml TEXT;
ALTER TABLE runs ADD COLUMN overlay_sha256 TEXT;
ALTER TABLE runs ADD COLUMN pause_reason TEXT;
ALTER TABLE runs ADD COLUMN ws_epoch INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN outcome_verified INTEGER;
ALTER TABLE runs ADD COLUMN breaker_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE runs ADD COLUMN pending_advisories_json TEXT NOT NULL DEFAULT '[]';
