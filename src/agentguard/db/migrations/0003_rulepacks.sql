-- Migration 0003: Rule Packs and Feeds

CREATE TABLE trust_keys (
    key_id TEXT PRIMARY KEY,
    publisher TEXT NOT NULL,
    public_key_b64 TEXT NOT NULL,
    capabilities_json TEXT NOT NULL,
    allowed_pack_ids_json TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT,
    revoked INTEGER NOT NULL DEFAULT 0,
    revoked_at TEXT,
    added_by TEXT NOT NULL,
    added_at TEXT NOT NULL
);

CREATE TABLE rulepacks (
    pack_id TEXT NOT NULL,
    version TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    key_id TEXT NOT NULL,
    status TEXT NOT NULL,
    status_reason TEXT,
    installed_at TEXT NOT NULL,
    expires_at TEXT,
    rule_count INTEGER NOT NULL,
    path TEXT NOT NULL,
    meta_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (pack_id, version)
);

CREATE TABLE rulepack_active (
    pack_id TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    activated_at TEXT NOT NULL
);

CREATE TABLE feeds (
    feed_id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    pack_id TEXT NOT NULL,
    channel TEXT NOT NULL,
    interval_s INTEGER NOT NULL,
    enabled INTEGER NOT NULL,
    etag TEXT,
    last_modified TEXT,
    last_checked_at TEXT,
    last_success_at TEXT,
    last_error TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL
);

CREATE TABLE rule_hits (
    rule_id TEXT NOT NULL,
    day TEXT NOT NULL,
    action_type TEXT NOT NULL,
    verdict TEXT NOT NULL,
    hits INTEGER NOT NULL,
    PRIMARY KEY (rule_id, day, action_type, verdict)
);
