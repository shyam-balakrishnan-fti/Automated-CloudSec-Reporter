-- schema.sql
-- Ground truth for all table definitions.
-- Applied once at startup via db/init.py if tables don't exist.

-- ── Engagements ───────────────────────────────────────────────────────
-- Top-level entity. One engagement per client assessment.
-- Multiple runs can exist under one engagement (e.g. re-scan after remediation).

CREATE TABLE IF NOT EXISTS engagements (
    id              TEXT PRIMARY KEY,           -- UUID
    client_name     TEXT NOT NULL,
    assessment_period TEXT NOT NULL,            -- e.g. "July 2026"
    analyst         TEXT NOT NULL DEFAULT '',
    pipeline_type   TEXT NOT NULL,              -- "prowler" | "scubagear" | "both"
    created_at      TEXT NOT NULL,              -- ISO-8601
    archived_at     TEXT,                       -- NULL = active
    notes           TEXT NOT NULL DEFAULT ''
);

-- ── Runs ─────────────────────────────────────────────────────────────
-- One execution of one pipeline for one engagement.

CREATE TABLE IF NOT EXISTS runs (
    id              TEXT PRIMARY KEY,           -- UUID
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    pipeline        TEXT NOT NULL,              -- "prowler" | "scubagear"
    status          TEXT NOT NULL DEFAULT 'pending',
    -- pending | running | awaiting_review | enriching | complete | failed | cancelled

    -- Input
    input_file      TEXT NOT NULL DEFAULT '',   -- absolute path to scanner output file
    input_format    TEXT NOT NULL DEFAULT 'auto', -- auto | csv | xlsx | json
    tenant_id       TEXT NOT NULL DEFAULT '',   -- ScubaGear only

    -- Config snapshot (written before run starts)
    config_path     TEXT NOT NULL DEFAULT '',   -- absolute path to config.toml used
    output_dir      TEXT NOT NULL DEFAULT '',   -- absolute path to output directory

    -- AWS credentials (session-scoped, never persisted to disk by the GUI)
    -- The credential_source tells the subprocess launcher how to auth.
    credential_source TEXT NOT NULL DEFAULT 'profile',  -- "profile" | "keys"
    aws_profile     TEXT NOT NULL DEFAULT '',
    aws_region      TEXT NOT NULL DEFAULT 'ap-southeast-2',

    -- Flags
    skip_review     INTEGER NOT NULL DEFAULT 0,
    skip_llm        INTEGER NOT NULL DEFAULT 0,

    -- Timing
    created_at      TEXT NOT NULL,
    started_at      TEXT,
    completed_at    TEXT,

    -- Results summary (populated on completion)
    findings_total  INTEGER,
    findings_included INTEGER,
    groups_total    INTEGER,
    groups_enriched INTEGER,
    risk_high       INTEGER,
    risk_medium     INTEGER,
    risk_low        INTEGER,
    llm_failures    INTEGER,

    -- Output
    excel_path      TEXT                        -- absolute path to final .xlsx
);

-- ── RunLogs ──────────────────────────────────────────────────────────
-- Append-only stdout/stderr from the subprocess. Used for log replay.

CREATE TABLE IF NOT EXISTS run_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT NOT NULL REFERENCES runs(id),
    ts              TEXT NOT NULL,              -- ISO-8601 with ms
    stream          TEXT NOT NULL DEFAULT 'stdout', -- "stdout" | "stderr" | "gui"
    line            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_run_logs_run_id ON run_logs(run_id);
CREATE INDEX IF NOT EXISTS idx_runs_engagement ON runs(engagement_id);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);

-- ── Scans ─────────────────────────────────────────────────────────────
-- One Prowler execution against one cloud environment.
-- Separate from runs — a scan produces raw output that can be used
-- by multiple report runs without re-scanning.

CREATE TABLE IF NOT EXISTS scans (
    id              TEXT PRIMARY KEY,           -- UUID
    engagement_id   TEXT NOT NULL REFERENCES engagements(id),
    provider        TEXT NOT NULL,              -- "aws" | "azure" | "scubagear"
    scan_type       TEXT NOT NULL DEFAULT 'prowler_aws',
    -- "prowler_aws" | "prowler_azure" | "scubagear"
    status          TEXT NOT NULL DEFAULT 'pending',
    -- pending | running | complete | failed | cancelled

    -- Scan credentials (session-scoped — raw secrets never stored here)
    credential_source TEXT NOT NULL DEFAULT 'keys', -- "keys" | "profile"
    aws_profile     TEXT NOT NULL DEFAULT '',   -- if credential_source = profile
    scan_region     TEXT NOT NULL DEFAULT '',   -- AWS region to scan
    scan_account_id TEXT NOT NULL DEFAULT '',   -- AWS account ID (informational)

    -- Azure only (injected as env vars, never stored — just metadata)
    azure_tenant_id TEXT NOT NULL DEFAULT '',
    azure_client_id TEXT NOT NULL DEFAULT '',
    azure_subscription_id TEXT NOT NULL DEFAULT '', -- blank = all subscriptions

    -- Scope (optional — blank means full scan)
    resource_scope  TEXT NOT NULL DEFAULT '',   -- JSON array of ARNs / resource IDs
    services_scope  TEXT NOT NULL DEFAULT '',   -- JSON array of service names (e.g. ["iam","s3"])

    -- Output
    output_dir      TEXT NOT NULL DEFAULT '',   -- directory containing scan output files
    output_file     TEXT NOT NULL DEFAULT '',   -- path to primary CSV/JSON output

    -- Timing
    created_at      TEXT NOT NULL,
    started_at      TEXT,
    completed_at    TEXT,

    -- Results
    findings_count  INTEGER,                    -- total raw findings before filtering
    duration_secs   INTEGER                     -- wall clock seconds
);

-- ── ScanLogs ──────────────────────────────────────────────────────────
-- Append-only stdout/stderr from the Prowler subprocess.

CREATE TABLE IF NOT EXISTS scan_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         TEXT NOT NULL REFERENCES scans(id),
    ts              TEXT NOT NULL,
    stream          TEXT NOT NULL DEFAULT 'stdout',
    line            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scan_logs_scan_id ON scan_logs(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_engagement  ON scans(engagement_id);
CREATE INDEX IF NOT EXISTS idx_scans_status      ON scans(status);