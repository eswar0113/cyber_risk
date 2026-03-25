-- ============================================================
--  Scanners + Risk Scoring — PostgreSQL Schema
-- ============================================================
-- Run this in pgAdmin Query Tool against your `scanner_db` database.

-- 1. scan_sessions: one row per getScore() call
CREATE TABLE IF NOT EXISTS scan_sessions (
    id              SERIAL PRIMARY KEY,
    target          TEXT NOT NULL,
    scan_time       TIMESTAMPTZ NOT NULL,
    composite_score INTEGER NOT NULL CHECK (composite_score BETWEEN 0 AND 100),
    severity        VARCHAR(10) NOT NULL,
    nmap_score      INTEGER NOT NULL,
    vt_score        INTEGER NOT NULL,
    findings        TEXT[],
    nmap_breakdown  JSONB,
    vt_breakdown    JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- 2. port_risks: one row per port in a scan session
CREATE TABLE IF NOT EXISTS port_risks (
    id          SERIAL PRIMARY KEY,
    session_id  INTEGER NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    portid      TEXT NOT NULL,
    service     TEXT,
    state       TEXT,
    risk_tag    TEXT,
    risk_reason TEXT,
    score       INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    findings    TEXT[],
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- 3. vt_results: one row per VirusTotal scan result
CREATE TABLE IF NOT EXISTS vt_results (
    id                  SERIAL PRIMARY KEY,
    session_id          INTEGER NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    total_votes         JSONB,
    total_agents        INTEGER,
    last_analysis_date  TIMESTAMPTZ,
    malicious           INTEGER DEFAULT 0,
    suspicious          INTEGER DEFAULT 0,
    harmless            INTEGER DEFAULT 0,
    undetected          INTEGER DEFAULT 0,
    malicious_outlinks  INTEGER DEFAULT 0,
    reputation          INTEGER DEFAULT 0,
    created_at          TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_scan_sessions_target   ON scan_sessions(target);
CREATE INDEX IF NOT EXISTS idx_scan_sessions_severity ON scan_sessions(severity);
CREATE INDEX IF NOT EXISTS idx_port_risks_session_id  ON port_risks(session_id);
CREATE INDEX IF NOT EXISTS idx_vt_results_session_id  ON vt_results(session_id);

-- ============================================================
-- Useful SELECT queries
-- ============================================================

-- All scan sessions, most recent first:
-- SELECT id, target, scan_time, composite_score, severity, nmap_score, vt_score
-- FROM scan_sessions ORDER BY scan_time DESC;

-- All scans for a specific target:
-- SELECT * FROM scan_sessions WHERE target = 'demo.testfire.net' ORDER BY scan_time DESC;

-- Port details for a specific session:
-- SELECT portid, service, state, risk_tag, score FROM port_risks WHERE session_id = 1;

-- VirusTotal summary for a specific session:
-- SELECT malicious, suspicious, harmless, reputation, malicious_outlinks
-- FROM vt_results WHERE session_id = 1;

-- High/Critical scans across all targets:
-- SELECT target, scan_time, composite_score, severity
-- FROM scan_sessions WHERE severity IN ('HIGH', 'CRITICAL') ORDER BY composite_score DESC;
