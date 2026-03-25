CREATE TABLE scan_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target          TEXT NOT NULL,
    scan_time       TEXT NOT NULL,
    composite_score INTEGER NOT NULL,
    severity        TEXT NOT NULL,
    nmap_score      INTEGER NOT NULL,
    vt_score        INTEGER NOT NULL,
    findings        TEXT,
    nmap_breakdown  TEXT,
    vt_breakdown    TEXT,
    created_at      TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at      TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE port_risks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      INTEGER NOT NULL,
    portid          TEXT NOT NULL,
    service         TEXT,
    state           TEXT,
    risk_tag        TEXT,
    risk_reason     TEXT,
    score           INTEGER NOT NULL,
    findings        TEXT,
    created_at      TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
);

CREATE TABLE vt_results (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          INTEGER NOT NULL,
    total_votes         TEXT,
    total_agents        INTEGER,
    last_analysis_date  TEXT,
    malicious           INTEGER DEFAULT 0,
    suspicious          INTEGER DEFAULT 0,
    harmless            INTEGER DEFAULT 0,
    undetected          INTEGER DEFAULT 0,
    malicious_outlinks  INTEGER DEFAULT 0,
    reputation          INTEGER DEFAULT 0,
    created_at          TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
);
