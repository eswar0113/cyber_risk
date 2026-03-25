import os
import json
import datetime
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()

# ── Connection settings from .env ─────────────────────────────────────────────
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", 5432))
DB_NAME = os.getenv("DB_NAME", "scanner_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")


def get_connection():
    """Returns a new psycopg2 connection to PostgreSQL."""
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _dt_now() -> str:
    return datetime.datetime.utcnow().isoformat() + "Z"


def _to_pg_timestamp(iso_str: str | None):
    """Convert an ISO timestamp string to a Python datetime (psycopg2 accepts datetime)."""
    if not iso_str:
        return None
    try:
        return datetime.datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
    except Exception:
        return None


# ── CRUD ──────────────────────────────────────────────────────────────────────

def save_scan(report_dict: dict, vt_data: dict) -> int:
    """
    Saves a complete scan (session + ports + VT results) into PostgreSQL transactionally.
    Returns the new session_id.
    """
    target          = report_dict.get("target", "unknown")
    scan_time       = _to_pg_timestamp(report_dict.get("scan_time")) or datetime.datetime.utcnow()
    composite_score = int(report_dict.get("composite_score", 0))
    severity        = report_dict.get("severity", "LOW")
    findings        = report_dict.get("findings", [])

    breakdown  = report_dict.get("breakdown", {})
    nmap_bd    = breakdown.get("nmap", {})
    vt_bd      = breakdown.get("vt", {})
    nmap_score = int(nmap_bd.get("port_avg", 0))
    vt_score   = int(report_dict.get("vt_score", vt_bd.get("score", 0)))

    conn = get_connection()
    try:
        with conn:  # transaction — auto-commits on success, rolls back on exception
            with conn.cursor() as cur:

                # 1. Insert scan session
                cur.execute(
                    """
                    INSERT INTO scan_sessions
                        (target, scan_time, composite_score, severity,
                         nmap_score, vt_score, findings, nmap_breakdown, vt_breakdown)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        target,
                        scan_time,
                        composite_score,
                        severity,
                        nmap_score,
                        vt_score,
                        findings,                        # list  → PostgreSQL TEXT[]
                        json.dumps(nmap_bd),             # dict  → JSONB
                        json.dumps(vt_bd),               # dict  → JSONB
                    ),
                )
                session_id = cur.fetchone()[0]

                # 2. Insert port risks
                ports = report_dict.get("port_results", report_dict.get("ports", []))
                if ports:
                    for port in ports:
                        p = port if isinstance(port, dict) else (port.__dict__ if hasattr(port, "__dict__") else {})
                        cur.execute(
                            """
                            INSERT INTO port_risks
                                (session_id, portid, service, state,
                                 risk_tag, risk_reason, score, findings)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                session_id,
                                str(p.get("portid", "")),
                                p.get("service", ""),
                                p.get("state", ""),
                                p.get("risk_tag", ""),
                                p.get("risk_reason", ""),
                                int(p.get("score", 0)),
                                p.get("findings", []),   # list → TEXT[]
                            ),
                        )

                # 3. Insert VirusTotal results
                if vt_data and isinstance(vt_data, dict) and "data" in vt_data:
                    attrs  = vt_data["data"].get("attributes", {})
                    stats  = attrs.get("last_analysis_stats", {})
                    votes  = attrs.get("total_votes", {})
                    agents = sum(stats.values()) if stats else 0

                    raw_date = attrs.get("last_analysis_date")
                    analysis_date = None
                    if raw_date:
                        try:
                            analysis_date = datetime.datetime.utcfromtimestamp(raw_date).replace(
                                tzinfo=datetime.timezone.utc
                            )
                        except Exception:
                            analysis_date = None

                    cur.execute(
                        """
                        INSERT INTO vt_results
                            (session_id, total_votes, total_agents, last_analysis_date,
                             malicious, suspicious, harmless, undetected,
                             malicious_outlinks, reputation)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            session_id,
                            json.dumps(votes),           # dict → JSONB
                            agents,
                            analysis_date,
                            stats.get("malicious", 0),
                            stats.get("suspicious", 0),
                            stats.get("harmless", 0),
                            stats.get("undetected", 0),
                            attrs.get("malicious_outlinks", 0),
                            attrs.get("reputation", 0),
                        ),
                    )

        print(f"[DB] Scan saved to PostgreSQL — session_id={session_id}  target={target}")
        return session_id

    except Exception as e:
        print(f"[DB] Error saving scan to PostgreSQL: {e}")
        raise
    finally:
        conn.close()


def get_all_scans() -> list:
    """Returns all scan sessions, most recent first."""
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM scan_sessions ORDER BY scan_time DESC")
            rows = [dict(r) for r in cur.fetchall()]
        return rows
    finally:
        conn.close()


def get_scan_by_id(session_id: int) -> dict | None:
    """Returns a session dict with its port_risks and vt_results, or None if not found."""
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM scan_sessions WHERE id = %s", (session_id,))
            session = cur.fetchone()
            if not session:
                return None
            session = dict(session)

            cur.execute("SELECT * FROM port_risks WHERE session_id = %s", (session_id,))
            ports = [dict(r) for r in cur.fetchall()]

            cur.execute("SELECT * FROM vt_results WHERE session_id = %s", (session_id,))
            vt = cur.fetchone()

        return {
            "session": session,
            "ports": ports,
            "vt_results": dict(vt) if vt else None,
        }
    finally:
        conn.close()


def get_scans_by_target(target: str) -> list:
    """Returns all scan sessions for a given target, most recent first."""
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM scan_sessions WHERE target = %s ORDER BY scan_time DESC",
                (target,),
            )
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def update_scan_severity(session_id: int, new_severity: str) -> bool:
    """Updates the severity label for an existing session. Returns True on success."""
    conn = get_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE scan_sessions SET severity = %s, updated_at = NOW() WHERE id = %s",
                    (new_severity, session_id),
                )
                return cur.rowcount == 1
    finally:
        conn.close()


def delete_scan(session_id: int) -> bool:
    """Deletes a session and its child rows (cascade). Returns True on success."""
    conn = get_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM scan_sessions WHERE id = %s", (session_id,))
                return cur.rowcount == 1
    finally:
        conn.close()
