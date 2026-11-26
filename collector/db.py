"""SQLite storage for events, alerts and findings.

Phase 1 uses SQLite so there's zero setup. Two security-minded choices worth
understanding:

1. The events table is APPEND-ONLY. Deleting or editing logs is an attacker's
   first move after a breach, so we only ever INSERT and SELECT - and we back
   that up with triggers that ABORT any UPDATE/DELETE at the database layer.
   (A production system would also use OS permissions / WORM storage and ship
   a copy off-box so a host compromise can't erase the evidence.)

2. Every query is PARAMETERIZED (values passed as `?`, never string-formatted
   into SQL). That's how you avoid SQL injection - a reflex worth keeping even
   when the data comes from your own agents.
"""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional

from .config import DB_PATH
from .models import Event

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT NOT NULL,
    agent_id    TEXT NOT NULL,
    host        TEXT NOT NULL,
    source      TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    user        TEXT,
    source_ip   TEXT,
    process     TEXT,
    message     TEXT,
    raw         TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_lookup
    ON events (event_type, user, source_ip, timestamp);

-- Enforce append-only at the DB layer: refuse edits and deletes outright.
CREATE TRIGGER IF NOT EXISTS events_no_update
BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'events table is append-only'); END;

CREATE TRIGGER IF NOT EXISTS events_no_delete
BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'events table is append-only'); END;

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at  TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    technique   TEXT,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    detail      TEXT NOT NULL,
    entity      TEXT NOT NULL DEFAULT ''
);

-- FINDINGS are posture problems ("the TLS cert expires in 5 days"). Unlike
-- alerts they have a lifecycle: open while the problem exists, resolved once a
-- check sees it fixed. Rows are kept after resolving, as history.
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     TEXT NOT NULL,
    entity      TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    detail      TEXT NOT NULL,
    fix         TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('open', 'resolved')),
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    resolved_at TEXT
);
-- At most ONE open finding per rule + entity.
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_open
    ON findings (rule_id, entity) WHERE status = 'open';
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connect() -> Iterator[sqlite3.Connection]:
    """`with db.connect() as conn:` - commits on success, rolls back on error,
    and always CLOSES (sqlite3's own context manager doesn't close, which
    leaks a connection per request in a long-running server)."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        # WAL lets the digest/API read while ingest writes, and survives
        # crashes better - the right default for a small always-on server.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_SCHEMA)
        # Migrate DBs created before alerts had `entity` / `fix` columns.
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(alerts)")}
        for col in ("entity", "fix"):
            if col not in cols:
                conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts (rule_id, entity, created_at)"
        )


def insert_event(conn: sqlite3.Connection, event: Event) -> int:
    cur = conn.execute(
        """INSERT INTO events (timestamp, agent_id, host, source, event_type,
                               user, source_ip, process, message, raw, received_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            event.timestamp.isoformat(),
            event.agent_id,
            event.host,
            event.source,
            event.event_type,
            event.user,
            event.source_ip,
            event.process,
            event.message,
            json.dumps(event.raw),
            _now(),
        ),
    )
    return cur.lastrowid


def count_recent(
    conn: sqlite3.Connection,
    event_type: str,
    since: datetime,
    user: Optional[str] = None,
    source_ip: Optional[str] = None,
) -> int:
    """How many events of a type happened since `since`, optionally filtered.

    Detections call this to ask questions like "how many auth failures for
    this account in the last 5 minutes?" - i.e. the store is also the memory
    the detection logic reasons over.
    """
    query = "SELECT COUNT(*) FROM events WHERE event_type = ? AND timestamp >= ?"
    params: list = [event_type, since.isoformat()]
    if user is not None:
        query += " AND user = ?"
        params.append(user)
    if source_ip is not None:
        query += " AND source_ip = ?"
        params.append(source_ip)
    return conn.execute(query, params).fetchone()[0]


def insert_alert(
    conn: sqlite3.Connection,
    rule_id: str,
    technique: str,
    severity: str,
    title: str,
    detail: str,
    entity: str = "",
    fix: str = "",
) -> None:
    conn.execute(
        """INSERT INTO alerts (created_at, rule_id, technique, severity, title, detail, entity, fix)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (_now(), rule_id, technique, severity, title, detail, entity, fix),
    )


# --- findings ---------------------------------------------------------------

def get_open_finding(conn: sqlite3.Connection, rule_id: str, entity: str) -> Optional[sqlite3.Row]:
    return conn.execute(
        "SELECT * FROM findings WHERE rule_id = ? AND entity = ? AND status = 'open'",
        (rule_id, entity),
    ).fetchone()


def open_finding(conn, rule_id, entity, severity, title, detail, fix) -> None:
    now = _now()
    conn.execute(
        """INSERT INTO findings (rule_id, entity, severity, title, detail, fix,
                                 status, first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?)""",
        (rule_id, entity, severity, title, detail, fix, now, now),
    )


def refresh_finding(conn, finding_id, severity, title, detail, fix) -> None:
    conn.execute(
        """UPDATE findings SET severity = ?, title = ?, detail = ?, fix = ?, last_seen = ?
           WHERE id = ?""",
        (severity, title, detail, fix, _now(), finding_id),
    )


def resolve_finding(conn: sqlite3.Connection, finding_id: int) -> None:
    now = _now()
    conn.execute(
        "UPDATE findings SET status = 'resolved', resolved_at = ?, last_seen = ? WHERE id = ?",
        (now, now, finding_id),
    )


def list_findings(
    conn: sqlite3.Connection, status: Optional[str] = "open", resolved_since: Optional[datetime] = None
) -> list[dict]:
    """Open findings (worst first), or findings resolved since a time."""
    if resolved_since is not None:
        rows = conn.execute(
            "SELECT * FROM findings WHERE status = 'resolved' AND resolved_at >= ? ORDER BY resolved_at DESC",
            (resolved_since.isoformat(),),
        )
    elif status:
        rows = conn.execute(
            """SELECT * FROM findings WHERE status = ?
               ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                      WHEN 'medium' THEN 2 ELSE 3 END, first_seen""",
            (status,),
        )
    else:
        rows = conn.execute("SELECT * FROM findings ORDER BY id DESC")
    return [dict(r) for r in rows]


def list_alerts(conn: sqlite3.Connection, since: datetime) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM alerts WHERE created_at >= ? ORDER BY id DESC", (since.isoformat(),)
    )
    return [dict(r) for r in rows]


def recent_alert_exists(
    conn: sqlite3.Connection, rule_id: str, entity: str, since: datetime
) -> bool:
    """Has this rule already alerted on this entity since `since`? (de-dup)"""
    row = conn.execute(
        "SELECT 1 FROM alerts WHERE rule_id = ? AND entity = ? AND created_at >= ? LIMIT 1",
        (rule_id, entity, since.isoformat()),
    ).fetchone()
    return row is not None
