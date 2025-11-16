# core/db.py
import sqlite3
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime

DB_PATH = Path(__file__).resolve().parent.parent / "osint.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_connection()
    cur = conn.cursor()

    # raw_items: collected OSINT
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS raw_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            external_id TEXT NOT NULL,
            title TEXT,
            text TEXT,
            url TEXT,
            timestamp TEXT,
            created_at TEXT NOT NULL,
            extra_json TEXT,
            UNIQUE(source, external_id)
        )
        """
    )

    # events: now richer with vuln_type, exploitation_status, risk_score, is_kev
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor TEXT,
            product TEXT,
            cves TEXT,               -- comma-separated string for now
            severity TEXT,
            summary TEXT,
            vuln_type TEXT,          -- e.g. RCE, auth_bypass, priv_esc, dos, info_disc
            exploitation_status TEXT, -- e.g. known_exploited, poc_available, under_attack, unknown
            risk_score INTEGER,      -- 0-100
            is_kev INTEGER,          -- 0/1
            created_at TEXT NOT NULL
        )
        """
    )

    # event_sources: link events back to raw_items
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS event_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            raw_item_id INTEGER NOT NULL,
            FOREIGN KEY (event_id) REFERENCES events(id),
            FOREIGN KEY (raw_item_id) REFERENCES raw_items(id)
        )
        """
    )

    # meta: key/value store
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )

    conn.commit()
    conn.close()


def insert_raw_item(item: Dict[str, Any]) -> bool:
    conn = get_connection()
    cur = conn.cursor()
    created_at = datetime.utcnow().isoformat()

    try:
        cur.execute(
            """
            INSERT INTO raw_items (source, external_id, title, text, url, timestamp, created_at, extra_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                item.get("source"),
                item.get("external_id"),
                item.get("title"),
                item.get("text"),
                item.get("url"),
                item.get("timestamp"),
                created_at,
                item.get("extra_json"),
            ),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


# -------- meta helpers --------

def get_meta(key: str) -> Optional[str]:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT value FROM meta WHERE key = ?", (key,))
    row = cur.fetchone()
    conn.close()
    return row["value"] if row else None


def set_meta(key: str, value: str) -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO meta (key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (key, value),
    )
    conn.commit()
    conn.close()


# -------- event helpers --------

def insert_event(event: Dict[str, Any]) -> int:
    """
    event: {
      vendor, product, cves(list/str), severity, summary,
      vuln_type, exploitation_status, risk_score(int), is_kev(bool/int)
    }
    returns new event_id
    """
    conn = get_connection()
    cur = conn.cursor()

    cves = event.get("cves")
    if isinstance(cves, list):
        cves_str = ",".join(cves)
    else:
        cves_str = cves or ""

    created_at = datetime.utcnow().isoformat()

    cur.execute(
        """
        INSERT INTO events (
            vendor, product, cves, severity, summary,
            vuln_type, exploitation_status, risk_score, is_kev, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.get("vendor"),
            event.get("product"),
            cves_str,
            event.get("severity"),
            event.get("summary"),
            event.get("vuln_type"),
            event.get("exploitation_status"),
            event.get("risk_score"),
            int(bool(event.get("is_kev", False))),
            created_at,
        ),
    )
    event_id = cur.lastrowid
    conn.commit()
    conn.close()
    return event_id


def link_event_to_raw_item(event_id: int, raw_item_id: int) -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO event_sources (event_id, raw_item_id)
        VALUES (?, ?)
        """,
        (event_id, raw_item_id),
    )
    conn.commit()
    conn.close()


def fetch_unprocessed_raw_items(batch_size: int = 200) -> List[sqlite3.Row]:
    """
    Fetch raw_items with id > last_processed_raw_item_id (tracked in meta).
    """
    last_id_str = get_meta("last_processed_raw_item_id")
    last_id = int(last_id_str) if last_id_str is not None else 0

    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT * FROM raw_items
        WHERE id > ?
        ORDER BY id ASC
        LIMIT ?
        """,
        (last_id, batch_size),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def update_last_processed_raw_item_id(new_last_id: int) -> None:
    set_meta("last_processed_raw_item_id", str(new_last_id))
