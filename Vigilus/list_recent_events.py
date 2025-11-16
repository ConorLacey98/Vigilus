from datetime import datetime, timedelta
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "osint.db"


def main(days: int = 7):
    since = datetime.utcnow() - timedelta(days=days)
    since_iso = since.isoformat()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, vendor, cves, severity, summary, created_at
        FROM events
        WHERE created_at >= ?
        ORDER BY created_at DESC
        """,
        (since_iso,),
    )
    rows = cur.fetchall()
    conn.close()

    print(f"Events in the last {days} days:")
    for r in rows:
        print("-" * 80)
        print(f"ID: {r[0]}")
        print(f"Vendor: {r[1]}")
        print(f"CVEs: {r[2]}")
        print(f"Severity: {r[3]}")
        print(f"Summary: {r[4]}")
        print(f"Created at: {r[5]}")


if __name__ == "__main__":
    main()
