import yaml
from pathlib import Path

from core.db import init_db, insert_raw_item
from collectors.rss_collector import fetch_all_rss_feeds
from collectors.cisa_kev_collector import fetch_cisa_kev


CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main():
    config = load_config()

    print("[*] Initializing database (if needed)...")
    init_db()

    total_inserted = 0
    total_seen = 0

    # RSS feeds
    rss_config = config.get("rss_feeds", [])
    if rss_config:
        print(f"[*] Fetching RSS feeds ({len(rss_config)} configured)...")
        rss_items = fetch_all_rss_feeds(rss_config)
        print(f"    Retrieved {len(rss_items)} RSS items.")
        for item in rss_items:
            total_seen += 1
            if insert_raw_item(item):
                total_inserted += 1

    # CISA KEV
    cisa_cfg = config.get("cisa_kev", {})
    if cisa_cfg.get("enabled", False):
        kev_url = cisa_cfg.get("url")
        if kev_url:
            print("[*] Fetching CISA KEV...")
            try:
                kev_items = fetch_cisa_kev(kev_url)
                print(f"    Retrieved {len(kev_items)} KEV entries.")
                for item in kev_items:
                    total_seen += 1
                    if insert_raw_item(item):
                        total_inserted += 1
            except Exception as e:
                print(f"[CISA KEV] Error: {e}")

    print(f"[*] Done. Seen: {total_seen}, newly inserted: {total_inserted}")


if __name__ == "__main__":
    main()
