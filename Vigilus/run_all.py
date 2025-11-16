from pathlib import Path
import yaml

from core.db import init_db
from collectors.rss_collector import fetch_all_rss_feeds
from collectors.cisa_kev_collector import fetch_cisa_kev
from core.db import insert_raw_item
from core.detect import run_detection

CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def run_collectors_only(config):
    total_seen = 0
    total_inserted = 0

    rss_config = config.get("rss_feeds", [])
    if rss_config:
        print(f"[*] Fetching RSS feeds ({len(rss_config)} configured)...")
        from collectors.rss_collector import fetch_all_rss_feeds
        rss_items = fetch_all_rss_feeds(rss_config)
        print(f"    Retrieved {len(rss_items)} RSS items.")
        for item in rss_items:
            total_seen += 1
            if insert_raw_item(item):
                total_inserted += 1

    cisa_cfg = config.get("cisa_kev", {})
    if cisa_cfg.get("enabled", False):
        kev_url = cisa_cfg.get("url")
        if kev_url:
            print("[*] Fetching CISA KEV...")
            from collectors.cisa_kev_collector import fetch_cisa_kev
            kev_items = fetch_cisa_kev(kev_url)
            print(f"    Retrieved {len(kev_items)} KEV entries.")
            for item in kev_items:
                total_seen += 1
                if insert_raw_item(item):
                    total_inserted += 1

    print(f"[*] Collector done. Seen: {total_seen}, newly inserted: {total_inserted}")


def main():
    print("[*] Initializing DB...")
    init_db()
    config = load_config()

    run_collectors_only(config)
    run_detection(config=config, batch_size=200)


if __name__ == "__main__":
    main()
