from typing import List, Dict, Any
from datetime import datetime, timezone
import feedparser


def fetch_rss_feed(name: str, url: str) -> List[Dict[str, Any]]:
    """
    Fetch a single RSS feed and return a list of normalized items.
    Each item:
      source: "rss"
      external_id: link or guid
      title, text, url, timestamp
    """
    feed = feedparser.parse(url)
    items: List[Dict[str, Any]] = []

    for entry in feed.entries:
        link = entry.get("link", "")
        guid = getattr(entry, "id", link)  # fallback to link as external_id

        published = (
            entry.get("published")
            or entry.get("updated")
            or datetime.now(timezone.utc).isoformat()
        )

        summary = entry.get("summary", "")
        title = entry.get("title", "")

        items.append(
            {
                "source": f"rss:{name}",
                "external_id": guid,
                "title": title,
                "text": summary,
                "url": link,
                "timestamp": published,
                "extra_json": None,  # placeholder for future extra data
            }
        )

    return items


def fetch_all_rss_feeds(rss_config: list) -> List[Dict[str, Any]]:
    all_items: List[Dict[str, Any]] = []
    for feed_cfg in rss_config:
        name = feed_cfg["name"]
        url = feed_cfg["url"]
        try:
            items = fetch_rss_feed(name, url)
            all_items.extend(items)
        except Exception as e:
            print(f"[RSS] Error fetching {name} ({url}): {e}")
    return all_items
