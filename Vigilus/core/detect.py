import re
from typing import Dict, Any, List

from .db import (
    fetch_unprocessed_raw_items,
    update_last_processed_raw_item_id,
    insert_event,
    link_event_to_raw_item,
)

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def extract_cves(text: str) -> List[str]:
    return list({m.upper() for m in CVE_REGEX.findall(text or "")})


def score_item(
    item: Dict[str, Any],
    vendors: List[str],
    high_terms: List[str],
    medium_terms: List[str],
) -> Dict[str, Any]:
    """
    Return a dict with keys:
      should_create_event: bool
      severity: "HIGH"|"MEDIUM"|None
      vendor, product, cves, summary
    Or should_create_event=False if it's not interesting enough.
    """
    title = (item.get("title") or "")[:300]
    text = item.get("text") or ""
    full = f"{title}\n{text}".lower()

    # vendor detection (simple substring match)
    matched_vendor = None
    for v in vendors:
        if v.lower() in full:
            matched_vendor = v
            break

    cves = extract_cves(full)

    high_hit = any(term.lower() in full for term in high_terms)
    med_hit = any(term.lower() in full for term in medium_terms)

    # Decide if we care
    if not matched_vendor and not cves:
        # For now, ignore anything with no vendor and no CVE.
        return {"should_create_event": False}

    severity = None
    if matched_vendor and (high_hit or (cves and high_hit)):
        severity = "HIGH"
    elif matched_vendor and (cves or med_hit):
        severity = "MEDIUM"
    elif cves and high_hit:
        severity = "MEDIUM"
    else:
        # You can relax this later if you want more noise
        return {"should_create_event": False}

    summary = title or (text[:200] + "...")
    return {
        "should_create_event": True,
        "severity": severity,
        "vendor": matched_vendor,
        "product": None,         # We can improve this later
        "cves": cves,
        "summary": summary,
    }


def run_detection(config: Dict[str, Any], batch_size: int = 200) -> None:
    detection_cfg = config.get("detection", {})
    vendors = detection_cfg.get("vendors", [])
    high_terms = detection_cfg.get("high_risk_terms", [])
    medium_terms = detection_cfg.get("medium_risk_terms", [])

    if not vendors and not high_terms and not medium_terms:
        print("[detect] No detection config found, nothing to do.")
        return

    print("[detect] Fetching unprocessed raw items...")
    rows = fetch_unprocessed_raw_items(batch_size=batch_size)
    if not rows:
        print("[detect] No new raw items to process.")
        return

    print(f"[detect] Processing {len(rows)} raw items...")
    max_id_seen = 0
    events_created = 0

    for row in rows:
        item = dict(row)
        max_id_seen = max(max_id_seen, item["id"])

        scored = score_item(
            item=item,
            vendors=vendors,
            high_terms=high_terms,
            medium_terms=medium_terms,
        )

        if not scored.get("should_create_event"):
            continue

        event_data = {
            "vendor": scored.get("vendor"),
            "product": scored.get("product"),
            "cves": scored.get("cves", []),
            "severity": scored.get("severity"),
            "summary": scored.get("summary"),
        }

        event_id = insert_event(event_data)
        link_event_to_raw_item(event_id, item["id"])
        events_created += 1

    if max_id_seen:
        update_last_processed_raw_item_id(max_id_seen)

    print(f"[detect] Done. Events created: {events_created}, last_processed_raw_item_id: {max_id_seen}")
