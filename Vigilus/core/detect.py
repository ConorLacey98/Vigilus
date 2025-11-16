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


def classify_vuln_type(full_text: str) -> str:
    ft = full_text.lower()

    if any(k in ft for k in ["remote code execution", "rce", "execute arbitrary code"]):
        return "RCE"
    if any(k in ft for k in ["auth bypass", "authentication bypass", "bypass authentication", "unauthenticated access"]):
        return "auth_bypass"
    if any(k in ft for k in ["privilege escalation", "elevation of privilege", "escalate privileges", "eop"]):
        return "priv_esc"
    if any(k in ft for k in ["denial of service", "dos", "service unavailable", "crash the service"]):
        return "dos"
    if any(k in ft for k in ["information disclosure", "info disclosure", "leak information", "data exposure"]):
        return "info_disc"

    return "unknown"


def classify_exploitation_status(full_text: str, is_kev: bool) -> str:
    ft = full_text.lower()

    # KEV usually implies known exploitation in the wild
    if is_kev:
        return "known_exploited"

    if any(k in ft for k in ["actively exploited", "exploited in the wild", "in the wild", "under active exploitation"]):
        return "known_exploited"

    if any(k in ft for k in ["proof of concept", "poc released", "exploit code", "exploit available"]):
        return "poc_available"

    if any(k in ft for k in ["under attack", "targeted attacks", "observed exploitation", "being exploited"]):
        return "under_attack"

    return "unknown"


def compute_risk_score(
    severity: str,
    vuln_type: str,
    exploitation_status: str,
    is_kev: bool,
    has_cves: bool,
) -> int:
    score = 0

    if severity == "HIGH":
        score += 60
    elif severity == "MEDIUM":
        score += 40
    else:
        score += 20

    if vuln_type == "RCE":
        score += 20
    elif vuln_type in ["auth_bypass", "priv_esc"]:
        score += 15
    elif vuln_type == "info_disc":
        score += 5
    elif vuln_type == "dos":
        score += 5

    if is_kev:
        score += 20

    if exploitation_status == "known_exploited":
        score += 20
    elif exploitation_status == "under_attack":
        score += 15
    elif exploitation_status == "poc_available":
        score += 10

    if has_cves:
        score += 5

    return min(score, 100)


def score_item(
    item: Dict[str, Any],
    vendors: List[str],
    high_terms: List[str],
    medium_terms: List[str],
) -> Dict[str, Any]:
    """
    Return a dict with keys:
      should_create_event: bool
      vendor, product, cves, severity, summary,
      vuln_type, exploitation_status, risk_score, is_kev
    Or should_create_event=False if it's not interesting enough.
    """
    title = (item.get("title") or "")[:300]
    text = item.get("text") or ""
    full = f"{title}\n{text}"
    full_lower = full.lower()

    # vendor detection (simple substring match)
    matched_vendor = None
    for v in vendors:
        if v.lower() in full_lower:
            matched_vendor = v
            break

    cves = extract_cves(full)
    has_cves = bool(cves)

    high_hit = any(term.lower() in full_lower for term in high_terms)
    med_hit = any(term.lower() in full_lower for term in medium_terms)

    # Is this from KEV?
    is_kev = (item.get("source") == "cisa_kev")

    # Decide if we care at all
    if not matched_vendor and not has_cves and not is_kev:
        # Ignore for now: no vendor, no CVE, not KEV.
        return {"should_create_event": False}

    # Base severity
    severity = None
    if matched_vendor and (high_hit or (has_cves and high_hit) or is_kev):
        severity = "HIGH"
    elif matched_vendor and (has_cves or med_hit):
        severity = "MEDIUM"
    elif is_kev:
        severity = "HIGH"
    elif has_cves and high_hit:
        severity = "MEDIUM"
    else:
        # Too weak a signal, skip
        return {"should_create_event": False}

    vuln_type = classify_vuln_type(full)
    exploitation_status = classify_exploitation_status(full, is_kev=is_kev)
    risk_score = compute_risk_score(
        severity=severity,
        vuln_type=vuln_type,
        exploitation_status=exploitation_status,
        is_kev=is_kev,
        has_cves=has_cves,
    )

    summary = title or (text[:200] + "...")

    return {
        "should_create_event": True,
        "severity": severity,
        "vendor": matched_vendor,
        "product": None,  # future enhancement if you want product mapping
        "cves": cves,
        "summary": summary,
        "vuln_type": vuln_type,
        "exploitation_status": exploitation_status,
        "risk_score": risk_score,
        "is_kev": is_kev,
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
            "vuln_type": scored.get("vuln_type"),
            "exploitation_status": scored.get("exploitation_status"),
            "risk_score": scored.get("risk_score"),
            "is_kev": scored.get("is_kev", False),
        }

        event_id = insert_event(event_data)
        link_event_to_raw_item(event_id, item["id"])
        events_created += 1

    if max_id_seen:
        update_last_processed_raw_item_id(max_id_seen)

    print(
        f"[detect] Done. Events created: {events_created}, "
        f"last_processed_raw_item_id: {max_id_seen}"
    )
