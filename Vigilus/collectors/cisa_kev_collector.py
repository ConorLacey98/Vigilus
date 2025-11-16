from typing import List, Dict, Any
from datetime import datetime, timezone
import json
import requests


def fetch_cisa_kev(url: str) -> List[Dict[str, Any]]:
    """
    Fetch CISA KEV JSON and return normalized items.
    Each item:
      source: "cisa_kev"
      external_id: cveID
      title: vendor + product
      text: description
      url: KEV catalog URL
      timestamp: dateAdded
      extra_json: full raw entry as JSON string
    """
    resp = requests.get(url, timeout=15)
    resp.raise_for_status()
    data = resp.json()

    vulns = data.get("vulnerabilities", [])
    items: List[Dict[str, Any]] = []

    catalog_url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

    for v in vulns:
        cve_id = v.get("cveID", "UNKNOWN")
        vendor = v.get("vendorProject", "Unknown vendor")
        product = v.get("product", "Unknown product")
        date_added = v.get("dateAdded") or datetime.now(timezone.utc).isoformat()
        desc = v.get("shortDescription", "")

        title = f"{vendor} {product} - {cve_id}"

        items.append(
            {
                "source": "cisa_kev",
                "external_id": cve_id,
                "title": title,
                "text": desc,
                "url": catalog_url,
                "timestamp": date_added,
                "extra_json": json.dumps(v),
            }
        )

    return items
