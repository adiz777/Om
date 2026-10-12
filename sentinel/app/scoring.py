"""Small deterministic scoring helpers; public metadata alone never proves exploitability."""
from __future__ import annotations
from typing import Any


def score_enrichment(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a conservative 0-100 indicator based on evidence availability, not vulnerability claims."""
    score = 0
    reasons: list[str] = []
    certs = payload.get("certificates", {})
    if certs.get("status") == "ok" and certs.get("count", 0) > 0:
        score += 10
        reasons.append("Public certificate records found (+10; informational only)")
    cves = payload.get("cves", {})
    if cves.get("status") == "ok" and cves.get("results"):
        score += min(20, 5 * len(cves["results"]))
        reasons.append("Keyword-matched public CVE records found (+5 each, capped at +20; not proof of target exposure)")
    kev = payload.get("kev_catalog", {})
    if kev.get("status") == "ok":
        reasons.append("CISA KEV catalogue metadata available (not a target-specific finding)")
    return {"score": min(score, 100), "label": "informational" if score < 20 else "review", "reasons": reasons, "method": "conservative metadata indicator; not a CVSS score or exploitability assessment"}
