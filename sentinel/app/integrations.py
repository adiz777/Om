"""Passive public-data integrations for Om Sentinel. No target probing here."""
from __future__ import annotations
import os
import re
import httpx

TIMEOUT = httpx.Timeout(8.0, connect=4.0)


def validate_domain(value: str) -> str:
    domain = value.strip().lower().rstrip(".")
    if len(domain) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        raise ValueError("Enter a valid fully qualified domain name, e.g. example.com")
    if domain in {"localhost", "local"} or domain.endswith((".localhost", ".local", ".internal")):
        raise ValueError("Local-only hostnames are not supported by passive enrichment")
    return domain


async def certificate_transparency(domain: str) -> dict:
    """Query crt.sh for public certificate records; fail soft on upstream errors."""
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
            response = await client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, headers={"User-Agent": "Om-Sentinel/0.1 (defensive security research)"})
            response.raise_for_status()
            data = response.json()
        names = set()
        for row in data[:5000] if isinstance(data, list) else []:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lower().lstrip("*.")
                if name == domain or name.endswith("." + domain):
                    names.add(name)
        return {"source": "crt.sh", "status": "ok", "count": len(names), "subdomains": sorted(names)[:1000]}
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        return {"source": "crt.sh", "status": "unavailable", "error": type(exc).__name__, "count": 0, "subdomains": []}


async def cisa_known_exploited_catalog() -> dict:
    """Fetch CISA's public KEV catalogue metadata, without scanning a target."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
            response = await client.get(url, headers={"User-Agent": "Om-Sentinel/0.1"})
            response.raise_for_status()
            data = response.json()
        vulns = data.get("vulnerabilities", [])
        return {"source": "CISA KEV", "status": "ok", "catalog_version": data.get("catalogVersion"), "count": len(vulns), "updated": data.get("dateReleased")}
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        return {"source": "CISA KEV", "status": "unavailable", "error": type(exc).__name__}


async def nvd_search(keyword: str, limit: int = 10) -> dict:
    """Search public NVD CVE records by a user-provided technology keyword."""
    params = {"keywordSearch": keyword[:100], "resultsPerPage": max(1, min(limit, 20))}
    headers = {"User-Agent": "Om-Sentinel/0.1"}
    if os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False) as client:
            response = await client.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
        results = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            descriptions = cve.get("descriptions", [])
            desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
            results.append({"id": cve.get("id"), "published": cve.get("published"), "description": desc[:1200], "url": "https://nvd.nist.gov/vuln/detail/" + str(cve.get("id", ""))})
        return {"source": "NVD CVE API", "status": "ok", "keyword": keyword, "count": data.get("totalResults", len(results)), "results": results}
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        return {"source": "NVD CVE API", "status": "unavailable", "error": type(exc).__name__, "keyword": keyword, "results": []}
