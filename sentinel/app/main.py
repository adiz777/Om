"""Om Sentinel API: passive enrichment, JSON reports, and a small web UI."""
from __future__ import annotations
import hmac, os, secrets
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from .integrations import validate_domain, certificate_transparency, cisa_known_exploited_catalog, nvd_search
from .ai import analyse_findings

app = FastAPI(title="Om Sentinel", version="0.1.0", description="Hybrid defensive reconnaissance and public-data enrichment")
WEB = Path(__file__).resolve().parent.parent / "web" / "index.html"

class EnrichmentRequest(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    cve_keyword: str | None = Field(default=None, max_length=100)
    use_ai: bool = True

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "Om Sentinel", "version": app.version}

@app.get("/")
async def index():
    if not WEB.exists():
        raise HTTPException(404, "Web interface not installed")
    return FileResponse(WEB)

@app.post("/api/enrich")
async def enrich(request: EnrichmentRequest, x_om_api_key: str | None = Header(default=None)):
    expected = os.getenv("OM_SENTINEL_API_KEY", "").strip()
    # Require a configured secret for non-health operations, including localhost.
    if not expected:
        raise HTTPException(503, "Set OM_SENTINEL_API_KEY in your environment before using enrichment")
    if not x_om_api_key or not hmac.compare_digest(x_om_api_key, expected):
        raise HTTPException(401, "Invalid API key")
    try:
        domain = validate_domain(request.domain)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    certificates, kev = await __import__("asyncio").gather(certificate_transparency(domain), cisa_known_exploited_catalog())
    cves = await nvd_search(request.cve_keyword) if request.cve_keyword else {"source": "NVD CVE API", "status": "skipped", "results": [], "count": 0}
    result = {"product": "Om Sentinel", "version": app.version, "created_at": datetime.now(timezone.utc).isoformat(), "mode": "passive-public-data", "domain": domain, "certificates": certificates, "kev_catalog": kev, "cve_keyword": request.cve_keyword, "cves": cves, "limitations": ["Certificate records and CVE keyword matches do not prove that a host is vulnerable.", "This endpoint performs passive public-data lookups only; it does not scan ports or test exploitability."]}
    result["ai"] = await analyse_findings(result) if request.use_ai else {"status": "disabled"}
    return result
