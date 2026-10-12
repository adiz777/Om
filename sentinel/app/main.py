"""Om Sentinel API: passive enrichment, persistent history, and report export."""
from __future__ import annotations
import asyncio, hmac, os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel, Field
from .ai import analyse_findings
from .database import get_run, init_db, list_runs, save_run
from .integrations import certificate_transparency, cisa_known_exploited_catalog, nvd_search, validate_domain
from .reports import html_report, json_report
from .scoring import score_enrichment

load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)
app = FastAPI(title="Om Sentinel", version="0.2.0", description="Hybrid defensive reconnaissance, passive enrichment, history, and evidence-grounded reporting")
WEB = Path(__file__).resolve().parent.parent / "web" / "index.html"


class EnrichmentRequest(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    cve_keyword: str | None = Field(default=None, max_length=100)
    use_ai: bool = True


class ImportRequest(BaseModel):
    """Import existing structured results without executing their contents."""
    domain: str = Field(min_length=3, max_length=253)
    source: str = Field(default="Om legacy JSON import", min_length=1, max_length=80)
    findings: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    notes: str | None = Field(default=None, max_length=4000)


def require_api_key(provided: str | None) -> None:
    expected = os.getenv("OM_SENTINEL_API_KEY", "").strip()
    if not expected:
        raise HTTPException(503, "Set OM_SENTINEL_API_KEY in sentinel/.env or your environment before using this endpoint")
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(401, "Invalid API key")


def normalized_domain(value: str) -> str:
    try:
        return validate_domain(value)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


@app.on_event("startup")
async def startup() -> None:
    init_db()


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "Om Sentinel", "version": app.version, "capabilities": ["passive-enrichment", "persistent-history", "json-html-reports", "legacy-json-import"]}


@app.get("/")
async def index():
    if not WEB.exists():
        raise HTTPException(404, "Web interface not installed")
    return FileResponse(WEB)


@app.post("/api/enrich")
async def enrich(request: EnrichmentRequest, x_om_api_key: str | None = Header(default=None)):
    require_api_key(x_om_api_key)
    domain = normalized_domain(request.domain)
    certificates, kev = await asyncio.gather(certificate_transparency(domain), cisa_known_exploited_catalog())
    cves = await nvd_search(request.cve_keyword) if request.cve_keyword else {"source": "NVD CVE API", "status": "skipped", "results": [], "count": 0}
    result: dict[str, Any] = {
        "product": "Om Sentinel", "version": app.version,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "mode": "passive-public-data", "domain": domain,
        "certificates": certificates, "kev_catalog": kev,
        "cve_keyword": request.cve_keyword, "cves": cves,
        "limitations": [
            "Certificate records and CVE keyword matches do not prove that a host is vulnerable.",
            "This endpoint performs passive public-data lookups only; it does not scan ports or test exploitability.",
            "The metadata indicator is not a CVSS score and must not be interpreted as confirmed risk."
        ]
    }
    result["risk_score"] = score_enrichment(result)
    result["ai"] = await analyse_findings(result) if request.use_ai else {"status": "disabled"}
    result["run"] = save_run(domain, result, result["risk_score"]["score"])
    return result


@app.get("/api/runs")
async def runs(x_om_api_key: str | None = Header(default=None), limit: int = Query(default=25, ge=1, le=100), offset: int = Query(default=0, ge=0)):
    require_api_key(x_om_api_key)
    return list_runs(limit=limit, offset=offset)


@app.get("/api/runs/{run_id}")
async def run_detail(run_id: str, x_om_api_key: str | None = Header(default=None)):
    require_api_key(x_om_api_key)
    run = get_run(run_id)
    if run is None:
        raise HTTPException(404, "Run not found")
    return run


@app.get("/api/runs/{run_id}/report")
async def run_report(run_id: str, x_om_api_key: str | None = Header(default=None), format: str = Query(default="html", pattern="^(html|json)$")):
    require_api_key(x_om_api_key)
    run = get_run(run_id)
    if run is None:
        raise HTTPException(404, "Run not found")
    if format == "json":
        return Response(content=json_report(run), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="om-sentinel-{run_id}.json"'})
    return HTMLResponse(content=html_report(run), headers={"Content-Disposition": f'attachment; filename="om-sentinel-{run_id}.html"'})


@app.post("/api/import")
async def import_legacy_result(request: ImportRequest, x_om_api_key: str | None = Header(default=None)):
    """Store existing structured findings; never runs shell commands or accepts filesystem paths."""
    require_api_key(x_om_api_key)
    domain = normalized_domain(request.domain)
    safe_findings = [{str(key)[:80]: str(value)[:2000] for key, value in list(finding.items())[:30]} for finding in request.findings]
    payload = {
        "product": "Om Sentinel", "version": app.version,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "mode": "imported-existing-results", "domain": domain,
        "source": request.source, "findings": safe_findings, "notes": request.notes,
        "limitations": ["Imported data is untrusted and was not independently verified by Om Sentinel.", "This endpoint does not execute scanners, shell commands, or uploaded files."],
        "risk_score": {"score": 0, "label": "unscored", "reasons": ["Imported findings are not automatically scored without a validated evidence schema."], "method": "unscored import"}
    }
    payload["run"] = save_run(domain, payload, 0)
    return payload
