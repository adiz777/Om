"""Local FastAPI server powering the Om 2.0 Dashboard and REST API.

Security controls:
- Binds to loopback (`127.0.0.1`) by default.
- Enforces Same-Origin / CSRF protection on state-changing requests (`POST`, `PUT`, `DELETE`).
- Supports optional `OM_API_KEY` header authentication (`X-Om-Api-Key`) when configured.
- Validates all targets, scopes, and configuration inputs via `om.security.scope` and `OmConfig`.
- Never exposes arbitrary filesystem reads or raw shell command execution.
"""
from __future__ import annotations

import hmac
import os
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel, Field

from om import AUTHOR, SCHEMA_VERSION, __version__
from om.core.config import (
    ALL_MODULE_GROUPS,
    PROFILE_POLICIES,
    VALID_PROFILES,
    OmConfig,
    load_config,
)
from om.engine.orchestrator import (
    ScanOrchestrator,
    cancel_active_scan,
    get_active_progress,
    list_active_progress,
)
from om.modules.registry import check_dependencies
from om.reporting.generator import (
    compare_reports,
    render_csv_report,
    render_html_report,
    render_json_report,
)
from om.security.scope import (
    parse_target,
    scope_allows_private_ip,
    verify_target_in_scope,
)
from om.storage.database import (
    cleanup_retention,
    delete_session,
    get_session,
    init_db,
    list_sessions,
)

DASHBOARD_HTML = Path(__file__).resolve().parents[2] / "dashboard" / "index.html"
ALLOWED_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]", "testserver"}


class ScanPreviewRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    profile: str = Field(default="low")
    modules: list[str] = Field(default_factory=list)
    scope: list[str] = Field(default_factory=list)
    authorize_active: bool = False
    timeout: int = Field(default=90, ge=5, le=3600)
    concurrency: int = Field(default=2, ge=1, le=8)
    rate_limit: int = Field(default=5, ge=1, le=500)


class ScanStartRequest(ScanPreviewRequest):
    confirm_execution: bool = Field(
        default=True,
        description="Confirmation flag before launching reconnaissance modules",
    )
    run_async: bool = Field(
        default=False,
        description="Run scan asynchronously in a background worker thread",
    )


class SettingsUpdateRequest(BaseModel):
    output_dir: str | None = Field(default=None, max_length=240)
    profile: str | None = None
    timeout: int | None = Field(default=None, ge=5, le=3600)
    concurrency: int | None = Field(default=None, ge=1, le=8)
    rate_limit: int | None = Field(default=None, ge=1, le=500)
    retention_days: int | None = Field(default=None, ge=1, le=3650)
    max_sessions: int | None = Field(default=None, ge=10, le=10000)
    wordlist: str | None = Field(default=None, max_length=300)
    archive_zip: bool | None = None


def _verify_local_security(
    request: Request, x_om_api_key: str | None = None
) -> None:
    """Enforce optional API key and CSRF / Browser Origin checks on state-changing operations."""
    expected_key = os.getenv("OM_API_KEY", "").strip()
    if expected_key:
        if not x_om_api_key or not hmac.compare_digest(x_om_api_key.strip(), expected_key):
            raise HTTPException(status_code=401, detail="Invalid or missing X-Om-Api-Key header.")

    if request.method in {"POST", "PUT", "DELETE", "PATCH"}:
        origin = request.headers.get("origin")
        if origin:
            parsed = urlparse(origin)
            if (parsed.hostname or "").lower() not in ALLOWED_LOCAL_HOSTS:
                raise HTTPException(
                    status_code=403,
                    detail=f"Cross-origin state-changing request from '{origin}' blocked by local security policy.",
                )


def create_app(initial_config: OmConfig | None = None) -> FastAPI:
    runtime_config = initial_config or load_config()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        init_db(runtime_config.db_path)
        yield

    api_app = FastAPI(
        title="Om 2.0 — Automated Reconnaissance & Intelligence Platform",
        version=__version__,
        description=f"Local Reconnaissance Engine & Intelligence API by {AUTHOR}",
        lifespan=lifespan,
    )
    api_app.state.config = runtime_config

    @api_app.get("/", response_class=HTMLResponse)
    async def serve_dashboard() -> Response:
        if not DASHBOARD_HTML.is_file():
            raise HTTPException(status_code=404, detail="Dashboard UI file not found.")
        return FileResponse(
            DASHBOARD_HTML,
            headers={
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
            },
        )

    @api_app.get("/api/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "tool_name": "Om",
            "version": __version__,
            "schema_version": SCHEMA_VERSION,
            "author": AUTHOR,
            "auth_required": bool(os.getenv("OM_API_KEY", "").strip()),
        }

    @api_app.get("/api/overview")
    async def overview(
        request: Request, x_om_api_key: str | None = Header(default=None)
    ) -> dict[str, Any]:
        _verify_local_security(request, x_om_api_key)
        cfg: OmConfig = api_app.state.config
        sessions_data = list_sessions(db_path=cfg.db_path, limit=25, offset=0)
        modules_status = check_dependencies(cfg.tool_paths, probe_versions=True)
        active = list_active_progress()

        recent_findings: list[dict[str, Any]] = []
        category_totals: dict[str, int] = {}
        unique_targets: set[str] = set()

        for s in sessions_data["sessions"][:10]:
            unique_targets.add(s["target"])
            full = get_session(s["session_id"], db_path=cfg.db_path)
            if full:
                for f in full.get("findings", []):
                    cat = str(f.get("category", "other"))
                    category_totals[cat] = category_totals.get(cat, 0) + 1
                    if len(recent_findings) < 20:
                        recent_findings.append(
                            {
                                **f,
                                "session_id": s["session_id"],
                                "target": s["target"],
                            }
                        )

        installed_count = sum(1 for m in modules_status if m["installed"])
        return {
            "total_sessions": sessions_data["total"],
            "unique_targets": len(unique_targets),
            "active_scans": active,
            "recent_sessions": sessions_data["sessions"][:10],
            "recent_findings": recent_findings,
            "category_totals": category_totals,
            "modules": {
                "installed": installed_count,
                "total": len(modules_status),
                "items": modules_status,
            },
            "profiles": PROFILE_POLICIES,
        }

    @api_app.get("/api/modules")
    async def get_modules(
        request: Request, x_om_api_key: str | None = Header(default=None)
    ) -> dict[str, Any]:
        _verify_local_security(request, x_om_api_key)
        cfg: OmConfig = api_app.state.config
        items = check_dependencies(cfg.tool_paths, probe_versions=True)
        return {
            "installed_count": sum(1 for m in items if m["installed"]),
            "total_count": len(items),
            "module_groups": list(ALL_MODULE_GROUPS),
            "profiles": PROFILE_POLICIES,
            "modules": items,
        }

    @api_app.post("/api/scans/preview")
    async def preview_scan(
        payload: ScanPreviewRequest,
        request: Request,
        x_om_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _verify_local_security(request, x_om_api_key)
        cfg: OmConfig = api_app.state.config
        if payload.profile not in VALID_PROFILES:
            raise HTTPException(status_code=422, detail=f"Invalid profile '{payload.profile}'.")

        effective_scope = [s.strip() for s in payload.scope if s.strip()]
        try:
            allow_priv = scope_allows_private_ip(payload.target, effective_scope)
            target_spec = parse_target(payload.target, allow_private=allow_priv)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        if effective_scope and not verify_target_in_scope(target_spec, effective_scope):
            raise HTTPException(
                status_code=403,
                detail=f"Target '{target_spec.host}' is outside declared scope ({', '.join(effective_scope)}).",
            )

        temp_cfg = OmConfig(
            output_dir=cfg.output_dir,
            db_path=cfg.db_path,
            profile=payload.profile,
            modules=payload.modules,
            scope=effective_scope or [target_spec.host],
            authorize_active=payload.authorize_active,
            timeout=payload.timeout,
            concurrency=payload.concurrency,
            rate_limit=payload.rate_limit,
            wordlist=cfg.wordlist,
            tool_paths=cfg.tool_paths,
        )
        orchestrator = ScanOrchestrator(temp_cfg)
        planned = orchestrator.resolve_planned_modules(
            payload.modules if payload.modules else None
        )
        active_needed = [m.name for m in planned if m.requires_active_auth]
        applicable = [
            m.to_dict() for m in planned if target_spec.target_type in m.supported_targets
        ]
        skipped_type = [
            m.name for m in planned if target_spec.target_type not in m.supported_targets
        ]

        return {
            "valid": True,
            "target": target_spec.to_dict(),
            "profile": payload.profile,
            "policy": PROFILE_POLICIES[payload.profile],
            "effective_scope": temp_cfg.scope,
            "planned_modules": applicable,
            "skipped_by_target_type": skipped_type,
            "active_modules_selected": active_needed,
            "requires_active_authorisation": bool(active_needed),
            "ready_to_execute": (not active_needed) or payload.authorize_active,
        }

    @api_app.post("/api/scans")
    async def create_scan(
        payload: ScanStartRequest,
        request: Request,
        x_om_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _verify_local_security(request, x_om_api_key)
        if not payload.confirm_execution:
            raise HTTPException(
                status_code=400,
                detail="Scan execution must be explicitly confirmed (confirm_execution=true).",
            )
        if payload.profile not in VALID_PROFILES:
            raise HTTPException(status_code=422, detail=f"Invalid profile '{payload.profile}'.")

        base_cfg: OmConfig = api_app.state.config
        effective_scope = [s.strip() for s in payload.scope if s.strip()]
        try:
            allow_priv = scope_allows_private_ip(payload.target, effective_scope)
            target_spec = parse_target(payload.target, allow_private=allow_priv)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        run_cfg = OmConfig(
            output_dir=base_cfg.output_dir,
            db_path=base_cfg.db_path,
            profile=payload.profile,
            modules=[m.lower().strip() for m in payload.modules if m.strip()],
            scope=effective_scope or [target_spec.host],
            authorize_active=payload.authorize_active,
            timeout=payload.timeout,
            concurrency=payload.concurrency,
            rate_limit=payload.rate_limit,
            retention_days=base_cfg.retention_days,
            max_sessions=base_cfg.max_sessions,
            wordlist=base_cfg.wordlist,
            tool_paths=base_cfg.tool_paths,
            report_formats=base_cfg.report_formats,
            archive_zip=base_cfg.archive_zip,
            quiet=True,
        )
        try:
            run_cfg.validate()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        orchestrator = ScanOrchestrator(run_cfg)
        planned = orchestrator.resolve_planned_modules(
            run_cfg.modules if run_cfg.modules else None
        )
        active_needed = [m.name for m in planned if m.requires_active_auth]
        if active_needed and not run_cfg.authorize_active:
            raise HTTPException(
                status_code=403,
                detail=(
                    f"Active reconnaissance modules ({', '.join(active_needed)}) require explicit "
                    "written authorisation. Enable 'Confirm Active Authorisation' before launching."
                ),
            )
        if not verify_target_in_scope(target_spec, run_cfg.scope):
            raise HTTPException(
                status_code=403,
                detail=f"Target '{target_spec.host}' is outside declared scope ({', '.join(run_cfg.scope)}).",
            )

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        session_id = f"{target_spec.safe_slug}_{stamp}_{uuid.uuid4().hex[:6]}"

        if payload.run_async:
            cancel_ev = threading.Event()

            def _bg_worker() -> None:
                try:
                    orchestrator.run(
                        target_spec,
                        selected_modules=run_cfg.modules if run_cfg.modules else None,
                        session_id=session_id,
                        cancel_event=cancel_ev,
                    )
                except Exception as bg_exc:  # pragma: no cover
                    import sys

                    print(f"[WARN] Background scan {session_id} failed: {bg_exc}", file=sys.stderr)

            t = threading.Thread(target=_bg_worker, daemon=True)
            t.start()
            return {
                "session_id": session_id,
                "status": "running",
                "target": target_spec.host,
                "profile": run_cfg.profile,
                "planned_modules": [m.name for m in planned],
            }

        try:
            report_doc, _ = orchestrator.run(
                target_spec,
                selected_modules=run_cfg.modules if run_cfg.modules else None,
                session_id=session_id,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return report_doc

    @api_app.get("/api/scans")
    async def get_scans(
        request: Request,
        target: str | None = Query(default=None),
        profile: str | None = Query(default=None),
        status: str | None = Query(default=None),
        q: str | None = Query(default=None),
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        x_om_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _verify_local_security(request, x_om_api_key)
        cfg: OmConfig = api_app.state.config
        res = list_sessions(
            db_path=cfg.db_path,
            target_filter=target,
            profile_filter=profile,
            status_filter=status,
            search_query=q,
            limit=limit,
            offset=offset,
        )
        res["active"] = list_active_progress()
        return res

    @api_app.get("/api/scans/{session_id}")
    async def get_scan_detail(
        session_id: str,
        request: Request,
        x_om_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _verify_local_security(request, x_om_api_key)
        cfg: OmConfig = api_app.state.config
        active_prog = get_active_progress(session_id)
        if active_prog:
            return {"status": "running", "progress": active_prog}
        doc = get_session(session_id, db_path=cfg.db_path)
        if not doc:
            raise HTTPException(status_code=404, detail=f"Scan session '{session_id}' not found.")
        return doc

    @api_app.post("/api/scans/{session_id}/cancel")
    async def cancel_scan_endpoint(
        session_id: str,
        request: Request,
        x_om_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _verify_local_security(request, x_om_api_key)
        ok = cancel_active_scan(session_id)
        if not ok:
            raise HTTPException(
                status_code=404,
                detail=f"No running scan session found with ID '{session_id}'.",
            )
        return {"session_id": session_id, "cancelled": True}

    @api_app.delete("/api/scans/{session_id}")
    async def remove_scan(
        session_id: str,
        request: Request,
        x_om_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _verify_local_security(request, x_om_api_key)
        cfg: OmConfig = api_app.state.config
        deleted = delete_session(session_id, db_path=cfg.db_path)
        if not deleted:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found.")
        return {"deleted": True, "session_id": session_id}

    @api_app.get("/api/scans/{session_id}/export")
    async def export_scan_report(
        session_id: str,
        request: Request,
        format: str = Query(default="html", pattern="^(html|json|csv)$"),
        x_om_api_key: str | None = Header(default=None),
    ) -> Response:
        _verify_local_security(request, x_om_api_key)
        cfg: OmConfig = api_app.state.config
        doc = get_session(session_id, db_path=cfg.db_path)
        if not doc:
            raise HTTPException(status_code=404, detail=f"Scan session '{session_id}' not found.")

        safe_id = "".join(c for c in session_id if c.isalnum() or c in "._-")[:80]
        if format == "json":
            return Response(
                content=render_json_report(doc),
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="om-report-{safe_id}.json"'},
            )
        if format == "csv":
            return Response(
                content=render_csv_report(doc.get("findings", [])),
                media_type="text/csv; charset=utf-8",
                headers={"Content-Disposition": f'attachment; filename="om-findings-{safe_id}.csv"'},
            )
        return HTMLResponse(
            content=render_html_report(doc),
            headers={"Content-Disposition": f'attachment; filename="om-report-{safe_id}.html"'},
        )

    @api_app.get("/api/intelligence/{domain_type}")
    async def get_intelligence(
        domain_type: str,
        request: Request,
        target: str | None = Query(default=None),
        session_id: str | None = Query(default=None),
        x_om_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Return aggregated intelligence for `domain`, `network`, or `web` views."""
        _verify_local_security(request, x_om_api_key)
        if domain_type not in {"domain", "network", "web"}:
            raise HTTPException(status_code=400, detail="Intelligence category must be 'domain', 'network', or 'web'.")

        category_filter_map = {
            "domain": {"subdomain", "dns_record", "osint_email", "ip_address"},
            "network": {"open_port", "ip_address"},
            "web": {"web_tech", "waf", "cms", "tls", "http_path"},
        }
        allowed_cats = category_filter_map[domain_type]
        cfg: OmConfig = api_app.state.config

        docs: list[dict[str, Any]] = []
        if session_id:
            d = get_session(session_id, db_path=cfg.db_path)
            if d:
                docs.append(d)
        else:
            listing = list_sessions(db_path=cfg.db_path, target_filter=target, limit=25)
            for row in listing["sessions"]:
                d = get_session(row["session_id"], db_path=cfg.db_path)
                if d:
                    docs.append(d)

        items: list[dict[str, Any]] = []
        for d in docs:
            for f in d.get("findings", []):
                if f.get("category") in allowed_cats:
                    items.append(
                        {
                            **f,
                            "session_id": d["session_id"],
                            "target": d["target"],
                            "session_started_at": d["started_at"],
                        }
                    )

        return {
            "intelligence_type": domain_type,
            "count": len(items),
            "items": items,
        }

    @api_app.get("/api/compare")
    async def compare_sessions_endpoint(
        request: Request,
        base_id: str = Query(..., min_length=1),
        target_id: str = Query(..., min_length=1),
        x_om_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _verify_local_security(request, x_om_api_key)
        cfg: OmConfig = api_app.state.config
        old_doc = get_session(base_id, db_path=cfg.db_path)
        new_doc = get_session(target_id, db_path=cfg.db_path)
        if not old_doc:
            raise HTTPException(status_code=404, detail=f"Baseline session '{base_id}' not found.")
        if not new_doc:
            raise HTTPException(status_code=404, detail=f"Comparison session '{target_id}' not found.")
        return compare_reports(old_doc, new_doc)

    @api_app.get("/api/settings")
    async def get_settings(
        request: Request, x_om_api_key: str | None = Header(default=None)
    ) -> dict[str, Any]:
        _verify_local_security(request, x_om_api_key)
        cfg: OmConfig = api_app.state.config
        return {
            "config": cfg.to_public_dict(),
            "modules": check_dependencies(cfg.tool_paths, probe_versions=True),
        }

    @api_app.put("/api/settings")
    async def update_settings(
        payload: SettingsUpdateRequest,
        request: Request,
        x_om_api_key: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _verify_local_security(request, x_om_api_key)
        cfg: OmConfig = api_app.state.config
        if payload.profile is not None:
            if payload.profile not in VALID_PROFILES:
                raise HTTPException(status_code=422, detail=f"Invalid profile '{payload.profile}'.")
            cfg.profile = payload.profile
        if payload.output_dir is not None:
            if ".." in payload.output_dir:
                raise HTTPException(status_code=422, detail="Output directory must not contain '..'.")
            cfg.output_dir = payload.output_dir.strip()
        if payload.timeout is not None:
            cfg.timeout = payload.timeout
        if payload.concurrency is not None:
            cfg.concurrency = payload.concurrency
        if payload.rate_limit is not None:
            cfg.rate_limit = payload.rate_limit
        if payload.retention_days is not None:
            cfg.retention_days = payload.retention_days
        if payload.max_sessions is not None:
            cfg.max_sessions = payload.max_sessions
        if payload.wordlist is not None:
            if ".." in payload.wordlist:
                raise HTTPException(status_code=422, detail="Wordlist path must not contain '..'.")
            cfg.wordlist = payload.wordlist.strip()
        if payload.archive_zip is not None:
            cfg.archive_zip = payload.archive_zip

        try:
            cfg.validate()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        cleanup_retention(
            db_path=cfg.db_path,
            retention_days=cfg.retention_days,
            max_sessions=cfg.max_sessions,
        )
        return {"status": "updated", "config": cfg.to_public_dict()}

    return api_app


app = create_app()
