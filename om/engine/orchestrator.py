"""Concurrent scan orchestration engine for Om 2.0.

Capabilities:
- Profile & individual module selection with duplicate task prevention
- Safe concurrent execution via `ThreadPoolExecutor(max_workers=config.concurrency)`
- Live progress and status tracking (`ScanProgress`)
- Timeout, failed subprocess, and cancellation handling (`threading.Event`)
- Partial result preservation when individual modules fail or time out
- Clear run status classification (`completed`, `partial`, `failed`, `skipped`, `cancelled`)
"""
from __future__ import annotations

import threading
import time
import uuid
import zipfile
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

from om import SCHEMA_VERSION, __version__
from om.core.config import OmConfig
from om.core.normalizer import deduplicate_findings, parse_tool_findings
from om.models.schemas import (
    Finding,
    ModuleContract,
    ModuleExecutionResult,
    ScanProgress,
    TargetSpec,
)
from om.modules.registry import MODULE_REGISTRY, execute_module
from om.reporting.generator import (
    build_report_document,
    render_csv_report,
    render_html_report,
    render_json_report,
)
from om.security.scope import filter_findings_to_scope, verify_target_in_scope
from om.storage.database import save_session

_ACTIVE_LOCK = threading.Lock()
_ACTIVE_PROGRESS: dict[str, ScanProgress] = {}
_ACTIVE_CANCEL_EVENTS: dict[str, threading.Event] = {}


def _log(msg: str, *, log_file: Path | None = None, quiet: bool = False) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    line = f"[{timestamp}] {msg}"
    if not quiet:
        print(line)
    if log_file:
        try:
            with log_file.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass


def create_session_directory(
    output_root: Path, target: TargetSpec, session_id: str | None = None
) -> tuple[str, Path]:
    """Create a collision-safe session directory without overwriting existing scans."""
    if not session_id:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        short_id = uuid.uuid4().hex[:6]
        session_id = f"{target.safe_slug}_{stamp}_{short_id}"
    session_dir = output_root / f"OM_Recon_{session_id}"
    session_dir.mkdir(parents=True, exist_ok=False)
    return session_id, session_dir


def _archive_session(session_dir: Path) -> Path:
    zip_path = session_dir.with_suffix(".zip")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(session_dir.rglob("*")):
            if file_path.is_file():
                zf.write(
                    file_path, arcname=str(file_path.relative_to(session_dir.parent))
                )
    return zip_path


def _determine_session_status(
    results: list[ModuleExecutionResult], cancelled: bool
) -> str:
    if cancelled or any(r.status == "cancelled" for r in results):
        return "cancelled"
    if not results:
        return "skipped"
    statuses = {r.status for r in results}
    if statuses <= {"skipped_missing", "skipped_target_type", "skipped_scope"}:
        return "skipped"
    has_completed = any(r.status == "completed" for r in results)
    has_failures = any(r.status in {"failed", "timed_out", "partial"} for r in results)
    if has_completed and not has_failures:
        return "completed"
    if has_completed and has_failures:
        return "partial"
    if any(r.status == "partial" for r in results):
        return "partial"
    return "failed"


def get_active_progress(session_id: str) -> dict[str, Any] | None:
    with _ACTIVE_LOCK:
        prog = _ACTIVE_PROGRESS.get(session_id)
        return prog.to_dict() if prog else None


def list_active_progress() -> list[dict[str, Any]]:
    with _ACTIVE_LOCK:
        return [p.to_dict() for p in _ACTIVE_PROGRESS.values()]


def cancel_active_scan(session_id: str) -> bool:
    """Signal cancellation to an active scan session."""
    with _ACTIVE_LOCK:
        ev = _ACTIVE_CANCEL_EVENTS.get(session_id)
        prog = _ACTIVE_PROGRESS.get(session_id)
        if not ev:
            return False
        ev.set()
        if prog:
            prog.status = "cancelled"
            prog.updated_at = datetime.now(timezone.utc).isoformat()
        return True


class ScanOrchestrator:
    """Orchestrates reconnaissance modules across a declared target and scope."""

    def __init__(self, config: OmConfig) -> None:
        self.config = config

    def resolve_planned_modules(
        self, selected_groups_or_names: Sequence[str] | None = None
    ) -> list[ModuleContract]:
        """Return deduplicated `ModuleContract` list matching selected groups or tool names."""
        requested = (
            [s.strip().lower() for s in selected_groups_or_names if s.strip()]
            if selected_groups_or_names is not None
            else [s.lower() for s in self.config.resolved_modules()]
        )
        seen_names: set[str] = set()
        planned: list[ModuleContract] = []
        for mod in MODULE_REGISTRY:
            if mod.module_group.lower() in requested or mod.name.lower() in requested:
                if mod.name not in seen_names:
                    seen_names.add(mod.name)
                    planned.append(mod)
        return planned

    def run(
        self,
        target: TargetSpec,
        selected_modules: Sequence[str] | None = None,
        *,
        session_id: str | None = None,
        cancel_event: threading.Event | None = None,
        progress_callback: Callable[[ScanProgress], None] | None = None,
        persist_db: bool = True,
    ) -> tuple[dict[str, Any], Path]:
        if not verify_target_in_scope(target, self.config.scope):
            raise PermissionError(
                f"Target '{target.host}' is outside the configured scope ({', '.join(self.config.scope)})."
            )

        planned_modules = self.resolve_planned_modules(selected_modules)
        active_tools_selected = [
            m.name for m in planned_modules if m.requires_active_auth
        ]
        if active_tools_selected and not self.config.authorize_active:
            raise PermissionError(
                f"Active reconnaissance modules ({', '.join(active_tools_selected)}) require explicit authorisation. "
                "Pass --authorize-active (or confirm authorisation in the UI/menu) after verifying written permission."
            )

        output_root = Path(self.config.output_dir).expanduser()
        session_id, session_dir = create_session_directory(
            output_root, target, session_id=session_id
        )
        log_file = session_dir / "recon_log.txt"
        started_at = datetime.now(timezone.utc).isoformat()
        t0 = time.monotonic()

        cancel_ev = cancel_event or threading.Event()
        progress = ScanProgress(
            session_id=session_id,
            target=target.host,
            profile=self.config.profile,
            status="running",
            total_modules=len(planned_modules),
            completed_modules=0,
            current_modules=[],
            started_at=started_at,
            updated_at=started_at,
        )

        with _ACTIVE_LOCK:
            _ACTIVE_PROGRESS[session_id] = progress
            _ACTIVE_CANCEL_EVENTS[session_id] = cancel_ev

        if progress_callback:
            progress_callback(progress)

        _log(
            f"Starting Om v{__version__} session '{session_id}' for target '{target.host}' "
            f"(profile={self.config.profile}, concurrency={self.config.concurrency}, modules={len(planned_modules)})",
            log_file=log_file,
            quiet=self.config.quiet,
        )
        if self.config.profile == "high":
            _log(
                f"[WARNING] { self.config.policy().get('warning', '') }",
                log_file=log_file,
                quiet=self.config.quiet,
            )

        results_by_name: dict[str, ModuleExecutionResult] = {}
        raw_findings: list[Finding] = []
        findings_lock = threading.Lock()

        def _run_one(mod: ModuleContract) -> ModuleExecutionResult:
            with _ACTIVE_LOCK:
                progress.current_modules.append(mod.name)
                progress.updated_at = datetime.now(timezone.utc).isoformat()
            if progress_callback:
                progress_callback(progress)

            _log(
                f"[{mod.category}] Running {mod.name} ({mod.traffic_mode}, timeout={self.config.timeout}s)...",
                log_file=log_file,
                quiet=self.config.quiet,
            )
            res = execute_module(
                mod, target, self.config, session_dir, cancel_event=cancel_ev
            )
            extracted = parse_tool_findings(res, target)
            scoped_extracted = filter_findings_to_scope(
                extracted, target, self.config.scope
            )
            res.findings_count = len(scoped_extracted)

            with findings_lock:
                raw_findings.extend(scoped_extracted)

            if res.status == "completed":
                _log(
                    f"[{mod.category}] {mod.name} completed in {res.duration_seconds:.2f}s ({len(scoped_extracted)} observations).",
                    log_file=log_file,
                    quiet=self.config.quiet,
                )
            elif res.status == "skipped_missing":
                _log(
                    f"[{mod.category}] {mod.name} skipped (not installed). Hint: {res.install_hint}",
                    log_file=log_file,
                    quiet=self.config.quiet,
                )
            else:
                _log(
                    f"[{mod.category}] {mod.name} finished with status '{res.status}': {res.error}",
                    log_file=log_file,
                    quiet=self.config.quiet,
                )

            with _ACTIVE_LOCK:
                if mod.name in progress.current_modules:
                    progress.current_modules.remove(mod.name)
                progress.completed_modules += 1
                progress.updated_at = datetime.now(timezone.utc).isoformat()
            if progress_callback:
                progress_callback(progress)
            return res

        try:
            max_workers = max(1, min(int(self.config.concurrency), len(planned_modules) or 1))
            if max_workers == 1:
                for mod in planned_modules:
                    results_by_name[mod.name] = _run_one(mod)
            else:
                with ThreadPoolExecutor(max_workers=max_workers) as pool:
                    future_map: dict[Future[ModuleExecutionResult], ModuleContract] = {
                        pool.submit(_run_one, mod): mod for mod in planned_modules
                    }
                    for fut in as_completed(future_map):
                        mod = future_map[fut]
                        results_by_name[mod.name] = fut.result()

            # Preserve registry order in report output
            ordered_results = [
                results_by_name[m.name]
                for m in planned_modules
                if m.name in results_by_name
            ]
            deduped_findings = deduplicate_findings(raw_findings)
            completed_at = datetime.now(timezone.utc).isoformat()
            total_duration = round(time.monotonic() - t0, 3)
            session_status = _determine_session_status(
                ordered_results, cancel_ev.is_set()
            )

            with _ACTIVE_LOCK:
                progress.status = session_status
                progress.current_modules.clear()
                progress.updated_at = completed_at

            report_doc = build_report_document(
                session_id=session_id,
                status=session_status,
                target=target.host,
                target_type=target.target_type,
                profile=self.config.profile,
                scope=self.config.scope or [target.host],
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=total_duration,
                tool_results=ordered_results,
                findings=deduped_findings,
            )

            json_path = session_dir / "report.json"
            json_path.write_text(render_json_report(report_doc), encoding="utf-8")

            if "html" in self.config.report_formats:
                html_path = session_dir / "Report.html"
                html_path.write_text(
                    render_html_report(report_doc, ordered_results), encoding="utf-8"
                )
                _log(
                    f"HTML report generated: {html_path}",
                    log_file=log_file,
                    quiet=self.config.quiet,
                )

            if "csv" in self.config.report_formats:
                csv_path = session_dir / "findings.csv"
                csv_path.write_text(
                    render_csv_report(deduped_findings), encoding="utf-8"
                )
                _log(
                    f"CSV findings exported: {csv_path}",
                    log_file=log_file,
                    quiet=self.config.quiet,
                )

            _log(
                f"JSON report (schema v{SCHEMA_VERSION}) exported: {json_path}",
                log_file=log_file,
                quiet=self.config.quiet,
            )

            if self.config.archive_zip:
                zip_path = _archive_session(session_dir)
                _log(
                    f"Session archived to: {zip_path}",
                    log_file=log_file,
                    quiet=self.config.quiet,
                )

            if persist_db:
                try:
                    save_session(
                        report_doc,
                        session_dir,
                        db_path=self.config.db_path,
                        retention_days=self.config.retention_days,
                        max_sessions=self.config.max_sessions,
                    )
                except Exception as db_exc:
                    _log(
                        f"[WARN] SQLite history write skipped ({db_exc}); file reports preserved.",
                        log_file=log_file,
                        quiet=self.config.quiet,
                    )

            return report_doc, session_dir
        finally:
            with _ACTIVE_LOCK:
                _ACTIVE_CANCEL_EVENTS.pop(session_id, None)
                _ACTIVE_PROGRESS.pop(session_id, None)


def run_scan_session(
    target: TargetSpec,
    config: OmConfig,
    selected_modules: Sequence[str] | None = None,
    *,
    session_id: str | None = None,
    cancel_event: threading.Event | None = None,
) -> tuple[dict[str, Any], Path]:
    """Convenience wrapper around `ScanOrchestrator(config).run(...)`."""
    orchestrator = ScanOrchestrator(config)
    return orchestrator.run(
        target,
        selected_modules=selected_modules,
        session_id=session_id,
        cancel_event=cancel_event,
    )
