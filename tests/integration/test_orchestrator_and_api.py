"""Integration tests for ScanOrchestrator, CLI, and FastAPI Dashboard endpoints using mocked executables."""
from __future__ import annotations

import sys
import threading
from pathlib import Path

from fastapi.testclient import TestClient

from om.api.server import create_app
from om.cli.main import main as cli_main
from om.core.config import OmConfig
from om.engine.orchestrator import ScanOrchestrator
from om.security.scope import parse_target


def _create_fake_tool(tmp_path: Path, name: str, stdout_lines: list[str], sleep_sec: float = 0.0) -> str:
    """Create a cross-platform fake executable script (.cmd on Windows, .sh on POSIX)."""
    py_script = tmp_path / f"{name}_impl.py"
    lines_repr = repr("\n".join(stdout_lines) + "\n")
    py_script.write_text(
        f"import sys, time\n"
        f"if {sleep_sec} > 0:\n"
        f"    time.sleep({sleep_sec})\n"
        f"sys.stdout.write({lines_repr})\n"
        f"if '-o' in sys.argv:\n"
        f"    idx = sys.argv.index('-o')\n"
        f"    if idx + 1 < len(sys.argv):\n"
        f"        open(sys.argv[idx + 1], 'w', encoding='utf-8').write({lines_repr})\n",
        encoding="utf-8",
    )
    if sys.platform.startswith("win"):
        wrapper = tmp_path / f"{name}.cmd"
        wrapper.write_text(f'@echo off\n"{sys.executable}" "{py_script}" %*\n', encoding="utf-8")
        return str(wrapper)
    wrapper = tmp_path / name
    wrapper.write_text(f'#!/usr/bin/env bash\nexec "{sys.executable}" "{py_script}" "$@"\n', encoding="utf-8")
    wrapper.chmod(0o755)
    return str(wrapper)


def test_orchestrator_runs_fake_executables_and_handles_missing_tools(tmp_path: Path) -> None:
    fake_amass = _create_fake_tool(tmp_path, "amass", ["api.example.com", "dev.example.com"])
    fake_dnsrecon = _create_fake_tool(tmp_path, "dnsrecon", ["[*] A api.example.com 93.184.216.34"])

    cfg = OmConfig(
        output_dir=str(tmp_path / "reports"),
        db_path=str(tmp_path / "reports" / "om.db"),
        profile="low",
        modules=["subdomains", "dns"],
        scope=["example.com"],
        concurrency=2,
        tool_paths={
            "amass": fake_amass,
            "sublist3r": str(tmp_path / "nonexistent_sublist3r"),
            "dnsrecon": fake_dnsrecon,
        },
        quiet=True,
    )
    orchestrator = ScanOrchestrator(cfg)
    target = parse_target("example.com")
    report_doc, session_dir = orchestrator.run(target)

    assert report_doc["status"] == "completed"
    assert (session_dir / "report.json").is_file()
    assert (session_dir / "Report.html").is_file()
    assert (session_dir / "findings.csv").is_file()

    statuses = {t["tool"]: t["status"] for t in report_doc["tools"]}
    assert statuses["amass"] == "completed"
    assert statuses["dnsrecon"] == "completed"
    assert statuses["sublist3r"] == "skipped_missing"
    assert report_doc["summary"]["total_findings"] >= 2


def test_orchestrator_cancellation_stops_running_module(tmp_path: Path) -> None:
    slow_amass = _create_fake_tool(tmp_path, "amass", ["slow.example.com"], sleep_sec=5.0)
    cfg = OmConfig(
        output_dir=str(tmp_path / "reports"),
        db_path=str(tmp_path / "reports" / "om.db"),
        profile="low",
        modules=["subdomains"],
        tool_paths={"amass": slow_amass, "sublist3r": str(tmp_path / "missing")},
        timeout=10,
        quiet=True,
    )
    cancel_ev = threading.Event()
    threading.Timer(0.4, cancel_ev.set).start()

    orchestrator = ScanOrchestrator(cfg)
    report_doc, _ = orchestrator.run(parse_target("example.com"), cancel_event=cancel_ev)
    assert report_doc["status"] == "cancelled"


def test_cli_end_to_end_and_active_guard(tmp_path: Path) -> None:
    out_dir = tmp_path / "cli_out"
    assert cli_main(["--check-tools-json"]) == 0

    # Active module (nmap) without --authorize-active must return exit code 3
    rc_blocked = cli_main(
        [
            "--target",
            "example.com",
            "--modules",
            "nmap",
            "--output",
            str(out_dir),
            "--quiet",
        ]
    )
    assert rc_blocked == 3

    # Passive/light scan succeeds
    rc_ok = cli_main(
        [
            "--target",
            "example.com",
            "--profile",
            "low",
            "--modules",
            "subdomains",
            "--output",
            str(out_dir),
            "--no-zip",
            "--quiet",
        ]
    )
    assert rc_ok == 0
    assert cli_main(["--history", "--output", str(out_dir)]) == 0


def test_fastapi_dashboard_and_local_security_controls(tmp_path: Path) -> None:
    fake_whatweb = _create_fake_tool(
        tmp_path,
        "whatweb",
        ["https://example.com [200 OK] HTTPServer[nginx/1.24.0]"],
    )
    cfg = OmConfig(
        output_dir=str(tmp_path / "api_reports"),
        db_path=str(tmp_path / "api_reports" / "om.db"),
        profile="low",
        tool_paths={"whatweb": fake_whatweb, "wafw00f": str(tmp_path / "missing_waf")},
        archive_zip=False,
        quiet=True,
    )
    app = create_app(cfg)
    client = TestClient(app)

    # 1. Dashboard HTML served with security headers
    dash_res = client.get("/")
    assert dash_res.status_code == 200
    assert "OM <span>2.0</span>" in dash_res.text
    assert dash_res.headers["X-Frame-Options"] == "DENY"

    # 2. Cross-Origin POST is rejected (CSRF protection)
    csrf_res = client.post(
        "/api/scans/preview",
        headers={"Origin": "https://evil.attacker.example"},
        json={"target": "example.com", "profile": "low"},
    )
    assert csrf_res.status_code == 403

    # 3. Preview endpoint validates target and active authorisation
    prev_res = client.post(
        "/api/scans/preview",
        json={"target": "example.com", "profile": "medium", "authorize_active": False},
    )
    assert prev_res.status_code == 200
    assert prev_res.json()["requires_active_authorisation"] is True
    assert prev_res.json()["ready_to_execute"] is False

    # 4. Run real scan through API
    scan_res = client.post(
        "/api/scans",
        json={
            "target": "example.com",
            "profile": "low",
            "modules": ["webtech"],
            "scope": ["example.com"],
            "confirm_execution": True,
        },
    )
    assert scan_res.status_code == 200
    report = scan_res.json()
    session_id = report["session_id"]
    assert report["summary"]["total_findings"] == 1

    # 5. Overview, Scan Details, Web Intelligence, Exports, and Settings
    ov = client.get("/api/overview").json()
    assert ov["total_sessions"] == 1

    web_intel = client.get("/api/intelligence/web").json()
    assert web_intel["count"] == 1
    assert "nginx/1.24.0" in web_intel["items"][0]["value"]

    for fmt in ("html", "json", "csv"):
        exp = client.get(f"/api/scans/{session_id}/export?format={fmt}")
        assert exp.status_code == 200

    # Path traversal in settings is rejected
    bad_set = client.put("/api/settings", json={"output_dir": "../../etc"})
    assert bad_set.status_code == 422

    ok_set = client.put("/api/settings", json={"concurrency": 3, "timeout": 120})
    assert ok_set.status_code == 200
    assert ok_set.json()["config"]["concurrency"] == 3
