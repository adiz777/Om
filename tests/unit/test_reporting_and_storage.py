"""Unit tests for SQLite persistence, report generation, HTML XSS escaping, and session comparison."""
from __future__ import annotations

import json
from pathlib import Path

from om.models.schemas import Finding, ModuleExecutionResult
from om.reporting.generator import (
    build_report_document,
    compare_reports,
    render_csv_report,
    render_html_report,
    render_json_report,
    validate_report_schema,
)
from om.storage.database import (
    delete_session,
    get_session,
    init_db,
    list_sessions,
    save_session,
)


def _sample_report(session_id: str, findings: list[Finding]) -> dict:
    tool_res = [
        ModuleExecutionResult(
            tool="whatweb",
            module_group="webtech",
            category="WebTech",
            traffic_mode="light-active",
            estimated_impact="low",
            status="completed",
            exit_code=0,
            duration_seconds=1.25,
            stdout="<script>alert('xss-from-stdout')</script>",
            version="0.5.5",
        )
    ]
    return build_report_document(
        session_id=session_id,
        status="completed",
        target="example.com",
        target_type="domain",
        profile="low",
        scope=["example.com"],
        started_at="2026-10-28T10:00:00+00:00",
        completed_at="2026-10-28T10:00:02+00:00",
        duration_seconds=2.0,
        tool_results=tool_res,
        findings=findings,
    )


def test_html_report_escapes_untrusted_content_and_sets_csp() -> None:
    xss_finding = Finding(
        category="web_tech",
        value='<img src=x onerror="alert(1)">',
        classification="normalised_finding",
        confidence="confirmed",
        severity="info",
        source_tool="whatweb",
        detail="<script>evil()</script>",
    )
    doc = _sample_report("sess_xss_1", [xss_finding])
    assert validate_report_schema(doc) is True

    html_out = render_html_report(doc)
    assert "Content-Security-Policy" in html_out
    assert "<script>alert('xss-from-stdout')</script>" not in html_out
    assert "&lt;script&gt;alert(&#x27;xss-from-stdout&#x27;)&lt;/script&gt;" in html_out
    assert '<img src=x onerror="alert(1)">' not in html_out
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in html_out

    json_out = render_json_report(doc)
    parsed = json.loads(json_out)
    assert parsed["schema_version"] == "2.0"

    csv_out = render_csv_report([xss_finding])
    assert "category,value,classification,confidence,severity" in csv_out


def test_sqlite_storage_and_session_comparison(tmp_path: Path) -> None:
    db_file = tmp_path / "test_om.db"
    init_db(db_file)

    f1 = Finding(
        category="subdomain",
        value="old.example.com",
        classification="normalised_finding",
        confidence="unverified",
        severity="info",
        source_tool="amass",
    )
    f2 = Finding(
        category="subdomain",
        value="shared.example.com",
        classification="normalised_finding",
        confidence="unverified",
        severity="info",
        source_tool="amass",
    )
    doc1 = _sample_report("sess_1", [f1, f2])
    save_session(doc1, tmp_path / "s1", db_path=db_file)

    f2_upgraded = Finding(
        category="subdomain",
        value="shared.example.com",
        classification="normalised_finding",
        confidence="confirmed",
        severity="info",
        source_tool="dnsrecon",
    )
    f3_new = Finding(
        category="open_port",
        value="443/tcp (https)",
        classification="normalised_finding",
        confidence="confirmed",
        severity="info",
        source_tool="nmap",
    )
    doc2 = _sample_report("sess_2", [f2_upgraded, f3_new])
    save_session(doc2, tmp_path / "s2", db_path=db_file)

    listing = list_sessions(db_path=db_file, target_filter="example.com")
    assert listing["total"] == 2

    loaded1 = get_session("sess_1", db_path=db_file)
    loaded2 = get_session("sess_2", db_path=db_file)
    assert loaded1 is not None and loaded2 is not None

    diff = compare_reports(loaded1, loaded2)
    assert diff["summary"]["added_count"] == 1
    assert diff["summary"]["removed_count"] == 1
    assert diff["summary"]["changed_count"] == 1
    assert diff["added"][0]["value"] == "443/tcp (https)"
    assert diff["removed"][0]["value"] == "old.example.com"
    assert diff["changed"][0]["value"] == "shared.example.com"

    assert delete_session("sess_1", db_path=db_file) is True
    assert get_session("sess_1", db_path=db_file) is None
