"""Self-contained HTML, versioned JSON (v2.0), CSV report generators, and session comparison for Om 2.0.

Escapes all untrusted target and tool output (`html.escape(..., quote=True)`) and sets a
strict Content-Security-Policy so generated HTML reports can never execute injected scripts.
"""
from __future__ import annotations

import csv
import html
import io
import json
from typing import Any

from om import AUTHOR, SCHEMA_VERSION, __version__
from om.core.normalizer import strip_ansi
from om.models.schemas import Finding, ModuleExecutionResult

REQUIRED_REPORT_KEYS = {
    "schema_version",
    "tool_name",
    "tool_version",
    "author",
    "session_id",
    "status",
    "target",
    "target_type",
    "profile",
    "scope",
    "started_at",
    "completed_at",
    "duration_seconds",
    "summary",
    "tools",
    "findings",
    "errors",
    "limitations",
}


def build_report_document(
    *,
    session_id: str,
    status: str,
    target: str,
    target_type: str,
    profile: str,
    scope: list[str],
    started_at: str,
    completed_at: str,
    duration_seconds: float,
    tool_results: list[ModuleExecutionResult],
    findings: list[Finding],
) -> dict[str, Any]:
    """Build a versioned v2.0 structured report dictionary."""
    counts_by_status: dict[str, int] = {}
    errors: list[dict[str, str]] = []
    for res in tool_results:
        counts_by_status[res.status] = counts_by_status.get(res.status, 0) + 1
        if res.error:
            errors.append({"tool": res.tool, "status": res.status, "error": res.error})

    confirmed_count = sum(1 for f in findings if f.confidence == "confirmed")
    inferred_count = sum(1 for f in findings if f.confidence in {"inferred", "unverified"})
    issues_count = sum(1 for f in findings if f.classification == "confirmed_issue")

    by_category: dict[str, int] = {}
    for f in findings:
        by_category[f.category] = by_category.get(f.category, 0) + 1

    doc: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool_name": "Om",
        "tool_version": __version__,
        "author": AUTHOR,
        "session_id": session_id,
        "status": status,
        "target": target,
        "target_type": target_type,
        "profile": profile,
        "scope": scope or [target],
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_seconds": round(duration_seconds, 3),
        "summary": {
            "total_tools": len(tool_results),
            "tool_status_counts": counts_by_status,
            "total_findings": len(findings),
            "confirmed_findings": confirmed_count,
            "inferred_or_unverified_findings": inferred_count,
            "confirmed_issues": issues_count,
            "findings_by_category": by_category,
            "error_count": len(errors),
        },
        "tools": [t.to_dict(include_raw=False) for t in tool_results],
        "findings": [f.to_dict() for f in findings],
        "errors": errors,
        "limitations": [
            "Reconnaissance observations record point-in-time surface metadata and do not prove exploitability.",
            "Subdomain and OSINT results marked 'unverified' or 'inferred' must be validated against an authorised inventory.",
            "Missing, skipped, or failed tools are explicitly marked and must not be interpreted as negative findings.",
            "Severity labels ('medium'/'high') are assigned only when direct protocol evidence confirms a misconfiguration (e.g., AXFR enabled, deprecated SSL/TLS enabled, exposed sensitive file).",
        ],
    }
    return doc


def validate_report_schema(doc: dict[str, Any]) -> bool:
    """Validate that a report dictionary conforms to Om JSON Schema v2.0 (or compatible v1.0)."""
    if not isinstance(doc, dict):
        raise ValueError("Report must be a JSON object.")
    schema_ver = str(doc.get("schema_version", ""))
    if schema_ver not in {SCHEMA_VERSION, "1.0"}:
        raise ValueError(
            f"Unsupported schema_version '{schema_ver}' (expected '{SCHEMA_VERSION}' or '1.0')."
        )
    required_min = {
        "schema_version",
        "tool_name",
        "tool_version",
        "session_id",
        "target",
        "target_type",
        "profile",
        "scope",
        "started_at",
        "completed_at",
        "summary",
        "tools",
        "findings",
        "limitations",
    }
    missing = required_min - set(doc.keys())
    if missing:
        raise ValueError(f"Report is missing required schema keys: {', '.join(sorted(missing))}")
    if not isinstance(doc.get("tools"), list) or not isinstance(doc.get("findings"), list):
        raise ValueError("Report 'tools' and 'findings' fields must be lists.")
    return True


def render_json_report(doc: dict[str, Any]) -> str:
    validate_report_schema(doc)
    return json.dumps(doc, indent=2, ensure_ascii=False)


def render_csv_report(findings: list[Finding] | list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(
        [
            "category",
            "value",
            "classification",
            "confidence",
            "severity",
            "source_tool",
            "timestamp",
            "evidence",
            "detail",
            "limitations",
            "remediation",
        ]
    )
    for item in findings:
        d = item.to_dict() if isinstance(item, Finding) else item
        writer.writerow(
            [
                d.get("category", ""),
                d.get("value", ""),
                d.get("classification", "normalised_finding"),
                d.get("confidence", ""),
                d.get("severity", ""),
                d.get("source_tool", ""),
                d.get("timestamp", ""),
                d.get("evidence", ""),
                d.get("detail", ""),
                d.get("limitations", ""),
                d.get("remediation", ""),
            ]
        )
    return buf.getvalue()


def _esc(val: Any) -> str:
    return html.escape(str(val if val is not None else ""), quote=True)


def render_html_report(
    doc: dict[str, Any], tool_results: list[ModuleExecutionResult] | list[dict[str, Any]] | None = None
) -> str:
    """Render a self-contained, print-friendly dark cybersecurity HTML report.

    All dynamic strings are passed through `_esc` (`html.escape(..., quote=True)`).
    """
    validate_report_schema(doc)
    target = _esc(doc["target"])
    target_type = _esc(doc["target_type"])
    profile = _esc(str(doc["profile"]).upper())
    session_id = _esc(doc["session_id"])
    status_str = _esc(str(doc.get("status", "completed")).upper())
    started_at = _esc(doc["started_at"])
    completed_at = _esc(doc["completed_at"])
    scope_str = _esc(", ".join(doc.get("scope", [])))
    summary = doc.get("summary", {})
    status_counts = summary.get("tool_status_counts", {})

    tools_source = tool_results if tool_results is not None else doc.get("tools", [])

    tool_rows_html: list[str] = []
    raw_panels_html: list[str] = []

    for res in tools_source:
        t_dict = res.to_dict(include_raw=True) if isinstance(res, ModuleExecutionResult) else res
        t_name = t_dict.get("tool", "")
        t_cat = t_dict.get("category", "")
        t_status = t_dict.get("status", "")
        t_mode = t_dict.get("traffic_mode", "")
        t_dur = float(t_dict.get("duration_seconds", 0.0) or 0.0)
        t_ver = t_dict.get("version") or "—"
        t_err = t_dict.get("error")
        t_hint = t_dict.get("install_hint")
        t_stdout = t_dict.get("stdout") or t_dict.get("stdout_preview") or ""
        t_stderr = t_dict.get("stderr") or t_dict.get("stderr_preview") or ""

        badge_cls = {
            "completed": "badge-ok",
            "partial": "badge-warn",
            "failed": "badge-err",
            "timed_out": "badge-warn",
            "cancelled": "badge-warn",
            "skipped_missing": "badge-muted",
            "skipped_target_type": "badge-muted",
            "skipped_scope": "badge-muted",
        }.get(t_status, "badge-muted")

        note = t_err or (t_hint if t_status == "skipped_missing" else "Completed cleanly")
        tool_rows_html.append(
            f"<tr>"
            f"<td><strong>{_esc(t_name)}</strong></td>"
            f"<td>{_esc(t_cat)}</td>"
            f"<td><span class='badge {badge_cls}'>{_esc(t_status)}</span></td>"
            f"<td>{_esc(t_mode)}</td>"
            f"<td>{_esc(f'{t_dur:.2f}s')}</td>"
            f"<td>{_esc(t_ver)}</td>"
            f"<td class='muted'>{_esc(note)}</td>"
            f"</tr>"
        )

        cleaned_out = strip_ansi(t_stdout).strip()
        cleaned_err = strip_ansi(t_stderr).strip()
        if cleaned_out:
            body_html = f"<pre>{_esc(cleaned_out[:25000])}</pre>"
        elif t_status == "completed":
            body_html = "<p class='muted'>Module completed with exit code 0 and produced no output (negative result).</p>"
        elif t_status == "skipped_missing":
            body_html = f"<p class='warn-text'>Tool not installed. Install with: <code>{_esc(t_hint)}</code></p>"
        else:
            body_html = f"<p class='err-text'>Check did not complete ({_esc(t_status)}): {_esc(t_err)}</p>"
        if cleaned_err and t_status != "completed":
            body_html += (
                f"<details><summary class='muted'>Standard Error</summary>"
                f"<pre>{_esc(cleaned_err[:4000])}</pre></details>"
            )

        raw_panels_html.append(
            f"<section class='card'>"
            f"<div class='card-head'><h3>{_esc(t_cat)} — {_esc(t_name)}</h3>"
            f"<span class='badge {badge_cls}'>{_esc(t_status)}</span></div>"
            f"{body_html}</section>"
        )

    findings_list: list[dict[str, Any]] = doc.get("findings", [])
    finding_rows_html: list[str] = []
    for f in findings_list:
        conf = str(f.get("confidence", "unverified"))
        sev = str(f.get("severity", "info"))
        cls_name = str(f.get("classification", "normalised_finding"))
        conf_cls = "badge-ok" if conf == "confirmed" else "badge-warn"
        sev_cls = {"high": "badge-err", "medium": "badge-warn", "low": "badge-info"}.get(sev, "badge-muted")
        rem = f.get("remediation")
        detail_text = _esc(f.get("detail", ""))
        if rem:
            detail_text += f"<br><span class='gold-text'>Remediation: {_esc(rem)}</span>"
        finding_rows_html.append(
            f"<tr>"
            f"<td><code>{_esc(f.get('category'))}</code></td>"
            f"<td><strong>{_esc(f.get('value'))}</strong></td>"
            f"<td><code>{_esc(cls_name)}</code></td>"
            f"<td><span class='badge {conf_cls}'>{_esc(conf)}</span></td>"
            f"<td><span class='badge {sev_cls}'>{_esc(sev)}</span></td>"
            f"<td>{_esc(f.get('source_tool'))}</td>"
            f"<td class='muted'>{detail_text}</td>"
            f"</tr>"
        )
    if not finding_rows_html:
        finding_rows_html.append(
            "<tr><td colspan='7' class='muted'>No structured observations extracted in this session. "
            "Check module execution statuses above to distinguish negative results from skipped/missing tools.</td></tr>"
        )

    limitations_html = "".join(f"<li>{_esc(item)}</li>" for item in doc.get("limitations", []))

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>OM 2.0 Reconnaissance Report — {target}</title>
<style>
:root {{
  color-scheme: dark;
  --bg: #060a14;
  --panel: #0d1526;
  --panel-alt: #121e36;
  --border: #1e3252;
  --text: #e8f0fe;
  --muted: #94a8c7;
  --accent: #38bdf8;
  --gold: #eab308;
  --ok: #22c55e;
  --warn: #f59e0b;
  --err: #ef4444;
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0;
  background: radial-gradient(circle at top right, #102344 0%, var(--bg) 60%);
  color: var(--text);
  font: 14px/1.6 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
}}
main {{ max-width: 1220px; margin: 0 auto; padding: 28px 20px 48px; }}
header {{
  background: linear-gradient(135deg, #0f1d35 0%, #091120 100%);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 24px;
  margin-bottom: 20px;
}}
.brand {{ font-size: 12px; letter-spacing: 0.16em; text-transform: uppercase; color: var(--accent); font-weight: 700; }}
.brand span {{ color: var(--gold); }}
h1 {{ margin: 6px 0 12px; font-size: 26px; }}
h2 {{ font-size: 18px; margin: 26px 0 12px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }}
h3 {{ font-size: 15px; margin: 0; }}
.meta-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(175px, 1fr));
  gap: 10px;
  margin-top: 14px;
}}
.meta-box {{
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 10px 14px;
}}
.meta-box span {{ display: block; font-size: 11px; color: var(--muted); text-transform: uppercase; }}
.meta-box strong {{ font-size: 15px; color: var(--text); }}
.card {{
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 18px;
  margin-bottom: 14px;
}}
.card-head {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th, td {{ text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }}
th {{ color: var(--muted); font-weight: 600; background: var(--panel-alt); }}
.badge {{
  display: inline-block;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 600;
  background: #1e293b;
  color: var(--text);
}}
.badge-ok {{ background: rgba(34, 197, 94, 0.18); color: #86efac; border: 1px solid rgba(34, 197, 94, 0.35); }}
.badge-warn {{ background: rgba(245, 158, 11, 0.18); color: #fcd34d; border: 1px solid rgba(245, 158, 11, 0.35); }}
.badge-err {{ background: rgba(239, 68, 68, 0.18); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.35); }}
.badge-info {{ background: rgba(56, 189, 248, 0.18); color: #7dd3fc; border: 1px solid rgba(56, 189, 248, 0.35); }}
.badge-muted {{ background: #162033; color: var(--muted); }}
pre {{
  margin: 0;
  padding: 12px;
  background: #050911;
  border: 1px solid var(--border);
  border-radius: 8px;
  color: #dbeafe;
  overflow-x: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font-size: 12px;
}}
.muted {{ color: var(--muted); }}
.gold-text {{ color: #fde047; font-size: 12px; }}
.warn-text {{ color: #fcd34d; }}
.err-text {{ color: #fca5a5; }}
footer {{ margin-top: 32px; font-size: 12px; color: var(--muted); text-align: center; }}
@media print {{
  :root {{ color-scheme: light; }}
  body {{ background: #fff; color: #111; }}
  header, .card, .meta-box, pre, th {{ background: #fff !important; color: #111 !important; border-color: #ccc !important; }}
  .muted {{ color: #444 !important; }}
}}
</style>
</head>
<body>
<main>
  <header>
    <div class="brand">OM 2.0 · Automated Reconnaissance &amp; Intelligence Platform v{_esc(__version__)} · <span>Major_ADI</span></div>
    <h1>Reconnaissance Report — {target}</h1>
    <p class="muted">Session ID: <code>{session_id}</code> · Status: <code>{status_str}</code> · Target Type: <code>{target_type}</code> · Authorized Scope: <code>{scope_str}</code></p>
    <div class="meta-grid">
      <div class="meta-box"><span>Scan Profile</span><strong>{profile}</strong></div>
      <div class="meta-box"><span>Modules Completed</span><strong>{_esc(status_counts.get('completed', 0))} / {_esc(summary.get('total_tools', 0))}</strong></div>
      <div class="meta-box"><span>Confirmed Observations</span><strong>{_esc(summary.get('confirmed_findings', 0))}</strong></div>
      <div class="meta-box"><span>Inferred / Unverified</span><strong>{_esc(summary.get('inferred_or_unverified_findings', 0))}</strong></div>
      <div class="meta-box"><span>Started (UTC)</span><strong>{started_at}</strong></div>
      <div class="meta-box"><span>Completed (UTC)</span><strong>{completed_at}</strong></div>
    </div>
  </header>

  <h2>1. Module Execution Status</h2>
  <div class="card">
    <table>
      <thead>
        <tr><th>Module</th><th>Category</th><th>Status</th><th>Traffic Mode</th><th>Duration</th><th>Version</th><th>Notes / Guidance</th></tr>
      </thead>
      <tbody>
        {''.join(tool_rows_html)}
      </tbody>
    </table>
  </div>

  <h2>2. Normalised &amp; Deduplicated Observations</h2>
  <div class="card">
    <table>
      <thead>
        <tr><th>Category</th><th>Indicator / Observation</th><th>Classification</th><th>Confidence</th><th>Severity</th><th>Source(s)</th><th>Details &amp; Remediation</th></tr>
      </thead>
      <tbody>
        {''.join(finding_rows_html)}
      </tbody>
    </table>
  </div>

  <h2>3. Evidence Rules &amp; Limitations</h2>
  <div class="card">
    <ul class="muted">
      {limitations_html}
    </ul>
  </div>

  <h2>4. Module-by-Module Output Log</h2>
  {''.join(raw_panels_html)}

  <footer>
    Generated by <strong>Om v{_esc(__version__)}</strong> (Schema v{_esc(SCHEMA_VERSION)}) · Created by Major_ADI · Authorised defensive &amp; educational reconnaissance only.
  </footer>
</main>
</body>
</html>"""


def compare_reports(old_doc: dict[str, Any], new_doc: dict[str, Any]) -> dict[str, Any]:
    """Compare two Om report documents and return added, removed, and changed findings."""
    validate_report_schema(old_doc)
    validate_report_schema(new_doc)

    old_map: dict[tuple[str, str], dict[str, Any]] = {}
    for f in old_doc.get("findings", []):
        key = (str(f.get("category", "")), str(f.get("value", "")))
        old_map[key] = f

    new_map: dict[tuple[str, str], dict[str, Any]] = {}
    for f in new_doc.get("findings", []):
        key = (str(f.get("category", "")), str(f.get("value", "")))
        new_map[key] = f

    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    unchanged_count = 0

    for key, item in sorted(new_map.items()):
        if key not in old_map:
            added.append(item)
        else:
            prev = old_map[key]
            if (
                prev.get("confidence") != item.get("confidence")
                or prev.get("severity") != item.get("severity")
                or prev.get("classification") != item.get("classification")
                or prev.get("detail") != item.get("detail")
            ):
                changed.append({"category": key[0], "value": key[1], "before": prev, "after": item})
            else:
                unchanged_count += 1

    for key, item in sorted(old_map.items()):
        if key not in new_map:
            removed.append(item)

    return {
        "baseline_session": old_doc.get("session_id"),
        "baseline_target": old_doc.get("target"),
        "baseline_started_at": old_doc.get("started_at"),
        "current_session": new_doc.get("session_id"),
        "current_target": new_doc.get("target"),
        "current_started_at": new_doc.get("started_at"),
        "summary": {
            "added_count": len(added),
            "removed_count": len(removed),
            "changed_count": len(changed),
            "unchanged_count": unchanged_count,
        },
        "added": added,
        "removed": removed,
        "changed": changed,
    }
