"""Report renderers for persisted Sentinel runs."""
from __future__ import annotations
import html
import json
from typing import Any


def json_report(run: dict[str, Any]) -> str:
    return json.dumps(run, indent=2, ensure_ascii=False)


def html_report(run: dict[str, Any]) -> str:
    payload = run.get("payload", {})
    domain = html.escape(str(run.get("domain", payload.get("domain", "unknown"))))
    created = html.escape(str(run.get("created_at", payload.get("created_at", ""))))
    score = html.escape(str(run.get("risk_score", payload.get("risk_score", {}).get("score", 0))))
    pretty = html.escape(json.dumps(payload, indent=2, ensure_ascii=False))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Om Sentinel Report — {domain}</title>
<style>
body{{margin:0;background:#080d18;color:#e8f0ff;font:15px/1.6 system-ui,sans-serif}}
main{{max-width:1000px;margin:auto;padding:32px 20px}}header,section{{background:#101a2a;border:1px solid #24344b;border-radius:12px;padding:20px;margin:16px 0}}
h1{{margin-top:0}}.muted{{color:#9aabc3}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#080f1b;padding:16px;border-radius:8px;overflow:auto}}
</style></head><body><main><header><p class="muted">OM SENTINEL · DEFENSIVE REPORT</p><h1>{domain}</h1><p>Created: {created}</p><p>Metadata indicator: {score}/100</p></header>
<section><h2>Evidence and limitations</h2><p>Public records and keyword-matched CVEs are leads only; they do not establish that the target is vulnerable. Validate findings against an authorised asset inventory and vendor advisories.</p></section>
<section><h2>Machine-readable evidence</h2><pre>{pretty}</pre></section></main></body></html>"""
