"""Self-contained HTML, versioned JSON, and CSV report generators for Om 2.0."""
from __future__ import annotations

from om.reporting.generator import (
    REQUIRED_REPORT_KEYS,
    build_report_document,
    compare_reports,
    render_csv_report,
    render_html_report,
    render_json_report,
    validate_report_schema,
)

__all__ = [
    "REQUIRED_REPORT_KEYS",
    "build_report_document",
    "compare_reports",
    "render_csv_report",
    "render_html_report",
    "render_json_report",
    "validate_report_schema",
]
