from app.scoring import score_enrichment
from app.reports import html_report, json_report


def test_score_is_conservative_and_bounded():
    result = score_enrichment({"certificates": {"status": "ok", "count": 2}, "cves": {"status": "ok", "results": [{"id": "CVE-1"}]}})
    assert result["score"] == 15
    assert "not proof" in " ".join(result["reasons"]).lower()


def test_html_report_escapes_untrusted_target_text():
    report = html_report({"domain": "<script>alert(1)</script>", "payload": {"domain": "<script>alert(1)</script>"}})
    assert "<script>alert(1)</script>" not in report
    assert "&lt;script&gt;" in report


def test_json_report_is_valid_json():
    import json
    run = {"id": "abc", "payload": {"domain": "example.com"}}
    assert json.loads(json_report(run))["id"] == "abc"
