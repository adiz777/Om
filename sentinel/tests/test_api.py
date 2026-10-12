import json

from fastapi.testclient import TestClient

from app.main import app


def test_health_is_public():
    with TestClient(app) as client:
        response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["service"] == "Om Sentinel"


def test_api_requires_configured_key(monkeypatch):
    monkeypatch.delenv("OM_SENTINEL_API_KEY", raising=False)
    with TestClient(app) as client:
        response = client.get("/api/runs")
    assert response.status_code == 503


def test_api_rejects_wrong_key(monkeypatch):
    monkeypatch.setenv("OM_SENTINEL_API_KEY", "test-secret")
    with TestClient(app) as client:
        response = client.get("/api/runs", headers={"X-Om-Api-Key": "wrong"})
    assert response.status_code == 401


def test_import_stores_data_without_execution(monkeypatch, tmp_path):
    monkeypatch.setenv("OM_SENTINEL_API_KEY", "test-secret")
    monkeypatch.setenv("OM_SENTINEL_DB_PATH", str(tmp_path / "test.db"))
    payload = {
        "domain": "example.com",
        "source": "test fixture",
        "findings": [{"title": "<script>alert(1)</script>", "detail": "untrusted text"}],
        "notes": "Imported only",
    }
    with TestClient(app) as client:
        response = client.post("/api/import", headers={"X-Om-Api-Key": "test-secret"}, json=payload)
        assert response.status_code == 200
        run_id = response.json()["run"]["id"]
        stored = client.get(f"/api/runs/{run_id}", headers={"X-Om-Api-Key": "test-secret"})
    assert stored.status_code == 200
    assert stored.json()["payload"]["findings"][0]["title"] == "<script>alert(1)</script>"
    assert "does not execute" in " ".join(stored.json()["payload"]["limitations"])


def test_invalid_domain_rejected_before_upstream_calls(monkeypatch):
    monkeypatch.setenv("OM_SENTINEL_API_KEY", "test-secret")
    with TestClient(app) as client:
        response = client.post(
            "/api/enrich",
            headers={"X-Om-Api-Key": "test-secret"},
            json={"domain": "http://127.0.0.1"},
        )
    assert response.status_code == 422
