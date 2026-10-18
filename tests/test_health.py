from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_ok():
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_health_db_returns_503_when_database_unavailable(monkeypatch):
    async def boom():
        raise RuntimeError("db down")

    monkeypatch.setattr("app.routers.health.ping_db", boom)
    r = client.get("/api/v1/health/db")
    assert r.status_code == 503
