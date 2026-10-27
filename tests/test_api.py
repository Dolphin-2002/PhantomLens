from fastapi.testclient import TestClient

from spectermap.core.events import bus
from spectermap.main import app


def test_dashboard_api_and_stream():
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        assert client.get("/static/app.js").status_code == 200
        assert client.get("/api/health").json()["status"] == "ok"
        assert client.post("/api/scans", json={"target": "invalid company"}).status_code == 422
        assert client.get("/api/scans/999/graph").status_code == 404
        with client.websocket_connect("/ws/logs") as websocket:
            client.portal.call(bus.emit, "test event", 42)
            assert websocket.receive_json()["message"] == "test event"


def test_scan_persisted_graph(monkeypatch):
    async def fake_crawl(target, max_pages, log):
        log("mock crawl")
        return {
            "target": target,
            "host": "example.com",
            "ips": ["192.0.2.1"],
            "pages": [{"url": target, "status": 200}],
            "services": [{"port": 443, "banner": "Apache/2.4.49"}],
        }

    monkeypatch.setattr("spectermap.core.scans.crawl", fake_crawl)
    with TestClient(app) as client:
        response = client.post("/api/scans", json={"target": "example.com"})
        assert response.status_code == 202
        scan_id = response.json()["id"]
        import time

        for _ in range(100):
            scans = client.get("/api/scans").json()
            scan = next(s for s in scans if s["id"] == scan_id)
            if scan["status"] in ["completed", "failed"]:
                break
            time.sleep(0.02)
        assert scan["status"] == "completed", scan
        graph = client.get(f"/api/scans/{scan_id}/graph").json()
        assert any(n["data"]["kind"] == "cve" for n in graph["nodes"])
        assert graph["edges"]
        assert client.get("/api/targets").json()
