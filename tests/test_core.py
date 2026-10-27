import httpx
import pytest

from spectermap.core.crawler import crawl, parse_target
from spectermap.core.graph import build_graph
from spectermap.core.matcher import match_vulnerabilities


def test_targets_and_matcher():
    assert parse_target("example.com") == "https://example.com/"
    assert parse_target("::1") == "https://[::1]/"
    for target in ["some company", "file:///etc/passwd", "https://user:pass@example.com"]:
        with pytest.raises(ValueError):
            parse_target(target)
    assert match_vulnerabilities("apache", "2.4.49")[0]["cve"] == "CVE-2021-41773"
    assert not match_vulnerabilities("apache", "2.4.51")
    assert not match_vulnerabilities("apache", "unknown")


def test_graph_risk_and_evidence():
    graph = build_graph(
        {
            "host": "example.com",
            "ips": ["127.0.0.1"],
            "pages": [
                {
                    "url": "https://example.com/",
                    "status": 200,
                    "documents": ["https://example.com/a.pdf"],
                }
            ],
            "services": [{"port": 443, "banner": "Apache/2.4.49"}],
        }
    )
    assert graph.nodes["host:example.com"]["risk"] == 7.5
    assert graph.has_edge("service:443:Apache/2.4.49", "cve:CVE-2021-41773")
    assert graph.has_edge("url:https://example.com/", "doc:https://example.com/a.pdf")


@pytest.mark.asyncio
async def test_crawler_scope(monkeypatch):
    calls = []

    async def handler(request):
        calls.append(str(request.url))
        return httpx.Response(
            200,
            headers={"content-type": "text/html", "server": "Apache/2.4.49"},
            text='<title>Test</title><a href="/next">next</a><a href="https://outside.invalid/">outside</a>',
        )

    original = httpx.AsyncClient
    monkeypatch.setattr(
        httpx, "AsyncClient", lambda **kw: original(transport=httpx.MockTransport(handler), **kw)
    )
    report = await crawl("http://localhost/", 2, lambda _: None)
    assert len(report["pages"]) == 2
    assert report["pages"][0]["title"] == "Test"
    assert calls == ["http://localhost/", "http://localhost/next"]
