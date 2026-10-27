# SpecterMap

A local FastAPI application for attack surface inventory, structural web crawling, and advisory correlation on Kali Linux / Python 3.11+. SQLite stores scans and graph evidence; NetworkX calculates relationships and propagates the highest connected candidate CVSS score to ancestors. The browser renders the resulting graph with Cytoscape.js.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
uvicorn spectermap.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. Enter a domain, IP, or HTTP(S) URL, select a page limit, and start a scan. Use an explicit `http://` URL for HTTP-only services or custom ports. A company name must first be resolved to a domain. Python virtual environments keep dependencies separate from Kali's system Python; install `python3-venv` through apt if it is missing.

The dashboard provides scan history, cancellation, node inspection, graph JSON export, and reconnecting WebSocket logs. API documentation is at `/docs`. Runs need DNS/network access to the target; the dashboard libraries currently load from pinned CDN URLs, so a browser needs internet access. For an air-gapped setup, download these libraries into `spectermap/static/vendor/` and update the three script URLs in the template. Scan data remains local.

## Layout

```text
pyproject.toml
spectermap/
  main.py                   # App lifecycle, template and static serving
  database.py               # Async SQLite sessions and initialization
  models.py                 # Target, Scan, Asset, OpenPort, Vulnerability, Relationship
  api/routes.py             # REST API and WebSocket logs
  core/
    crawler.py              # Validated targets, DNS, bounded same-origin crawl
    matcher.py              # Local product/version advisory candidates
    graph.py                # NetworkX topology, risk propagation, persistence
    scans.py                # Background task lifecycle and cancellation
    events.py               # Bounded in-memory log fanout and replay
  data/vulnerabilities.json # Small example advisory mapping
  templates/index.html      # Tailwind/Alpine dashboard
  static/app.js             # Cytoscape, controls, polling, WebSockets
  static/style.css
 tests/
  test_core.py
  test_api.py
```

## Behavior and extension points

The worker gathers DNS addresses, page titles/descriptions, same-origin links, document URLs, response statuses, and advertised HTTP server versions. It caps requests at 50 pages, limits response reads to 1 MB, uses timeouts, and never follows off-origin redirects. It does not download document contents. A server header is an observation about a virtual host; it is not evidence that every resolved IP independently exposes that service.

`build_graph(report)` accepts structured JSON with `host`, `ips`, `pages`, and `services`. Services contain `banner` and `port`; pages contain `url`, optional `status`, `title`, and `documents`. Add tool-specific adapters here for authorized Nmap/Amass results. Current assets include domains, IPs, endpoints, documents, services, and CVEs. The current graph visualizes observed relationships; it does not establish exploitable attack paths.

`match_vulnerabilities(product, version)` uses the bundled example dictionary. Extend it with verified advisories and product-specific version ranges. These are candidates requiring patch/configuration verification, especially for distro backports. No NVD download, WHOIS/DNS-history provider, email lookup, subdomain enumeration, directory fuzzing, Searchsploit integration, or exploit launcher is implemented. No exploits are executed.

SQLite defaults to `./spectermap.db`; override with `SPECTERMAP_DATABASE_URL=sqlite+aiosqlite:////absolute/path/spectermap.db`. The schema initializes automatically. Use migrations before evolving an existing deployment's schema. Scan results persist; the latest 300 log events remain in memory. Restarted scans become `interrupted`; failed/cancelled scans retain status but partial graph results are not saved.

The application is intended for one local operator and authorized targets. Keep it bound to loopback: it has no multiuser authentication. Trusted-host checks and same-origin WebSocket checks are enabled. Use one Uvicorn worker because task control and log fanout are process-local. Use a task queue and shared event broker before adding workers. Crawls may contact private/loopback addresses supplied by the operator.

## API

- `GET /api/health`, `GET /api/targets`, `GET /api/scans`
- `POST /api/scans` with `{"target":"https://example.com", "max_pages":10}`
- `POST /api/scans/{id}/cancel`
- `GET /api/scans/{id}/graph` returns Cytoscape nodes and edges
- `WS /ws/logs` replays the bounded history, then streams events with scan IDs

## Verify

```bash
pytest
ruff check spectermap tests
```

Implementation references: [FastAPI WebSockets](https://fastapi.tiangolo.com/advanced/websockets/), [FastAPI templates](https://fastapi.tiangolo.com/advanced/templates/), and [SQLAlchemy asyncio](https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html).
