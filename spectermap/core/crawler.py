import asyncio
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from bs4 import BeautifulSoup


def parse_target(value: str) -> str:
    value = value.strip()
    if not value or any(c.isspace() for c in value):
        raise ValueError("Enter a domain, IP address, or HTTP(S) URL. Company names need a domain.")
    try:
        address = ipaddress.ip_address(value)
        value = f"[{address}]" if address.version == 6 else str(address)
    except ValueError:
        pass
    parsed = urlsplit(value if "://" in value else "https://" + value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise ValueError("Target must be an HTTP(S) URL without credentials.")
    try:
        _ = parsed.port  # Access validates malformed ports.
        parsed.hostname.encode("idna")
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid hostname or port.") from exc
    return urlunsplit((parsed.scheme, parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))


def origin(url):
    p = urlsplit(url)
    return p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)


async def crawl(target: str, max_pages: int, log) -> dict:
    """Bounded same-origin GET crawler. No redirect escapes or exploit execution."""
    parsed = urlsplit(target)
    host = parsed.hostname
    result = {"target": target, "host": host, "ips": [], "pages": [], "services": []}
    try:
        records = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM), 8
        )
        result["ips"] = sorted({record[4][0] for record in records})
        log(f"DNS: {host} → {', '.join(result['ips'])}")
    except (OSError, TimeoutError) as exc:
        raise ValueError(f"DNS lookup failed for {host}: {exc}") from exc
    pending, visited = [target], set()
    async with httpx.AsyncClient(
        timeout=8,
        follow_redirects=False,
        trust_env=False,
        headers={"User-Agent": "SpecterMap/0.1 (authorized surface inventory)"},
    ) as client:
        while pending and len(visited) < max_pages:
            url = pending.pop(0)
            if url in visited:
                continue
            visited.add(url)
            log(f"GET {url}")
            try:
                async with client.stream("GET", url) as response:
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk[: max(0, 1_000_000 - len(body))])
                        if len(body) >= 1_000_000:
                            break
                    page = {
                        "url": url,
                        "status": response.status_code,
                        "title": "",
                        "documents": [],
                    }
                    banner = response.headers.get("server", "")
                    if banner:
                        result["services"].append({"banner": banner, "port": origin(url)[2]})
                    links = []
                    if "text/html" in response.headers.get("content-type", ""):
                        soup = BeautifulSoup(bytes(body), "html.parser")
                        page["title"] = soup.title.get_text(strip=True)[:300] if soup.title else ""
                        links = [a.get("href", "") for a in soup.find_all("a", href=True)]
                        page["description"] = next(
                            (
                                m.get("content", "")[:500]
                                for m in soup.find_all("meta")
                                if m.get("name", "").lower() == "description"
                            ),
                            "",
                        )
                    if response.is_redirect:
                        links.append(response.headers.get("location", ""))
                    for link in links[:500]:
                        try:
                            resolved = urlsplit(urljoin(url, link))
                            absolute = urlunsplit(resolved._replace(fragment=""))
                            if (
                                resolved.username
                                or resolved.password
                                or origin(absolute) != origin(target)
                            ):
                                continue
                        except ValueError:
                            continue
                        if resolved.path.lower().endswith(
                            (".pdf", ".doc", ".docx", ".xls", ".xlsx")
                        ):
                            page["documents"].append(absolute)
                        if (
                            absolute not in visited
                            and absolute not in pending
                            and len(pending) < 200
                        ):
                            pending.append(absolute)
                    result["pages"].append(page)
            except httpx.HTTPError as exc:
                log(f"Request failed: {type(exc).__name__}: {exc}")
                result["pages"].append({"url": url, "error": str(exc)})
            await asyncio.sleep(0.1)
    if not any("status" in page for page in result["pages"]):
        raise ValueError("No HTTP responses received; check target scheme, TLS, and connectivity.")
    return result
