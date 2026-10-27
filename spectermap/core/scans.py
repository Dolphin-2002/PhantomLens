import asyncio

from ..database import Session
from ..models import Scan
from .crawler import crawl
from .events import bus
from .graph import build_graph, persist_graph

tasks = {}


async def run_scan(scan_id, target, max_pages):
    try:
        async with Session() as session:
            scan = await session.get(Scan, scan_id)
            scan.status = "running"
            await session.commit()
        bus.emit(f"Scan started: {target}", scan_id)
        report = await crawl(target, max_pages, lambda message: bus.emit(message, scan_id))
        async with Session() as session:
            await persist_graph(session, scan_id, build_graph(report))
            scan = await session.get(Scan, scan_id)
            scan.status = "completed"
            await session.commit()
        bus.emit("Scan completed", scan_id)
    except asyncio.CancelledError:
        async with Session() as session:
            scan = await session.get(Scan, scan_id)
            scan.status = "cancelled"
            await session.commit()
        bus.emit("Scan cancelled", scan_id)
        raise
    except Exception as exc:  # noqa: BLE001 - persist worker failures for the dashboard
        async with Session() as session:
            scan = await session.get(Scan, scan_id)
            scan.status, scan.error = "failed", str(exc)[:2000]
            await session.commit()
        bus.emit(f"Scan failed: {exc}", scan_id, "error")
    finally:
        tasks.pop(scan_id, None)
