import asyncio

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from ..core.crawler import parse_target
from ..core.events import bus
from ..core.graph import graph_elements
from ..core.scans import run_scan, tasks
from ..database import Session
from ..models import Scan, Target

router = APIRouter()


class ScanRequest(BaseModel):
    target: str = Field(max_length=2048)
    max_pages: int = Field(default=10, ge=1, le=50)

    @field_validator("target")
    @classmethod
    def valid_target(cls, value):
        return parse_target(value)


@router.get("/api/health")
async def health():
    return {"status": "ok", "name": "SpecterMap"}


@router.get("/api/targets")
async def targets():
    async with Session() as session:
        return (await session.scalars(select(Target).order_by(Target.id.desc()))).all()


@router.get("/api/scans")
async def scans():
    async with Session() as session:
        rows = (
            await session.execute(
                select(Scan, Target.value).join(Target).order_by(Scan.id.desc()).limit(100)
            )
        ).all()
        return [
            {
                "id": s.id,
                "target": value,
                "status": s.status,
                "error": s.error,
                "created_at": s.created_at,
            }
            for s, value in rows
        ]


@router.post("/api/scans", status_code=202)
async def start_scan(body: ScanRequest):
    if len(tasks) >= 3:
        raise HTTPException(429, "Three scans are already running")
    async with Session() as session:
        # SQLite upsert handles concurrent requests for the same target.
        from sqlalchemy.dialects.sqlite import insert

        await session.execute(
            insert(Target)
            .values(value=body.target)
            .on_conflict_do_nothing(index_elements=["value"])
        )
        target = await session.scalar(select(Target).where(Target.value == body.target))
        scan = Scan(target_id=target.id)
        session.add(scan)
        await session.commit()
        tasks[scan.id] = asyncio.create_task(run_scan(scan.id, body.target, body.max_pages))
        return {"id": scan.id, "status": "queued"}


@router.post("/api/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: int):
    task = tasks.get(scan_id)
    if not task:
        raise HTTPException(409, "Scan is not running")
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    async with Session() as session:
        scan = await session.get(Scan, scan_id)
        if scan.status in {"queued", "running"}:
            scan.status = "cancelled"
            await session.commit()
    tasks.pop(scan_id, None)
    return {"status": "cancelled"}


@router.get("/api/scans/{scan_id}/graph")
async def graph(scan_id: int):
    async with Session() as session:
        if not await session.get(Scan, scan_id):
            raise HTTPException(404, "Scan not found")
        return await graph_elements(session, scan_id)


@router.websocket("/ws/logs")
async def logs(websocket: WebSocket):
    origin = websocket.headers.get("origin")
    if origin:
        from urllib.parse import urlsplit

        if urlsplit(origin).netloc != websocket.headers.get("host"):
            await websocket.close(code=1008)
            return
    await websocket.accept()
    queue = bus.subscribe()

    async def send():
        for item in list(bus.history):
            await websocket.send_json(item)
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), 20)
            except TimeoutError:
                item = {"type": "heartbeat"}
            await websocket.send_json(item)

    async def receive():
        while True:
            await websocket.receive_text()

    workers = [asyncio.create_task(send()), asyncio.create_task(receive())]
    try:
        done, _ = await asyncio.wait(workers, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        bus.listeners.discard(queue)
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
