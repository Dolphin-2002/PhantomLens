import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import update
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .api.routes import router
from .core.scans import tasks
from .database import Session, engine, initialize
from .models import Scan

ROOT = Path(__file__).resolve().parent


@asynccontextmanager
async def lifespan(app):
    await initialize()
    async with Session() as session:
        await session.execute(
            update(Scan)
            .where(Scan.status.in_(["queued", "running"]))
            .values(status="interrupted", error="Application restarted")
        )
        await session.commit()
    yield
    active = list(tasks.values())
    for task in active:
        task.cancel()
    await asyncio.gather(*active, return_exceptions=True)
    await engine.dispose()


app = FastAPI(title="SpecterMap", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"]
)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
app.include_router(router)
templates = Jinja2Templates(directory=ROOT / "templates")


@app.get("/")
async def dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={})
