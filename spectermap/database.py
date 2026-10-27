import os

from sqlalchemy import event
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from .models import Base

engine = create_async_engine(
    os.getenv("SPECTERMAP_DATABASE_URL", "sqlite+aiosqlite:///./spectermap.db")
)
Session = async_sessionmaker(engine, expire_on_commit=False)


@event.listens_for(engine.sync_engine, "connect")
def configure_sqlite(connection, _):
    cursor = connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


async def initialize():
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
