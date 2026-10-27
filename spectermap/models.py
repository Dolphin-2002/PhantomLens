from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def now():
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[str] = mapped_column(String(2048), unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"))
    status: Mapped[str] = mapped_column(default="queued")
    error: Mapped[str | None]
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("scan_id", "key"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    key: Mapped[str]
    kind: Mapped[str]
    label: Mapped[str]
    risk: Mapped[float] = mapped_column(Float, default=0)
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class OpenPort(Base):
    __tablename__ = "open_ports"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(default="tcp")
    service: Mapped[str]
    version: Mapped[str] = mapped_column(default="")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    cve: Mapped[str]
    summary: Mapped[str]
    severity: Mapped[float] = mapped_column(Float)
    confidence: Mapped[str] = mapped_column(default="candidate")
    reference: Mapped[str] = mapped_column(default="")


class Relationship(Base):
    __tablename__ = "relationships"
    __table_args__ = (UniqueConstraint("source_id", "target_id", "kind"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    target_id: Mapped[int] = mapped_column(ForeignKey("assets.id"))
    kind: Mapped[str]
