import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target: Mapped[str] = mapped_column(String(512))
    target_type: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    overall_risk: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(16), default="safe")
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    scan_duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    files_analyzed: Mapped[int] = mapped_column(Integer, default=0)
    urls_checked: Mapped[int] = mapped_column(Integer, default=0)
    deps_analyzed: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    content_hashes_json: Mapped[str] = mapped_column(Text, default="{}")
    rescan_of: Mapped[str | None] = mapped_column(String(36), nullable=True)

    findings: Mapped[list["Finding"]] = relationship(back_populates="scan", lazy="selectin")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"))
    category: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    title: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    cwe: Mapped[str | None] = mapped_column(String(16), nullable=True)
    owasp: Mapped[str | None] = mapped_column(String(32), nullable=True)
    references_json: Mapped[str] = mapped_column(Text, default="[]")

    scan: Mapped["Scan"] = relationship(back_populates="findings")
