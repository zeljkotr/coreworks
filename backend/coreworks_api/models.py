from datetime import datetime

from sqlalchemy import CheckConstraint, Column, DateTime, ForeignKey, Index, Integer, String, Text, func, text
from sqlalchemy.orm import Mapped, mapped_column

from coreworks_api.db import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("role IN ('admin', 'user')", name="ck_users_role"),
        Index("uq_users_username_lower", text("lower(username)"), unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(20), nullable=False, default="user", server_default="user"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class GuardianScan(Base):
    __tablename__ = "coreworks_guardian_scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    target = Column(String(255), nullable=False)
    scanned_at = Column(DateTime(timezone=True), nullable=False)
    hosts_checked = Column(Integer, nullable=False, default=0)
    ports_per_host = Column(Integer, nullable=False, default=0)
    checks_completed = Column(Integer, nullable=False, default=0)
    open_ports = Column(Integer, nullable=False, default=0)


class GuardianFinding(Base):
    __tablename__ = "coreworks_guardian_findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(
        Integer,
        ForeignKey("coreworks_guardian_scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    host = Column(String(255), nullable=False)
    port = Column(Integer, nullable=False)
    service = Column(String(100), nullable=False, default="unknown")
    product = Column(String(255), nullable=False, default="")
    version = Column(String(255), nullable=False, default="")
    evidence = Column(Text, nullable=False, default="")
    confidence = Column(String(50), nullable=False, default="medium")
    severity = Column(String(50), nullable=False, default="info")
    title = Column(String(255), nullable=False)
    recommendation = Column(Text, nullable=False, default="")
