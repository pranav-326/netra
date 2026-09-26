"""PostgreSQL Persistence Layer using SQLAlchemy (Layers 7 & 8)
Stores finalized threat intelligence reports, classification metrics, and IOC graphs.
"""

from datetime import datetime
from typing import AsyncGenerator

from sqlalchemy import BigInteger, Boolean, Column, String, Integer, DateTime, JSON, Text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base

from netra_common.config import settings

Base = declarative_base()


class EmailReport(Base):
    """Finalized threat analysis and correlation report for an email."""
    __tablename__ = "email_reports"

    email_id = Column(String(64), primary_key=True, index=True)
    subject = Column(Text, nullable=True)
    sender = Column(Text, nullable=True)
    classification = Column(String(32), nullable=False, index=True)
    risk_score = Column(Integer, nullable=False, index=True)
    campaign_id = Column(String(64), nullable=True, index=True)
    full_report = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class User(Base):
    """An analyst or administrator who can sign in (Layer 9)."""
    __tablename__ = "users"

    username = Column(String(32), primary_key=True)
    password_hash = Column(Text, nullable=False)
    role = Column(String(16), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditRecord(Base):
    """Append-only record of who did what to which evidence (Layer 9)."""
    __tablename__ = "audit_events"

    id = Column(BigInteger, primary_key=True, autoincrement=True)
    at = Column(DateTime, nullable=False, index=True)
    service = Column(String(32), nullable=False)
    username = Column(String(32), nullable=True, index=True)
    role = Column(String(16), nullable=True)
    action = Column(String(48), nullable=False, index=True)
    resource = Column(String(128), nullable=True, index=True)
    success = Column(Boolean, nullable=False)
    client_ip = Column(String(64), nullable=True)
    detail = Column(JSON, nullable=False)


# Async database engine & session factory
engine = create_async_engine(
    settings.postgres_async_url,
    echo=False,
    pool_pre_ping=True,
)
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def init_db():
    """Create tables if they do not already exist."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency generator for database sessions."""
    async with async_session_maker() as session:
        yield session
