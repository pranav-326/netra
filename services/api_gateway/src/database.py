"""PostgreSQL Persistence Layer using SQLAlchemy (Layers 7 & 8)
Stores finalized threat intelligence reports, classification metrics, and IOC graphs.
"""

from datetime import datetime
from typing import AsyncGenerator

from sqlalchemy import Column, String, Integer, DateTime, JSON, Text
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
