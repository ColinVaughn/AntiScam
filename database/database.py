import asyncio
import asyncpg
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool
from contextlib import asynccontextmanager
import os
from typing import AsyncGenerator
import logging

from .models import Base

logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.engine = create_async_engine(
            database_url,
            poolclass=NullPool,
            echo=False,
            future=True
        )
        self.async_session_maker = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

    async def create_tables(self):
        """Create all database tables"""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created successfully")

    async def drop_tables(self):
        """Drop all database tables"""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        logger.info("Database tables dropped successfully")

    async def close(self):
        """Close database engine"""
        await self.engine.dispose()
        logger.info("Database connection closed")

    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get async database session"""
        async with self.async_session_maker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

# Global database manager instance
db_manager: DatabaseManager = None

def init_database(database_url: str) -> DatabaseManager:
    """Initialize the global database manager"""
    global db_manager
    db_manager = DatabaseManager(database_url)
    return db_manager

async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Get database session dependency for FastAPI"""
    if db_manager is None:
        raise RuntimeError("Database manager not initialized")
    
    async with db_manager.get_session() as session:
        yield session

async def create_default_guild_config(guild_id: str) -> None:
    """Create default configuration for a new guild"""
    from .models import GuildConfig
    
    if db_manager is None:
        raise RuntimeError("Database manager not initialized")
    
    async with db_manager.get_session() as session:
        # Check if config already exists
        existing = await session.get(GuildConfig, guild_id)
        if existing:
            return
        
        config = GuildConfig(
            guild_id=guild_id,
            auto_delete_confidence=0.9,
            flag_threshold=0.5,
            enable_ocr=True,
            enable_llm=True,
            enable_rules=True,
            retention_days=30
        )
        session.add(config)
        await session.commit()
        logger.info(f"Created default config for guild {guild_id}")

async def cleanup_old_records(retention_days: int = 30) -> None:
    """Clean up old flagged messages and logs based on retention policy"""
    from .models import FlaggedMessage, SystemLog
    from datetime import datetime, timedelta
    
    if db_manager is None:
        raise RuntimeError("Database manager not initialized")
    
    cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
    
    async with db_manager.get_session() as session:
        # Clean up old flagged messages
        result = await session.execute(
            "DELETE FROM flagged_messages WHERE created_at < $1 AND status = 'reviewed'",
            cutoff_date
        )
        
        # Clean up old system logs (keep errors longer)
        result2 = await session.execute(
            "DELETE FROM system_logs WHERE created_at < $1 AND level NOT IN ('ERROR', 'CRITICAL')",
            cutoff_date
        )
        
        await session.commit()
        logger.info(f"Cleaned up records older than {retention_days} days")
