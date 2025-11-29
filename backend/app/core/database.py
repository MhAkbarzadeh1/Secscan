"""
MongoDB database connection and utilities.
"""
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from typing import Optional
import logging

from app.core.config import settings

logger = logging.getLogger(__name__)


class Database:
    """MongoDB database connection manager."""
    
    client: Optional[AsyncIOMotorClient] = None
    db: Optional[AsyncIOMotorDatabase] = None


db = Database()


async def connect_to_mongo():
    """Connect to MongoDB database."""
    try:
        db.client = AsyncIOMotorClient(
            settings.MONGODB_URL,
            maxPoolSize=50,
            minPoolSize=10,
            serverSelectionTimeoutMS=5000
        )
        db.db = db.client[settings.MONGODB_DB_NAME]
        
        # Verify connection
        await db.client.admin.command('ping')
        logger.info(f"Connected to MongoDB: {settings.MONGODB_DB_NAME}")
        
        # Create indexes
        await create_indexes()
        
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise


async def close_mongo_connection():
    """Close MongoDB connection."""
    if db.client:
        db.client.close()
        logger.info("Closed MongoDB connection")


async def create_indexes():
    """Create database indexes for optimal performance."""
    try:
        # Users collection indexes
        await db.db.users.create_index("email", unique=True)
        await db.db.users.create_index("username", unique=True)
        
        # Projects collection indexes
        await db.db.projects.create_index("owner_id")
        await db.db.projects.create_index("domain")
        await db.db.projects.create_index([("domain", 1), ("owner_id", 1)], unique=True)
        
        # Scans collection indexes
        await db.db.scans.create_index("project_id")
        await db.db.scans.create_index("status")
        await db.db.scans.create_index("created_at")
        await db.db.scans.create_index([("project_id", 1), ("status", 1)])
        
        # Findings collection indexes
        await db.db.findings.create_index("scan_id")
        await db.db.findings.create_index("severity")
        await db.db.findings.create_index("wstg_id")
        await db.db.findings.create_index([("scan_id", 1), ("severity", 1)])
        
        # Verification collection indexes
        await db.db.verifications.create_index("project_id", unique=True)
        await db.db.verifications.create_index("token")
        await db.db.verifications.create_index("expires_at")
        
        # Audit logs collection indexes
        await db.db.audit_logs.create_index("user_id")
        await db.db.audit_logs.create_index("action")
        await db.db.audit_logs.create_index("created_at")
        await db.db.audit_logs.create_index([("user_id", 1), ("created_at", -1)])
        
        # Payloads collection indexes
        await db.db.payloads.create_index("category")
        await db.db.payloads.create_index("type")
        await db.db.payloads.create_index("is_aggressive")
        await db.db.payloads.create_index([("category", 1), ("type", 1)])
        
        # Session tokens (for refresh tokens)
        await db.db.sessions.create_index("user_id")
        await db.db.sessions.create_index("refresh_token", unique=True)
        await db.db.sessions.create_index("expires_at")
        
        logger.info("Database indexes created successfully")
        
    except Exception as e:
        logger.error(f"Failed to create indexes: {e}")
        raise


def get_database() -> AsyncIOMotorDatabase:
    """Get database instance."""
    return db.db


# Collection accessors
def users_collection():
    return db.db.users


def projects_collection():
    return db.db.projects


def scans_collection():
    return db.db.scans


def findings_collection():
    return db.db.findings


def verifications_collection():
    return db.db.verifications


def audit_logs_collection():
    return db.db.audit_logs


def payloads_collection():
    return db.db.payloads


def sessions_collection():
    return db.db.sessions


def reports_collection():
    return db.db.reports