"""
MongoDB database connection and utilities.
"""
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from typing import Optional
import logging
from pymongo import IndexModel, ASCENDING, DESCENDING
from pymongo.errors import OperationFailure

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


async def safe_create_index(collection, keys, **kwargs):
    """
    Safely create an index. If index with same keys but different options exists,
    drop it first and recreate.
    
    Args:
        collection: MongoDB collection
        keys: Index keys (string or list of tuples)
        **kwargs: Additional index options (name, unique, expireAfterSeconds, etc.)
    """
    # Normalize keys to list format for comparison
    if isinstance(keys, str):
        key_list = [(keys, 1)]
    else:
        key_list = keys
    
    try:
        # Try to create the index
        return await collection.create_index(keys, **kwargs)
    except OperationFailure as e:
        # If it's an IndexOptionsConflict error (code 85) or IndexKeySpecsConflict (code 86)
        if e.code in [85, 86]:
            logger.warning(f"Index conflict detected. Finding and dropping conflicting index...")
            try:
                # Get all existing indexes
                existing_indexes = await collection.index_information()
                
                # Find the conflicting index by comparing keys
                conflicting_index_name = None
                for idx_name, idx_info in existing_indexes.items():
                    # Skip the default _id index
                    if idx_name == "_id_":
                        continue
                    
                    # Compare keys
                    existing_keys = idx_info.get('key', [])
                    if existing_keys == key_list:
                        conflicting_index_name = idx_name
                        logger.info(f"Found conflicting index: {idx_name}")
                        break
                
                if conflicting_index_name:
                    # Drop the conflicting index
                    await collection.drop_index(conflicting_index_name)
                    logger.info(f"Dropped conflicting index: {conflicting_index_name}")
                    
                    # Recreate with new options
                    result = await collection.create_index(keys, **kwargs)
                    logger.info(f"Successfully recreated index with new options")
                    return result
                else:
                    logger.error(f"Could not find conflicting index to drop")
                    raise
                    
            except Exception as drop_error:
                logger.error(f"Failed to drop/recreate index: {drop_error}")
                raise
        else:
            raise


async def create_indexes():
    """Create database indexes for optimal performance."""
    try:
        logger.info("Creating database indexes...")
        
        # Users collection indexes
        await db.db.users.create_index("email", unique=True)
        await db.db.users.create_index("username", unique=True)
        logger.info("✓ Users indexes created")
        
        # Projects collection indexes
        await db.db.projects.create_index("owner_id")
        await db.db.projects.create_index("domain")
        await db.db.projects.create_index([("domain", 1), ("owner_id", 1)], unique=True)
        logger.info("✓ Projects indexes created")
        
        # Scans collection indexes
        await db.db.scans.create_index("project_id")
        await db.db.scans.create_index("status")
        await db.db.scans.create_index("created_at")
        await db.db.scans.create_index([("project_id", 1), ("status", 1)])
        logger.info("✓ Scans indexes created")
        
        # Findings collection indexes
        await db.db.findings.create_index("scan_id")
        await db.db.findings.create_index("severity")
        await db.db.findings.create_index("wstg_id")
        await db.db.findings.create_index([("scan_id", 1), ("severity", 1)])
        logger.info("✓ Findings indexes created")
        
        # Verification collection indexes
        await db.db.verifications.create_index("project_id", unique=True)
        await db.db.verifications.create_index("token")
        
        # TTL index for automatic verification expiration (7 days)
        await safe_create_index(
            db.db.verifications,
            [("expires_at", ASCENDING)],
            expireAfterSeconds=604800,  # 7 days
            name="expires_at_ttl"
        )
        logger.info("✓ Verifications indexes created")
        
        # Audit logs collection indexes
        await db.db.audit_logs.create_index("user_id")
        await db.db.audit_logs.create_index("action")
        await db.db.audit_logs.create_index("created_at")
        await db.db.audit_logs.create_index([("user_id", 1), ("created_at", -1)])
        logger.info("✓ Audit logs indexes created")
        
        # Payloads collection indexes
        await db.db.payloads.create_index("category")
        await db.db.payloads.create_index("type")
        await db.db.payloads.create_index("is_aggressive")
        await db.db.payloads.create_index([("category", 1), ("type", 1)])
        logger.info("✓ Payloads indexes created")
        
        # Session tokens (for refresh tokens)
        await db.db.sessions.create_index("user_id")
        await db.db.sessions.create_index("refresh_token", unique=True)
        
        # TTL index for automatic session expiration (24 hours)
        await safe_create_index(
            db.db.sessions,
            [("expires_at", ASCENDING)],
            expireAfterSeconds=86400,  # 24 hours
            name="expires_at_ttl"
        )
        logger.info("✓ Sessions indexes created")
        
        logger.info("✅ All database indexes created successfully")
        
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