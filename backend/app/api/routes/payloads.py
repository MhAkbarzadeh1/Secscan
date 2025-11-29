"""
Payloads API routes.

Manages security payloads from PayloadsAllTheThings repository.
Separates safe and aggressive payloads.
"""
from fastapi import APIRouter, HTTPException, status, Depends, Request, Query, BackgroundTasks
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
import logging

from app.models.schemas import PayloadCategory, PayloadInfo, PayloadStats
from app.core.security import (
    get_current_user, require_minimum_role, Role,
    log_audit_event, get_client_ip
)
from app.core.database import payloads_collection
from app.services.payload_service import PayloadService

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize payload service
payload_service = PayloadService()


@router.get("/stats", response_model=PayloadStats)
async def get_payload_stats(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get payload statistics.
    """
    # Aggregate stats
    pipeline = [
        {"$facet": {
            "total": [{"$count": "count"}],
            "by_category": [
                {"$group": {"_id": "$category", "count": {"$sum": 1}}}
            ],
            "safe": [
                {"$match": {"is_aggressive": False}},
                {"$count": "count"}
            ],
            "aggressive": [
                {"$match": {"is_aggressive": True}},
                {"$count": "count"}
            ],
            "last_sync": [
                {"$sort": {"synced_at": -1}},
                {"$limit": 1},
                {"$project": {"synced_at": 1}}
            ]
        }}
    ]
    
    result = await payloads_collection().aggregate(pipeline).to_list(length=1)
    
    if not result:
        return PayloadStats(
            total_count=0,
            by_category={},
            safe_count=0,
            aggressive_count=0,
            last_sync=None
        )
    
    data = result[0]
    
    by_category = {item["_id"]: item["count"] for item in data.get("by_category", [])}
    
    return PayloadStats(
        total_count=data.get("total", [{}])[0].get("count", 0),
        by_category=by_category,
        safe_count=data.get("safe", [{}])[0].get("count", 0),
        aggressive_count=data.get("aggressive", [{}])[0].get("count", 0),
        last_sync=data.get("last_sync", [{}])[0].get("synced_at") if data.get("last_sync") else None
    )


@router.get("/categories")
async def get_payload_categories(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get available payload categories.
    """
    categories = [
        {
            "id": cat.value,
            "name": cat.name.replace("_", " ").title(),
            "description": get_category_description(cat)
        }
        for cat in PayloadCategory
    ]
    
    return {"categories": categories}


def get_category_description(category: PayloadCategory) -> str:
    """Get description for payload category."""
    descriptions = {
        PayloadCategory.SQLI: "SQL Injection payloads for testing database vulnerabilities",
        PayloadCategory.XSS: "Cross-Site Scripting payloads for testing input sanitization",
        PayloadCategory.COMMAND_INJECTION: "OS command injection payloads",
        PayloadCategory.PATH_TRAVERSAL: "Directory traversal payloads",
        PayloadCategory.SSRF: "Server-Side Request Forgery payloads",
        PayloadCategory.XXE: "XML External Entity injection payloads",
        PayloadCategory.SSTI: "Server-Side Template Injection payloads",
        PayloadCategory.LDAP_INJECTION: "LDAP injection payloads",
        PayloadCategory.NOSQL_INJECTION: "NoSQL injection payloads for MongoDB, etc.",
        PayloadCategory.HEADER_INJECTION: "HTTP header injection payloads"
    }
    return descriptions.get(category, "")


@router.get("/")
async def list_payloads(
    category: Optional[PayloadCategory] = None,
    is_aggressive: Optional[bool] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    List payloads with optional filters.
    
    Note: Actual payload content is not exposed via API for safety.
    Only metadata is returned.
    """
    # Build query
    query = {}
    
    if category:
        query["category"] = category.value
    
    if is_aggressive is not None:
        query["is_aggressive"] = is_aggressive
    
    if search:
        query["$or"] = [
            {"name": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}}
        ]
    
    # Get total count
    total = await payloads_collection().count_documents(query)
    
    # Get paginated results (excluding actual payload content)
    skip = (page - 1) * page_size
    cursor = payloads_collection().find(
        query,
        {"payload": 0}  # Exclude actual payload for safety
    ).skip(skip).limit(page_size)
    
    payloads = await cursor.to_list(length=page_size)
    
    items = [
        PayloadInfo(
            id=p["_id"],
            category=PayloadCategory(p["category"]),
            name=p["name"],
            description=p.get("description"),
            is_aggressive=p.get("is_aggressive", False),
            source=p.get("source", "PayloadsAllTheThings")
        )
        for p in payloads
    ]
    
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size
    }


@router.post("/sync")
async def sync_payloads(
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: Dict[str, Any] = Depends(require_minimum_role(Role.ADMIN))
):
    """
    Sync payloads from PayloadsAllTheThings repository.
    
    This clones/updates the repository and imports payloads into the database.
    Payloads are categorized as safe or aggressive based on their potential impact.
    """
    client_ip = get_client_ip(request)
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="payload_sync_started",
        resource_type="payloads",
        resource_id="all",
        ip_address=client_ip
    )
    
    # Start sync in background
    background_tasks.add_task(payload_service.sync_payloads)
    
    logger.info(f"Payload sync started by {current_user['email']}")
    
    return {"message": "همگام‌سازی پیلودها شروع شد. این فرآیند ممکن است چند دقیقه طول بکشد."}


@router.get("/sync/status")
async def get_sync_status(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get payload sync status.
    """
    status = await payload_service.get_sync_status()
    return status


@router.delete("/")
async def clear_payloads(
    request: Request,
    current_user: Dict[str, Any] = Depends(require_minimum_role(Role.OWNER))
):
    """
    Clear all payloads from database (owner only).
    
    Use with caution! This will remove all synced payloads.
    """
    client_ip = get_client_ip(request)
    
    result = await payloads_collection().delete_many({})
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="payloads_cleared",
        resource_type="payloads",
        resource_id="all",
        details={"deleted_count": result.deleted_count},
        ip_address=client_ip
    )
    
    logger.warning(f"All payloads cleared by {current_user['email']}")
    
    return {"message": f"{result.deleted_count} پیلود حذف شد"}


# Internal endpoint for scanner to get payloads
@router.get("/internal/{category}")
async def get_payloads_for_scan(
    category: PayloadCategory,
    is_aggressive: bool = False,
    limit: int = Query(100, ge=1, le=1000),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get payloads for scanning (internal use).
    
    This endpoint returns actual payload content for authorized scans.
    """
    query = {
        "category": category.value,
        "is_aggressive": is_aggressive
    }
    
    # Get payloads with content
    cursor = payloads_collection().find(query).limit(limit)
    payloads = await cursor.to_list(length=limit)
    
    # Return only necessary fields
    return {
        "category": category.value,
        "is_aggressive": is_aggressive,
        "count": len(payloads),
        "payloads": [
            {
                "id": p["_id"],
                "name": p["name"],
                "payload": p["payload"]
            }
            for p in payloads
        ]
    }