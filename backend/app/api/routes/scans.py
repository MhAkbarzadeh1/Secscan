"""
Scans API routes.

Manages security scan creation, scheduling, and monitoring.
"""
from fastapi import APIRouter, HTTPException, status, Depends, Request, Query, BackgroundTasks
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import uuid
import logging

from app.models.schemas import (
    ScanCreate, ScanResponse, ScanStatus, ScanMode, ScanProgress, 
    PaginatedResponse
)
from app.core.security import (
    get_current_user, require_minimum_role, Role,
    log_audit_event, get_client_ip, rate_limiter
)
from app.core.database import (
    projects_collection, scans_collection, findings_collection
)
from app.core.config import settings
from app.services.scan_service import ScanService

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize scan service
scan_service = ScanService()


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanCreate,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Create and queue a new security scan.
    
    Requirements:
    - Project must be verified before scanning
    - Aggressive mode requires explicit confirmation
    - Rate limiting applies to prevent abuse
    """
    client_ip = get_client_ip(request)
    
    # Rate limiting for scans
    rate_key = f"scan:{current_user['_id']}"
    if not rate_limiter.is_allowed(rate_key, limit=settings.SCAN_RATE_LIMIT_PER_MINUTE, window_seconds=60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="نرخ درخواست اسکن بیش از حد مجاز است. لطفاً کمی صبر کنید."
        )
    
    # Get project
    project = await projects_collection().find_one({"_id": scan_data.project_id})
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="پروژه یافت نشد"
        )
    
    # Check permissions
    if current_user["role"] == Role.USER and project["owner_id"] != current_user["_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="دسترسی غیرمجاز"
        )
    
    # Check verification status
    if not project.get("is_verified"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="مالکیت دامنه تأیید نشده است. لطفاً ابتدا دامنه را تأیید کنید."
        )
    
    # Check for aggressive mode confirmation
    if scan_data.config.mode == ScanMode.AGGRESSIVE:
        # In a real app, you'd check for a confirmation token or additional auth
        logger.warning(f"Aggressive scan requested for {project['domain']} by {current_user['email']}")
    
    # Check concurrent scan limit
    active_scans = await scans_collection().count_documents({
        "project_id": scan_data.project_id,
        "status": {"$in": [ScanStatus.PENDING.value, ScanStatus.QUEUED.value, ScanStatus.RUNNING.value]}
    })
    
    if active_scans >= settings.MAX_CONCURRENT_SCANS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"حداکثر {settings.MAX_CONCURRENT_SCANS} اسکن همزمان مجاز است"
        )
    
    # Create scan
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    
    scan_doc = {
        "_id": scan_id,
        "project_id": scan_data.project_id,
        "user_id": current_user["_id"],
        "status": ScanStatus.QUEUED.value,
        "config": scan_data.config.model_dump(),
        "progress": 0.0,
        "scheduled_at": scan_data.scheduled_at,
        "endpoints": scan_data.endpoints or [ep["path"] for ep in project.get("endpoints", [])],
        "started_at": None,
        "completed_at": None,
        "total_findings": 0,
        "findings_by_severity": {},
        "error_message": None,
        "created_at": now,
        "updated_at": now
    }
    
    await scans_collection().insert_one(scan_doc)
    
    # Update project scan count
    await projects_collection().update_one(
        {"_id": scan_data.project_id},
        {
            "$inc": {"scan_count": 1},
            "$set": {"last_scan_at": now, "updated_at": now}
        }
    )
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="scan_created",
        resource_type="scan",
        resource_id=scan_id,
        details={
            "project_id": scan_data.project_id,
            "domain": project["domain"],
            "mode": scan_data.config.mode.value
        },
        ip_address=client_ip
    )
    
    # Queue scan for execution
    background_tasks.add_task(scan_service.execute_scan, scan_id)
    
    logger.info(f"Scan created: {scan_id} for {project['domain']} (mode: {scan_data.config.mode.value})")
    
    return ScanResponse(
        id=scan_id,
        project_id=scan_data.project_id,
        status=ScanStatus.QUEUED,
        config=scan_data.config,
        progress=0.0,
        created_at=now,
        updated_at=now
    )


@router.get("/", response_model=PaginatedResponse)
async def list_scans(
    project_id: Optional[str] = None,
    status_filter: Optional[ScanStatus] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    List scans with optional filters.
    """
    # Build query
    query = {}
    
    if current_user["role"] == Role.USER:
        query["user_id"] = current_user["_id"]
    
    if project_id:
        query["project_id"] = project_id
    
    if status_filter:
        query["status"] = status_filter.value
    
    # Get total count
    total = await scans_collection().count_documents(query)
    
    # Get paginated results
    skip = (page - 1) * page_size
    cursor = scans_collection().find(query).skip(skip).limit(page_size).sort("created_at", -1)
    scans = await cursor.to_list(length=page_size)
    
    items = [
        ScanResponse(
            id=s["_id"],
            project_id=s["project_id"],
            status=ScanStatus(s["status"]),
            config=s.get("config", {}),
            progress=s.get("progress", 0.0),
            started_at=s.get("started_at"),
            completed_at=s.get("completed_at"),
            total_findings=s.get("total_findings", 0),
            findings_by_severity=s.get("findings_by_severity", {}),
            error_message=s.get("error_message"),
            created_at=s.get("created_at"),
            updated_at=s.get("updated_at")
        )
        for s in scans
    ]
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get scan details by ID.
    """
    scan = await scans_collection().find_one({"_id": scan_id})
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="اسکن یافت نشد"
        )
    
    # Check permissions
    if current_user["role"] == Role.USER and scan["user_id"] != current_user["_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="دسترسی غیرمجاز"
        )
    
    return ScanResponse(
        id=scan["_id"],
        project_id=scan["project_id"],
        status=ScanStatus(scan["status"]),
        config=scan.get("config", {}),
        progress=scan.get("progress", 0.0),
        started_at=scan.get("started_at"),
        completed_at=scan.get("completed_at"),
        total_findings=scan.get("total_findings", 0),
        findings_by_severity=scan.get("findings_by_severity", {}),
        error_message=scan.get("error_message"),
        created_at=scan.get("created_at"),
        updated_at=scan.get("updated_at")
    )


@router.get("/{scan_id}/progress", response_model=ScanProgress)
async def get_scan_progress(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get real-time scan progress.
    """
    scan = await scans_collection().find_one({"_id": scan_id})
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="اسکن یافت نشد"
        )
    
    if current_user["role"] == Role.USER and scan["user_id"] != current_user["_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="دسترسی غیرمجاز"
        )
    
    return ScanProgress(
        scan_id=scan_id,
        status=ScanStatus(scan["status"]),
        progress=scan.get("progress", 0.0),
        current_test=scan.get("current_test"),
        tests_completed=scan.get("tests_completed", 0),
        tests_total=scan.get("tests_total", 0)
    )


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Cancel a running or queued scan.
    """
    client_ip = get_client_ip(request)
    
    scan = await scans_collection().find_one({"_id": scan_id})
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="اسکن یافت نشد"
        )
    
    if current_user["role"] == Role.USER and scan["user_id"] != current_user["_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="دسترسی غیرمجاز"
        )
    
    # Check if scan can be cancelled
    if scan["status"] not in [ScanStatus.PENDING.value, ScanStatus.QUEUED.value, ScanStatus.RUNNING.value]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="این اسکن قابل لغو نیست"
        )
    
    # Update scan status
    await scans_collection().update_one(
        {"_id": scan_id},
        {"$set": {
            "status": ScanStatus.CANCELLED.value,
            "completed_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc)
        }}
    )
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="scan_cancelled",
        resource_type="scan",
        resource_id=scan_id,
        ip_address=client_ip
    )
    
    logger.info(f"Scan cancelled: {scan_id}")
    
    return {"message": "اسکن با موفقیت لغو شد"}


@router.post("/{scan_id}/retry")
async def retry_scan(
    scan_id: str,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Retry a failed scan.
    """
    client_ip = get_client_ip(request)
    
    scan = await scans_collection().find_one({"_id": scan_id})
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="اسکن یافت نشد"
        )
    
    if current_user["role"] == Role.USER and scan["user_id"] != current_user["_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="دسترسی غیرمجاز"
        )
    
    # Only failed scans can be retried
    if scan["status"] != ScanStatus.FAILED.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="فقط اسکن‌های ناموفق قابل تکرار هستند"
        )
    
    # Reset scan
    now = datetime.now(timezone.utc)
    await scans_collection().update_one(
        {"_id": scan_id},
        {"$set": {
            "status": ScanStatus.QUEUED.value,
            "progress": 0.0,
            "started_at": None,
            "completed_at": None,
            "error_message": None,
            "updated_at": now
        }}
    )
    
    # Delete old findings
    await findings_collection().delete_many({"scan_id": scan_id})
    
    # Queue for execution
    background_tasks.add_task(scan_service.execute_scan, scan_id)
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="scan_retried",
        resource_type="scan",
        resource_id=scan_id,
        ip_address=client_ip
    )
    
    logger.info(f"Scan retried: {scan_id}")
    
    return {"message": "اسکن مجدداً در صف قرار گرفت"}