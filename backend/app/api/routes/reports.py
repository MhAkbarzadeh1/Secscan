"""
Reports API routes.

Generates and manages security scan reports in PDF/HTML/JSON formats.
"""
from fastapi import APIRouter, HTTPException, status, Depends, Request, BackgroundTasks
from fastapi.responses import FileResponse, StreamingResponse
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
import uuid
import os
import json
import logging

from app.models.schemas import (
    ReportRequest, ReportResponse, ReportFormat, SeverityLevel
)
from app.core.security import (
    get_current_user, Role, log_audit_event, get_client_ip
)
from app.core.database import (
    scans_collection, findings_collection, projects_collection, reports_collection
)
from app.core.config import settings, SEVERITY_LEVELS
from app.services.report_service import ReportService

logger = logging.getLogger(__name__)
router = APIRouter()

# Initialize report service
report_service = ReportService()


def ensure_utc(dt: datetime) -> datetime:
    """Ensure datetime is timezone-aware (UTC)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


@router.post("/generate", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def generate_report(
    report_data: ReportRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Generate a security report for a completed scan.
    
    Reports are generated asynchronously and available for download.
    Reports expire after configured TTL.
    """
    client_ip = get_client_ip(request)
    
    # Get scan
    scan = await scans_collection().find_one({"_id": report_data.scan_id})
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="اسکن یافت نشد"
        )
    
    # Check if scan is completed
    if scan["status"] != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="فقط برای اسکن‌های تکمیل شده می‌توان گزارش تولید کرد"
        )
    
    # Check permissions
    if current_user["role"] == Role.USER:
        project = await projects_collection().find_one({"_id": scan["project_id"]})
        if not project or project["owner_id"] != current_user["_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="دسترسی غیرمجاز"
            )
    
    # Check if findings exist (only generate report if issues found)
    findings_count = await findings_collection().count_documents({"scan_id": report_data.scan_id})
    
    if findings_count == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="هیچ یافته امنیتی در این اسکن وجود ندارد"
        )
    
    # Create report record
    report_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=settings.REPORT_TTL_DAYS)
    
    # Get project info
    project = await projects_collection().find_one({"_id": scan["project_id"]})
    
    report_filename = f"report_{project['domain']}_{scan['_id'][:8]}.{report_data.format.value}"
    report_path = os.path.join(settings.REPORTS_DIR, report_filename)
    
    report_doc = {
        "_id": report_id,
        "scan_id": report_data.scan_id,
        "project_id": scan["project_id"],
        "user_id": current_user["_id"],
        "format": report_data.format.value,
        "language": report_data.language,
        "include_evidence": report_data.include_evidence,
        "include_remediation": report_data.include_remediation,
        "file_path": report_path,
        "status": "generating",
        "created_at": now,
        "expires_at": expires_at
    }
    
    await reports_collection().insert_one(report_doc)
    
    # Generate report in background
    background_tasks.add_task(
        report_service.generate_report,
        report_id=report_id,
        scan_id=report_data.scan_id,
        format=report_data.format,
        language=report_data.language,
        include_evidence=report_data.include_evidence,
        include_remediation=report_data.include_remediation
    )
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="report_generated",
        resource_type="report",
        resource_id=report_id,
        details={
            "scan_id": report_data.scan_id,
            "format": report_data.format.value
        },
        ip_address=client_ip
    )
    
    logger.info(f"Report generation started: {report_id}")
    
    return ReportResponse(
        id=report_id,
        scan_id=report_data.scan_id,
        format=report_data.format,
        file_path=report_path,
        download_url=f"/api/reports/{report_id}/download",
        expires_at=expires_at,
        created_at=now
    )


@router.get("/{report_id}")
async def get_report_status(
    report_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get report generation status.
    """
    report = await reports_collection().find_one({"_id": report_id})
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="گزارش یافت نشد"
        )
    
    # Check permissions
    if current_user["role"] == Role.USER and report["user_id"] != current_user["_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="دسترسی غیرمجاز"
        )
    
    return {
        "id": report["_id"],
        "scan_id": report["scan_id"],
        "format": report["format"],
        "status": report.get("status", "generating"),
        "download_url": f"/api/reports/{report_id}/download" if report.get("status") == "ready" else None,
        "expires_at": report["expires_at"],
        "created_at": report["created_at"]
    }


@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Download a generated report.
    """
    client_ip = get_client_ip(request)
    
    report = await reports_collection().find_one({"_id": report_id})
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="گزارش یافت نشد"
        )
    
    # Check permissions
    if current_user["role"] == Role.USER and report["user_id"] != current_user["_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="دسترسی غیرمجاز"
        )
    
    # Check expiration (ensure timezone-aware comparison)
    expires_at = ensure_utc(report["expires_at"])
    if expires_at < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="گزارش منقضی شده است"
        )
    
    # Check if ready
    if report.get("status") != "ready":
        raise HTTPException(
            status_code=status.HTTP_425_TOO_EARLY,
            detail="گزارش هنوز آماده نیست"
        )
    
    file_path = report["file_path"]
    
    if not os.path.exists(file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="فایل گزارش یافت نشد"
        )
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="report_downloaded",
        resource_type="report",
        resource_id=report_id,
        ip_address=client_ip
    )
    
    # Set content type based on format
    content_types = {
        "pdf": "application/pdf",
        "html": "text/html",
        "json": "application/json"
    }
    
    content_type = content_types.get(report["format"], "application/octet-stream")
    filename = os.path.basename(file_path)
    
    return FileResponse(
        path=file_path,
        media_type=content_type,
        filename=filename
    )


@router.get("/scan/{scan_id}/logs")
async def get_scan_logs(
    scan_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get scan logs (only if issues were found).
    
    Logs are redacted to not expose raw payloads.
    """
    scan = await scans_collection().find_one({"_id": scan_id})
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="اسکن یافت نشد"
        )
    
    # Check permissions
    if current_user["role"] == Role.USER:
        project = await projects_collection().find_one({"_id": scan["project_id"]})
        if not project or project["owner_id"] != current_user["_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="دسترسی غیرمجاز"
            )
    
    # Check if issues found
    findings_count = await findings_collection().count_documents({"scan_id": scan_id})
    
    if findings_count == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="لاگ فقط برای اسکن‌هایی که مشکل یافت شده قابل دانلود است"
        )
    
    # Return scan log (in real implementation, this would read from log file)
    return {
        "scan_id": scan_id,
        "status": scan["status"],
        "started_at": scan.get("started_at"),
        "completed_at": scan.get("completed_at"),
        "findings_count": findings_count,
        "tests_completed": scan.get("tests_completed", 0),
        "config": scan.get("config", {}),
        "log_entries": scan.get("log_entries", [])
    }


@router.delete("/{report_id}")
async def delete_report(
    report_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Delete a report.
    """
    client_ip = get_client_ip(request)
    
    report = await reports_collection().find_one({"_id": report_id})
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="گزارش یافت نشد"
        )
    
    # Check permissions
    if current_user["role"] == Role.USER and report["user_id"] != current_user["_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="دسترسی غیرمجاز"
        )
    
    # Delete file if exists
    if os.path.exists(report["file_path"]):
        try:
            os.remove(report["file_path"])
        except Exception as e:
            logger.error(f"Failed to delete report file: {e}")
    
    # Delete record
    await reports_collection().delete_one({"_id": report_id})
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="report_deleted",
        resource_type="report",
        resource_id=report_id,
        ip_address=client_ip
    )
    
    return {"message": "گزارش با موفقیت حذف شد"}