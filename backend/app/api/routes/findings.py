"""
Findings API routes.

Manages security findings discovered during scans.
"""
from fastapi import APIRouter, HTTPException, status, Depends, Request, Query
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
import logging

from app.models.schemas import (
    FindingResponse, FindingUpdate, SeverityLevel, PaginatedResponse
)
from app.core.security import (
    get_current_user, Role, log_audit_event, get_client_ip
)
from app.core.database import (
    findings_collection, scans_collection, projects_collection
)
from app.core.config import WSTG_CATEGORIES, OWASP_TOP_10, SEVERITY_LEVELS

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/", response_model=PaginatedResponse)
async def list_findings(
    scan_id: Optional[str] = None,
    project_id: Optional[str] = None,
    severity: Optional[SeverityLevel] = None,
    wstg_category: Optional[str] = None,
    is_false_positive: Optional[bool] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    List findings with optional filters.
    """
    # Build query
    query = {}
    
    if scan_id:
        query["scan_id"] = scan_id
    
    if project_id:
        query["project_id"] = project_id
    
    if severity:
        query["severity"] = severity.value
    
    if wstg_category:
        query["wstg_id"] = {"$regex": f"^WSTG-{wstg_category}"}
    
    if is_false_positive is not None:
        query["is_false_positive"] = is_false_positive
    
    # For regular users, only show their findings
    if current_user["role"] == Role.USER:
        # Get user's project IDs
        user_projects = await projects_collection().find(
            {"owner_id": current_user["_id"]},
            {"_id": 1}
        ).to_list(length=1000)
        project_ids = [p["_id"] for p in user_projects]
        query["project_id"] = {"$in": project_ids}
    
    # Get total count
    total = await findings_collection().count_documents(query)
    
    # Get paginated results
    skip = (page - 1) * page_size
    cursor = findings_collection().find(query).skip(skip).limit(page_size).sort([
        ("severity", 1),  # Critical first
        ("created_at", -1)
    ])
    findings = await cursor.to_list(length=page_size)
    
    items = [
        FindingResponse(
            id=f["_id"],
            scan_id=f["scan_id"],
            project_id=f["project_id"],
            title=f["title"],
            description=f["description"],
            severity=SeverityLevel(f["severity"]),
            wstg_id=f["wstg_id"],
            owasp_top10_id=f.get("owasp_top10_id"),
            endpoint=f["endpoint"],
            method=f.get("method", "GET"),
            evidence=f.get("evidence"),
            recommendation=f["recommendation"],
            recommendation_fa=f.get("recommendation_fa"),
            cvss_score=f.get("cvss_score"),
            is_false_positive=f.get("is_false_positive", False),
            verified=f.get("verified", False),
            notes=f.get("notes"),
            created_at=f.get("created_at"),
            updated_at=f.get("updated_at")
        )
        for f in findings
    ]
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size
    )


@router.get("/stats")
async def get_findings_stats(
    project_id: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get findings statistics.
    """
    # Build match stage
    match_stage = {}
    
    if project_id:
        match_stage["project_id"] = project_id
    
    if current_user["role"] == Role.USER:
        user_projects = await projects_collection().find(
            {"owner_id": current_user["_id"]},
            {"_id": 1}
        ).to_list(length=1000)
        project_ids = [p["_id"] for p in user_projects]
        match_stage["project_id"] = {"$in": project_ids}
    
    # Aggregation pipeline
    pipeline = [
        {"$match": match_stage},
        {"$facet": {
            "by_severity": [
                {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
            ],
            "by_wstg_category": [
                {"$group": {
                    "_id": {"$substr": ["$wstg_id", 5, 4]},
                    "count": {"$sum": 1}
                }}
            ],
            "by_owasp_top10": [
                {"$match": {"owasp_top10_id": {"$ne": None}}},
                {"$group": {"_id": "$owasp_top10_id", "count": {"$sum": 1}}}
            ],
            "total": [
                {"$count": "count"}
            ],
            "false_positives": [
                {"$match": {"is_false_positive": True}},
                {"$count": "count"}
            ],
            "verified": [
                {"$match": {"verified": True}},
                {"$count": "count"}
            ]
        }}
    ]
    
    result = await findings_collection().aggregate(pipeline).to_list(length=1)
    
    if not result:
        return {
            "total": 0,
            "by_severity": {},
            "by_wstg_category": {},
            "by_owasp_top10": {},
            "false_positives": 0,
            "verified": 0
        }
    
    data = result[0]
    
    # Transform severity stats with Persian labels
    severity_stats = {}
    for item in data.get("by_severity", []):
        sev = item["_id"]
        severity_stats[sev] = {
            "count": item["count"],
            "label": SEVERITY_LEVELS.get(sev, {}).get("persian", sev),
            "color": SEVERITY_LEVELS.get(sev, {}).get("color", "#666")
        }
    
    # Transform WSTG category stats
    wstg_stats = {}
    for item in data.get("by_wstg_category", []):
        cat = item["_id"]
        cat_info = WSTG_CATEGORIES.get(cat, {})
        wstg_stats[cat] = {
            "count": item["count"],
            "name": cat_info.get("name", cat),
            "code": f"WSTG-{cat}"
        }
    
    # Transform OWASP Top 10 stats
    owasp_stats = {}
    for item in data.get("by_owasp_top10", []):
        top10_id = item["_id"]
        top10_info = OWASP_TOP_10.get(top10_id, {})
        owasp_stats[top10_id] = {
            "count": item["count"],
            "name": top10_info.get("name", top10_id)
        }
    
    return {
        "total": data.get("total", [{}])[0].get("count", 0),
        "by_severity": severity_stats,
        "by_wstg_category": wstg_stats,
        "by_owasp_top10": owasp_stats,
        "false_positives": data.get("false_positives", [{}])[0].get("count", 0),
        "verified": data.get("verified", [{}])[0].get("count", 0)
    }


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get finding details by ID.
    """
    finding = await findings_collection().find_one({"_id": finding_id})
    
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="یافته امنیتی پیدا نشد"
        )
    
    # Check permissions
    if current_user["role"] == Role.USER:
        project = await projects_collection().find_one({"_id": finding["project_id"]})
        if not project or project["owner_id"] != current_user["_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="دسترسی غیرمجاز"
            )
    
    return FindingResponse(
        id=finding["_id"],
        scan_id=finding["scan_id"],
        project_id=finding["project_id"],
        title=finding["title"],
        description=finding["description"],
        severity=SeverityLevel(finding["severity"]),
        wstg_id=finding["wstg_id"],
        owasp_top10_id=finding.get("owasp_top10_id"),
        endpoint=finding["endpoint"],
        method=finding.get("method", "GET"),
        evidence=finding.get("evidence"),
        recommendation=finding["recommendation"],
        recommendation_fa=finding.get("recommendation_fa"),
        cvss_score=finding.get("cvss_score"),
        is_false_positive=finding.get("is_false_positive", False),
        verified=finding.get("verified", False),
        notes=finding.get("notes"),
        created_at=finding.get("created_at"),
        updated_at=finding.get("updated_at")
    )


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: str,
    update_data: FindingUpdate,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Update finding (mark as false positive, add notes, etc.)
    """
    client_ip = get_client_ip(request)
    
    finding = await findings_collection().find_one({"_id": finding_id})
    
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="یافته امنیتی پیدا نشد"
        )
    
    # Check permissions
    if current_user["role"] == Role.USER:
        project = await projects_collection().find_one({"_id": finding["project_id"]})
        if not project or project["owner_id"] != current_user["_id"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="دسترسی غیرمجاز"
            )
    
    # Build update
    update = {"updated_at": datetime.now(timezone.utc)}
    
    if update_data.is_false_positive is not None:
        update["is_false_positive"] = update_data.is_false_positive
    
    if update_data.verified is not None:
        update["verified"] = update_data.verified
    
    if update_data.notes is not None:
        update["notes"] = update_data.notes
    
    await findings_collection().update_one(
        {"_id": finding_id},
        {"$set": update}
    )
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="finding_updated",
        resource_type="finding",
        resource_id=finding_id,
        details={"updates": list(update.keys())},
        ip_address=client_ip
    )
    
    # Get updated finding
    updated = await findings_collection().find_one({"_id": finding_id})
    
    return FindingResponse(
        id=updated["_id"],
        scan_id=updated["scan_id"],
        project_id=updated["project_id"],
        title=updated["title"],
        description=updated["description"],
        severity=SeverityLevel(updated["severity"]),
        wstg_id=updated["wstg_id"],
        owasp_top10_id=updated.get("owasp_top10_id"),
        endpoint=updated["endpoint"],
        method=updated.get("method", "GET"),
        evidence=updated.get("evidence"),
        recommendation=updated["recommendation"],
        recommendation_fa=updated.get("recommendation_fa"),
        cvss_score=updated.get("cvss_score"),
        is_false_positive=updated.get("is_false_positive", False),
        verified=updated.get("verified", False),
        notes=updated.get("notes"),
        created_at=updated.get("created_at"),
        updated_at=updated.get("updated_at")
    )


@router.get("/wstg/categories")
async def get_wstg_categories():
    """
    Get all WSTG categories and tests.
    """
    return WSTG_CATEGORIES


@router.get("/owasp/top10")
async def get_owasp_top10():
    """
    Get OWASP Top 10 list.
    """
    return OWASP_TOP_10