"""
Projects API routes.
"""
from fastapi import APIRouter, HTTPException, status, Depends, Request, Query
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import uuid
import logging

from app.models.schemas import (
    ProjectCreate, ProjectUpdate, ProjectResponse, 
    PaginatedResponse, VerificationStatus
)
from app.core.security import (
    get_current_user, require_minimum_role, Role,
    log_audit_event, get_client_ip
)
from app.core.database import projects_collection, scans_collection, verifications_collection

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    project_data: ProjectCreate,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Create a new project.
    
    Domain ownership verification is required before scanning.
    """
    client_ip = get_client_ip(request)
    
    # Check if project with same domain exists for this user
    existing = await projects_collection().find_one({
        "domain": project_data.domain,
        "owner_id": current_user["_id"]
    })
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Project with this domain already exists"
        )
    
    project_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    
    project_doc = {
        "_id": project_id,
        "name": project_data.name,
        "description": project_data.description,
        "domain": project_data.domain,
        "owner_id": current_user["_id"],
        "endpoints": [ep.model_dump() for ep in project_data.endpoints],
        "auth_config": project_data.auth_config,
        "verification_status": VerificationStatus.VERIFIED.value,
        "is_verified": True,
        "last_scan_at": None,
        "scan_count": 0,
        "created_at": now,
        "updated_at": now
    }
    
    await projects_collection().insert_one(project_doc)
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="project_created",
        resource_type="project",
        resource_id=project_id,
        details={"domain": project_data.domain},
        ip_address=client_ip
    )
    
    logger.info(f"Project created: {project_data.name} ({project_data.domain})")
    
    return ProjectResponse(
        id=project_id,
        name=project_data.name,
        description=project_data.description,
        domain=project_data.domain,
        owner_id=current_user["_id"],
        endpoints=project_data.endpoints,
        verification_status=VerificationStatus.PENDING,
        is_verified=False,
        created_at=now,
        updated_at=now
    )


@router.get("/", response_model=PaginatedResponse)
async def list_projects(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    List all projects for current user.
    
    Admins and owners can see all projects.
    """
    # Build query
    query = {}
    if current_user["role"] == Role.USER:
        query["owner_id"] = current_user["_id"]
    
    # Get total count
    total = await projects_collection().count_documents(query)
    
    # Get paginated results
    skip = (page - 1) * page_size
    cursor = projects_collection().find(query).skip(skip).limit(page_size).sort("created_at", -1)
    projects = await cursor.to_list(length=page_size)
    
    # Transform to response
    items = [
        ProjectResponse(
            id=p["_id"],
            name=p["name"],
            description=p.get("description"),
            domain=p["domain"],
            owner_id=p["owner_id"],
            endpoints=p.get("endpoints", []),
            verification_status=p.get("verification_status", VerificationStatus.PENDING),
            is_verified=p.get("is_verified", False),
            last_scan_at=p.get("last_scan_at"),
            scan_count=p.get("scan_count", 0),
            created_at=p.get("created_at"),
            updated_at=p.get("updated_at")
        )
        for p in projects
    ]
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size
    )


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get project by ID.
    """
    project = await projects_collection().find_one({"_id": project_id})
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Check permissions
    if current_user["role"] == Role.USER and project["owner_id"] != current_user["_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return ProjectResponse(
        id=project["_id"],
        name=project["name"],
        description=project.get("description"),
        domain=project["domain"],
        owner_id=project["owner_id"],
        endpoints=project.get("endpoints", []),
        verification_status=project.get("verification_status", VerificationStatus.PENDING),
        is_verified=project.get("is_verified", False),
        last_scan_at=project.get("last_scan_at"),
        scan_count=project.get("scan_count", 0),
        created_at=project.get("created_at"),
        updated_at=project.get("updated_at")
    )


@router.put("/{project_id}", response_model=ProjectResponse)
async def update_project(
    project_id: str,
    project_data: ProjectUpdate,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Update project.
    """
    client_ip = get_client_ip(request)
    
    project = await projects_collection().find_one({"_id": project_id})
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Check permissions
    if current_user["role"] == Role.USER and project["owner_id"] != current_user["_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Build update data
    update_data = {"updated_at": datetime.now(timezone.utc)}
    
    if project_data.name is not None:
        update_data["name"] = project_data.name
    if project_data.description is not None:
        update_data["description"] = project_data.description
    if project_data.endpoints is not None:
        update_data["endpoints"] = [ep.model_dump() for ep in project_data.endpoints]
    if project_data.auth_config is not None:
        update_data["auth_config"] = project_data.auth_config
    
    await projects_collection().update_one(
        {"_id": project_id},
        {"$set": update_data}
    )
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="project_updated",
        resource_type="project",
        resource_id=project_id,
        ip_address=client_ip
    )
    
    # Get updated project
    updated_project = await projects_collection().find_one({"_id": project_id})
    
    return ProjectResponse(
        id=updated_project["_id"],
        name=updated_project["name"],
        description=updated_project.get("description"),
        domain=updated_project["domain"],
        owner_id=updated_project["owner_id"],
        endpoints=updated_project.get("endpoints", []),
        verification_status=updated_project.get("verification_status", VerificationStatus.PENDING),
        is_verified=updated_project.get("is_verified", False),
        last_scan_at=updated_project.get("last_scan_at"),
        scan_count=updated_project.get("scan_count", 0),
        created_at=updated_project.get("created_at"),
        updated_at=updated_project.get("updated_at")
    )


@router.delete("/{project_id}")
async def delete_project(
    project_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Delete project and all associated data.
    """
    client_ip = get_client_ip(request)
    
    project = await projects_collection().find_one({"_id": project_id})
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Only owner or admin can delete
    if current_user["role"] == Role.USER and project["owner_id"] != current_user["_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Delete associated data
    await scans_collection().delete_many({"project_id": project_id})
    await verifications_collection().delete_many({"project_id": project_id})
    await projects_collection().delete_one({"_id": project_id})
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="project_deleted",
        resource_type="project",
        resource_id=project_id,
        details={"domain": project["domain"]},
        ip_address=client_ip
    )
    
    logger.info(f"Project deleted: {project['name']} ({project['domain']})")
    
    return {"message": "Project deleted successfully"}


@router.post("/{project_id}/endpoints")
async def add_endpoint(
    project_id: str,
    endpoint: Dict[str, Any],
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Add an endpoint to the project.
    """
    client_ip = get_client_ip(request)
    
    project = await projects_collection().find_one({"_id": project_id})
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    if current_user["role"] == Role.USER and project["owner_id"] != current_user["_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Add endpoint
    await projects_collection().update_one(
        {"_id": project_id},
        {
            "$push": {"endpoints": endpoint},
            "$set": {"updated_at": datetime.now(timezone.utc)}
        }
    )
    
    await log_audit_event(
        user_id=current_user["_id"],
        action="endpoint_added",
        resource_type="project",
        resource_id=project_id,
        details={"path": endpoint.get("path")},
        ip_address=client_ip
    )
    
    return {"message": "Endpoint added successfully"}