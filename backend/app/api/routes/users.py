"""
Users API routes.

User management for admins and user profile management.
"""
from fastapi import APIRouter, HTTPException, status, Depends, Request, Query
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import logging

from app.models.schemas import (
    UserResponse, UserUpdate, UserRole, PaginatedResponse
)
from app.core.security import (
    get_current_user, require_minimum_role, Role,
    log_audit_event, get_client_ip, get_password_hash, verify_password
)
from app.core.database import users_collection

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/", response_model=PaginatedResponse)
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    role: Optional[UserRole] = None,
    is_active: Optional[bool] = None,
    current_user: Dict[str, Any] = Depends(require_minimum_role(Role.ADMIN))
):
    """
    List all users (admin only).
    """
    # Build query
    query = {}
    
    if role:
        query["role"] = role.value
    
    if is_active is not None:
        query["is_active"] = is_active
    
    # Get total count
    total = await users_collection().count_documents(query)
    
    # Get paginated results
    skip = (page - 1) * page_size
    cursor = users_collection().find(
        query,
        {"hashed_password": 0}  # Exclude password hash
    ).skip(skip).limit(page_size).sort("created_at", -1)
    users = await cursor.to_list(length=page_size)
    
    items = [
        UserResponse(
            id=u["_id"],
            email=u["email"],
            username=u["username"],
            full_name=u.get("full_name"),
            role=UserRole(u["role"]),
            is_active=u.get("is_active", True),
            last_login=u.get("last_login"),
            created_at=u.get("created_at"),
            updated_at=u.get("updated_at")
        )
        for u in users
    ]
    
    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get user by ID.
    
    Users can only view their own profile unless they're admin.
    """
    # Check permissions
    if current_user["role"] == Role.USER and current_user["_id"] != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="دسترسی غیرمجاز"
        )
    
    user = await users_collection().find_one(
        {"_id": user_id},
        {"hashed_password": 0}
    )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="کاربر یافت نشد"
        )
    
    return UserResponse(
        id=user["_id"],
        email=user["email"],
        username=user["username"],
        full_name=user.get("full_name"),
        role=UserRole(user["role"]),
        is_active=user.get("is_active", True),
        last_login=user.get("last_login"),
        created_at=user.get("created_at"),
        updated_at=user.get("updated_at")
    )


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_data: UserUpdate,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Update user profile.
    
    Users can update their own profile. Admins can update any user.
    """
    client_ip = get_client_ip(request)
    
    # Check permissions
    is_self = current_user["_id"] == user_id
    is_admin = current_user["role"] in [Role.ADMIN, Role.OWNER]
    
    if not is_self and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="دسترسی غیرمجاز"
        )
    
    user = await users_collection().find_one({"_id": user_id})
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="کاربر یافت نشد"
        )
    
    # Build update
    update = {"updated_at": datetime.now(timezone.utc)}
    
    if user_data.email:
        # Check if email is taken
        existing = await users_collection().find_one({
            "email": user_data.email,
            "_id": {"$ne": user_id}
        })
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="این ایمیل قبلاً ثبت شده است"
            )
        update["email"] = user_data.email
    
    if user_data.full_name is not None:
        update["full_name"] = user_data.full_name
    
    # Password change
    if user_data.new_password:
        if not is_self:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="فقط کاربر می‌تواند رمز عبور خود را تغییر دهد"
            )
        
        if not user_data.current_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="رمز عبور فعلی الزامی است"
            )
        
        if not verify_password(user_data.current_password, user["hashed_password"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="رمز عبور فعلی اشتباه است"
            )
        
        update["hashed_password"] = get_password_hash(user_data.new_password)
    
    await users_collection().update_one(
        {"_id": user_id},
        {"$set": update}
    )
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="user_updated",
        resource_type="user",
        resource_id=user_id,
        details={"fields_updated": list(update.keys())},
        ip_address=client_ip
    )
    
    # Get updated user
    updated_user = await users_collection().find_one(
        {"_id": user_id},
        {"hashed_password": 0}
    )
    
    return UserResponse(
        id=updated_user["_id"],
        email=updated_user["email"],
        username=updated_user["username"],
        full_name=updated_user.get("full_name"),
        role=UserRole(updated_user["role"]),
        is_active=updated_user.get("is_active", True),
        last_login=updated_user.get("last_login"),
        created_at=updated_user.get("created_at"),
        updated_at=updated_user.get("updated_at")
    )


@router.patch("/{user_id}/role")
async def update_user_role(
    user_id: str,
    role: UserRole,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_minimum_role(Role.OWNER))
):
    """
    Update user role (owner only).
    """
    client_ip = get_client_ip(request)
    
    # Can't change own role
    if current_user["_id"] == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="نمی‌توانید نقش خود را تغییر دهید"
        )
    
    user = await users_collection().find_one({"_id": user_id})
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="کاربر یافت نشد"
        )
    
    await users_collection().update_one(
        {"_id": user_id},
        {"$set": {
            "role": role.value,
            "updated_at": datetime.now(timezone.utc)
        }}
    )
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="user_role_changed",
        resource_type="user",
        resource_id=user_id,
        details={"old_role": user["role"], "new_role": role.value},
        ip_address=client_ip
    )
    
    logger.info(f"User role changed: {user['email']} -> {role.value}")
    
    return {"message": f"نقش کاربر به {role.value} تغییر یافت"}


@router.patch("/{user_id}/status")
async def toggle_user_status(
    user_id: str,
    is_active: bool,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_minimum_role(Role.ADMIN))
):
    """
    Enable or disable a user account (admin only).
    """
    client_ip = get_client_ip(request)
    
    # Can't disable own account
    if current_user["_id"] == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="نمی‌توانید حساب خود را غیرفعال کنید"
        )
    
    user = await users_collection().find_one({"_id": user_id})
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="کاربر یافت نشد"
        )
    
    # Can't disable owner
    if user["role"] == Role.OWNER and not is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="نمی‌توان حساب مالک را غیرفعال کرد"
        )
    
    await users_collection().update_one(
        {"_id": user_id},
        {"$set": {
            "is_active": is_active,
            "updated_at": datetime.now(timezone.utc)
        }}
    )
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="user_status_changed",
        resource_type="user",
        resource_id=user_id,
        details={"is_active": is_active},
        ip_address=client_ip
    )
    
    status_text = "فعال" if is_active else "غیرفعال"
    logger.info(f"User status changed: {user['email']} -> {status_text}")
    
    return {"message": f"حساب کاربر {status_text} شد"}


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(require_minimum_role(Role.OWNER))
):
    """
    Delete a user account (owner only).
    """
    client_ip = get_client_ip(request)
    
    # Can't delete own account
    if current_user["_id"] == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="نمی‌توانید حساب خود را حذف کنید"
        )
    
    user = await users_collection().find_one({"_id": user_id})
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="کاربر یافت نشد"
        )
    
    # Can't delete owner
    if user["role"] == Role.OWNER:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="نمی‌توان حساب مالک را حذف کرد"
        )
    
    await users_collection().delete_one({"_id": user_id})
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="user_deleted",
        resource_type="user",
        resource_id=user_id,
        details={"email": user["email"]},
        ip_address=client_ip
    )
    
    logger.info(f"User deleted: {user['email']}")
    
    return {"message": "کاربر با موفقیت حذف شد"}