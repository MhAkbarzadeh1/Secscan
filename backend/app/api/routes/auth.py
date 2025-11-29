"""
Authentication API routes.
"""
from fastapi import APIRouter, HTTPException, status, Depends, Request
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
import uuid
import logging

from app.models.schemas import (
    UserCreate, UserResponse, LoginRequest, TokenResponse, RefreshTokenRequest
)
from app.core.security import (
    get_password_hash, verify_password, create_access_token, 
    create_refresh_token, decode_token, get_current_user,
    rate_limiter, get_client_ip, log_audit_event, Role
)
from app.core.database import users_collection, sessions_collection
from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, request: Request):
    """
    Register a new user.
    
    First user becomes owner, subsequent users are regular users.
    """
    client_ip = get_client_ip(request)
    
    # Rate limiting
    if not rate_limiter.is_allowed(f"register:{client_ip}", limit=5, window_seconds=3600):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts. Please try again later."
        )
    
    # Check if email exists
    existing_user = await users_collection().find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Check if username exists
    existing_username = await users_collection().find_one({"username": user_data.username})
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )
    
    # Determine role (first user is owner)
    user_count = await users_collection().count_documents({})
    role = Role.OWNER if user_count == 0 else Role.USER
    
    # Create user
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    
    user_doc = {
        "_id": user_id,
        "email": user_data.email,
        "username": user_data.username,
        "full_name": user_data.full_name,
        "hashed_password": get_password_hash(user_data.password),
        "role": role,
        "is_active": True,
        "failed_login_attempts": 0,
        "locked_until": None,
        "last_login": None,
        "created_at": now,
        "updated_at": now
    }
    
    await users_collection().insert_one(user_doc)
    
    # Audit log
    await log_audit_event(
        user_id=user_id,
        action="user_registered",
        resource_type="user",
        resource_id=user_id,
        ip_address=client_ip
    )
    
    logger.info(f"New user registered: {user_data.email} (role: {role})")
    
    return UserResponse(
        id=user_id,
        email=user_data.email,
        username=user_data.username,
        full_name=user_data.full_name,
        role=role,
        is_active=True,
        created_at=now,
        updated_at=now
    )


@router.post("/login", response_model=TokenResponse)
async def login(credentials: LoginRequest, request: Request):
    """
    Authenticate user and return JWT tokens.
    """
    client_ip = get_client_ip(request)
    
    # Rate limiting
    if not rate_limiter.is_allowed(f"login:{client_ip}", limit=10, window_seconds=60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please wait before trying again."
        )
    
    # Find user
    user = await users_collection().find_one({"email": credentials.email})
    
    if not user:
        # Don't reveal whether email exists
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    # Check if account is locked
    if user.get("locked_until"):
        lock_time = user["locked_until"]
        if lock_time > datetime.now(timezone.utc):
            remaining = (lock_time - datetime.now(timezone.utc)).seconds // 60
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account temporarily locked. Try again in {remaining} minutes."
            )
        else:
            # Reset lock
            await users_collection().update_one(
                {"_id": user["_id"]},
                {"$set": {"locked_until": None, "failed_login_attempts": 0}}
            )
    
    # Verify password
    if not verify_password(credentials.password, user["hashed_password"]):
        # Increment failed attempts
        failed_attempts = user.get("failed_login_attempts", 0) + 1
        update_data = {"failed_login_attempts": failed_attempts}
        
        if failed_attempts >= settings.MAX_LOGIN_ATTEMPTS:
            update_data["locked_until"] = datetime.now(timezone.utc) + timedelta(
                minutes=settings.LOCKOUT_DURATION_MINUTES
            )
            logger.warning(f"Account locked due to failed attempts: {credentials.email}")
        
        await users_collection().update_one(
            {"_id": user["_id"]},
            {"$set": update_data}
        )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    # Check if user is active
    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled"
        )
    
    # Reset failed attempts and update last login
    now = datetime.now(timezone.utc)
    await users_collection().update_one(
        {"_id": user["_id"]},
        {"$set": {
            "failed_login_attempts": 0,
            "locked_until": None,
            "last_login": now
        }}
    )
    
    # Create tokens
    token_data = {
        "sub": user["_id"],
        "email": user["email"],
        "role": user["role"]
    }
    
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)
    
    # Store refresh token in database
    session_id = str(uuid.uuid4())
    await sessions_collection().insert_one({
        "_id": session_id,
        "user_id": user["_id"],
        "refresh_token": refresh_token,
        "ip_address": client_ip,
        "user_agent": request.headers.get("user-agent", ""),
        "created_at": now,
        "expires_at": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    })
    
    # Audit log
    await log_audit_event(
        user_id=user["_id"],
        action="user_login",
        resource_type="session",
        resource_id=session_id,
        ip_address=client_ip
    )
    
    logger.info(f"User logged in: {credentials.email}")
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request_data: RefreshTokenRequest, request: Request):
    """
    Refresh access token using refresh token.
    """
    client_ip = get_client_ip(request)
    
    # Decode refresh token
    token_data = decode_token(request_data.refresh_token)
    
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    # Verify refresh token exists in database
    session = await sessions_collection().find_one({
        "refresh_token": request_data.refresh_token,
        "user_id": token_data.user_id
    })
    
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found or expired"
        )
    
    # Check expiration
    if session.get("expires_at") and session["expires_at"] < datetime.now(timezone.utc):
        await sessions_collection().delete_one({"_id": session["_id"]})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired"
        )
    
    # Get user
    user = await users_collection().find_one({"_id": token_data.user_id})
    
    if not user or not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    # Create new tokens
    new_token_data = {
        "sub": user["_id"],
        "email": user["email"],
        "role": user["role"]
    }
    
    new_access_token = create_access_token(new_token_data)
    new_refresh_token = create_refresh_token(new_token_data)
    
    # Update session with new refresh token
    now = datetime.now(timezone.utc)
    await sessions_collection().update_one(
        {"_id": session["_id"]},
        {"$set": {
            "refresh_token": new_refresh_token,
            "updated_at": now,
            "expires_at": now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        }}
    )
    
    logger.info(f"Token refreshed for user: {user['email']}")
    
    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post("/logout")
async def logout(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Logout user and invalidate refresh token.
    """
    client_ip = get_client_ip(request)
    
    # Delete user's session (could also delete all sessions for the user)
    result = await sessions_collection().delete_many({"user_id": current_user["_id"]})
    
    # Audit log
    await log_audit_event(
        user_id=current_user["_id"],
        action="user_logout",
        resource_type="session",
        resource_id=current_user["_id"],
        details={"sessions_deleted": result.deleted_count},
        ip_address=client_ip
    )
    
    logger.info(f"User logged out: {current_user['email']}")
    
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Get current authenticated user profile.
    """
    return UserResponse(
        id=current_user["_id"],
        email=current_user["email"],
        username=current_user["username"],
        full_name=current_user.get("full_name"),
        role=current_user["role"],
        is_active=current_user["is_active"],
        last_login=current_user.get("last_login"),
        created_at=current_user.get("created_at"),
        updated_at=current_user.get("updated_at")
    )