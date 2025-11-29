"""
Security utilities: JWT tokens, password hashing, RBAC, rate limiting.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import secrets
import hashlib
import logging

from app.core.config import settings
from app.core.database import users_collection, sessions_collection, audit_logs_collection

logger = logging.getLogger(__name__)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Bearer token security
security = HTTPBearer()


# Enums and constants
class Role:
    OWNER = "owner"
    ADMIN = "admin"
    USER = "user"


ROLE_HIERARCHY = {
    Role.OWNER: 3,
    Role.ADMIN: 2,
    Role.USER: 1
}


class TokenData(BaseModel):
    """JWT token payload data."""
    user_id: str
    email: str
    role: str
    exp: datetime


class TokenResponse(BaseModel):
    """Token response model."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    
    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    """Create JWT refresh token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[TokenData]:
    """Decode and validate JWT token."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        email: str = payload.get("email")
        role: str = payload.get("role")
        exp: datetime = datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc)
        
        if user_id is None:
            return None
            
        return TokenData(user_id=user_id, email=email, role=role, exp=exp)
        
    except JWTError as e:
        logger.warning(f"JWT decode error: {e}")
        return None


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """Get current authenticated user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    token = credentials.credentials
    token_data = decode_token(token)
    
    if token_data is None:
        raise credentials_exception
    
    # Get user from database
    user = await users_collection().find_one({"_id": token_data.user_id})
    
    if user is None:
        raise credentials_exception
    
    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    return user


async def get_current_active_user(
    current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """Get current active user."""
    if not current_user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user


def require_role(allowed_roles: List[str]):
    """Dependency to require specific roles."""
    async def role_checker(
        current_user: Dict[str, Any] = Depends(get_current_user)
    ) -> Dict[str, Any]:
        user_role = current_user.get("role", Role.USER)
        
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        return current_user
    
    return role_checker


def require_minimum_role(minimum_role: str):
    """Dependency to require minimum role level."""
    async def role_checker(
        current_user: Dict[str, Any] = Depends(get_current_user)
    ) -> Dict[str, Any]:
        user_role = current_user.get("role", Role.USER)
        user_level = ROLE_HIERARCHY.get(user_role, 0)
        required_level = ROLE_HIERARCHY.get(minimum_role, 0)
        
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        
        return current_user
    
    return role_checker


# Domain ownership verification
def generate_verification_token() -> str:
    """Generate a secure verification token for domain ownership."""
    return secrets.token_urlsafe(settings.VERIFICATION_TOKEN_LENGTH)


def get_dns_txt_record(domain: str) -> str:
    """Get the expected DNS TXT record name for verification."""
    return f"{settings.DNS_TXT_PREFIX}.{domain}"


def get_verification_file_content(token: str) -> str:
    """Get the content for the verification file."""
    return f"owasp-scanner-verification={token}"


# Audit logging
async def log_audit_event(
    user_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None
):
    """Log an audit event."""
    if not settings.AUDIT_LOG_ENABLED:
        return
    
    audit_entry = {
        "user_id": user_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "details": details or {},
        "ip_address": ip_address,
        "created_at": datetime.now(timezone.utc)
    }
    
    try:
        await audit_logs_collection().insert_one(audit_entry)
    except Exception as e:
        logger.error(f"Failed to log audit event: {e}")


# Rate limiting helper
class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(self):
        self.requests: Dict[str, List[datetime]] = {}
    
    def is_allowed(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        """Check if request is allowed within rate limit."""
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=window_seconds)
        
        if key not in self.requests:
            self.requests[key] = []
        
        # Clean old requests
        self.requests[key] = [
            req_time for req_time in self.requests[key]
            if req_time > window_start
        ]
        
        if len(self.requests[key]) >= limit:
            return False
        
        self.requests[key].append(now)
        return True
    
    def get_remaining(self, key: str, limit: int, window_seconds: int = 60) -> int:
        """Get remaining requests in current window."""
        now = datetime.now(timezone.utc)
        window_start = now - timedelta(seconds=window_seconds)
        
        if key not in self.requests:
            return limit
        
        recent_requests = [
            req_time for req_time in self.requests[key]
            if req_time > window_start
        ]
        
        return max(0, limit - len(recent_requests))


# Global rate limiter instance
rate_limiter = RateLimiter()


def get_client_ip(request: Request) -> str:
    """Extract client IP from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# Payload safety check
def is_payload_safe(payload: str) -> bool:
    """
    Basic check if a payload should be considered safe mode.
    Aggressive payloads that could cause damage are flagged.
    """
    aggressive_patterns = [
        "DROP TABLE",
        "DELETE FROM",
        "TRUNCATE",
        "UPDATE",
        "INSERT INTO",
        "EXEC(",
        "xp_cmdshell",
        "rm -rf",
        "shutdown",
        "format c:",
        "; rm ",
        "| rm ",
        "&& rm ",
    ]
    
    payload_upper = payload.upper()
    for pattern in aggressive_patterns:
        if pattern.upper() in payload_upper:
            return False
    
    return True


# Redact sensitive data in logs
def redact_payload(payload: str, max_length: int = 50) -> str:
    """Redact payload for safe logging."""
    if len(payload) <= max_length:
        return f"[PAYLOAD:{hashlib.md5(payload.encode()).hexdigest()[:8]}]"
    return f"[PAYLOAD:{hashlib.md5(payload.encode()).hexdigest()[:8]}:truncated]"


def redact_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Redact sensitive headers for logging."""
    sensitive_keys = ["authorization", "cookie", "x-api-key", "api-key"]
    redacted = {}
    
    for key, value in headers.items():
        if key.lower() in sensitive_keys:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    
    return redacted