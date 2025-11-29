"""
Pydantic models for API requests and responses.
"""
from pydantic import BaseModel, Field, EmailStr, HttpUrl, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import re


# Enums
class UserRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    USER = "user"


class ScanStatus(str, Enum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanMode(str, Enum):
    SAFE = "safe"
    AGGRESSIVE = "aggressive"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VerificationMethod(str, Enum):
    DNS_TXT = "dns_txt"
    FILE = "file"


class VerificationStatus(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"


class ReportFormat(str, Enum):
    PDF = "pdf"
    HTML = "html"
    JSON = "json"


# Base Models
class TimestampMixin(BaseModel):
    """Mixin for timestamp fields."""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


# User Models
class UserBase(BaseModel):
    """Base user model."""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    full_name: Optional[str] = Field(None, max_length=100)


class UserCreate(UserBase):
    """User creation model."""
    password: str = Field(..., min_length=8, max_length=100)
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        return v


class UserUpdate(BaseModel):
    """User update model."""
    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(None, max_length=100)
    current_password: Optional[str] = None
    new_password: Optional[str] = Field(None, min_length=8, max_length=100)


class UserResponse(UserBase, TimestampMixin):
    """User response model."""
    id: str
    role: UserRole = UserRole.USER
    is_active: bool = True
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class UserInDB(UserBase, TimestampMixin):
    """User model for database."""
    id: str
    hashed_password: str
    role: UserRole = UserRole.USER
    is_active: bool = True
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    last_login: Optional[datetime] = None


# Auth Models
class LoginRequest(BaseModel):
    """Login request model."""
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """Token response model."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshTokenRequest(BaseModel):
    """Refresh token request model."""
    refresh_token: str


# Project Models
class EndpointConfig(BaseModel):
    """Endpoint configuration for scanning."""
    path: str = Field(..., description="URL path to scan")
    method: str = Field(default="GET", pattern="^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)$")
    params: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None
    requires_auth: bool = False


class ProjectBase(BaseModel):
    """Base project model."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    domain: str = Field(..., description="Target domain (e.g., example.com)")
    
    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v):
        # Basic domain validation
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(pattern, v):
            raise ValueError('Invalid domain format')
        return v.lower()


class ProjectCreate(ProjectBase):
    """Project creation model."""
    endpoints: List[EndpointConfig] = Field(default_factory=list)
    auth_config: Optional[Dict[str, Any]] = None


class ProjectUpdate(BaseModel):
    """Project update model."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    endpoints: Optional[List[EndpointConfig]] = None
    auth_config: Optional[Dict[str, Any]] = None


class ProjectResponse(ProjectBase, TimestampMixin):
    """Project response model."""
    id: str
    owner_id: str
    endpoints: List[EndpointConfig] = []
    verification_status: VerificationStatus = VerificationStatus.PENDING
    is_verified: bool = False
    last_scan_at: Optional[datetime] = None
    scan_count: int = 0
    
    class Config:
        from_attributes = True


# Verification Models
class VerificationRequest(BaseModel):
    """Domain verification request."""
    method: VerificationMethod


class VerificationResponse(BaseModel):
    """Domain verification response."""
    project_id: str
    method: VerificationMethod
    token: str
    instructions: str
    dns_record: Optional[str] = None
    file_path: Optional[str] = None
    file_content: Optional[str] = None
    expires_at: datetime


class VerificationCheck(BaseModel):
    """Verification check result."""
    verified: bool
    method: VerificationMethod
    message: str


# Scan Models
class ScanConfig(BaseModel):
    """Scan configuration."""
    mode: ScanMode = ScanMode.SAFE
    categories: List[str] = Field(default_factory=lambda: ["INFO", "CONF", "INPV"])
    max_depth: int = Field(default=3, ge=1, le=10)
    request_delay_ms: int = Field(default=100, ge=50, le=5000)
    timeout_seconds: int = Field(default=30, ge=5, le=120)
    follow_redirects: bool = True
    max_payloads_per_test: int = Field(default=100, ge=1, le=1000)
    concurrent_requests: int = Field(default=5, ge=1, le=20)
    custom_headers: Optional[Dict[str, str]] = None
    auth_token: Optional[str] = None


class ScanCreate(BaseModel):
    """Scan creation model."""
    project_id: str
    config: ScanConfig = Field(default_factory=ScanConfig)
    scheduled_at: Optional[datetime] = None
    endpoints: Optional[List[str]] = None  # Specific endpoints to scan, or all if None


class ScanResponse(TimestampMixin):
    """Scan response model."""
    id: str
    project_id: str
    status: ScanStatus
    config: ScanConfig
    progress: float = 0.0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    error_message: Optional[str] = None
    
    class Config:
        from_attributes = True


class ScanProgress(BaseModel):
    """Scan progress update."""
    scan_id: str
    status: ScanStatus
    progress: float
    current_test: Optional[str] = None
    tests_completed: int = 0
    tests_total: int = 0


# Finding Models
class FindingBase(BaseModel):
    """Base finding model."""
    title: str
    description: str
    severity: SeverityLevel
    wstg_id: str = Field(..., description="WSTG test ID (e.g., WSTG-INPV-05)")
    owasp_top10_id: Optional[str] = Field(None, description="OWASP Top 10 ID (e.g., A03)")
    endpoint: str
    method: str = "GET"
    evidence: Optional[str] = None
    recommendation: str
    recommendation_fa: Optional[str] = None  # Persian recommendation
    cvss_score: Optional[float] = Field(None, ge=0, le=10)


class FindingCreate(FindingBase):
    """Finding creation model."""
    scan_id: str
    raw_request: Optional[str] = None  # Will be redacted
    raw_response: Optional[str] = None  # Will be redacted


class FindingResponse(FindingBase, TimestampMixin):
    """Finding response model."""
    id: str
    scan_id: str
    project_id: str
    is_false_positive: bool = False
    verified: bool = False
    notes: Optional[str] = None
    
    class Config:
        from_attributes = True


class FindingUpdate(BaseModel):
    """Finding update model."""
    is_false_positive: Optional[bool] = None
    verified: Optional[bool] = None
    notes: Optional[str] = Field(None, max_length=1000)


# Report Models
class ReportRequest(BaseModel):
    """Report generation request."""
    scan_id: str
    format: ReportFormat = ReportFormat.PDF
    include_evidence: bool = False
    include_remediation: bool = True
    language: str = Field(default="fa", pattern="^(en|fa)$")


class ReportResponse(BaseModel):
    """Report response model."""
    id: str
    scan_id: str
    format: ReportFormat
    file_path: str
    download_url: str
    expires_at: datetime
    created_at: datetime


# Payload Models
class PayloadCategory(str, Enum):
    SQLI = "sqli"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    LDAP_INJECTION = "ldap_injection"
    NOSQL_INJECTION = "nosql_injection"
    HEADER_INJECTION = "header_injection"


class PayloadInfo(BaseModel):
    """Payload information."""
    id: str
    category: PayloadCategory
    name: str
    description: Optional[str] = None
    is_aggressive: bool = False
    source: str = "PayloadsAllTheThings"


class PayloadStats(BaseModel):
    """Payload statistics."""
    total_count: int
    by_category: Dict[str, int]
    safe_count: int
    aggressive_count: int
    last_sync: Optional[datetime] = None


# Dashboard Models
class DashboardStats(BaseModel):
    """Dashboard statistics."""
    total_projects: int
    total_scans: int
    total_findings: int
    findings_by_severity: Dict[str, int]
    recent_scans: List[ScanResponse]
    top_vulnerabilities: List[Dict[str, Any]]


# Pagination
class PaginatedResponse(BaseModel):
    """Paginated response wrapper."""
    items: List[Any]
    total: int
    page: int
    page_size: int
    pages: int


class PaginationParams(BaseModel):
    """Pagination parameters."""
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=20, ge=1, le=100)