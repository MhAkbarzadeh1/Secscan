"""
Domain verification API routes.

Users must verify domain ownership before scanning.
Supports DNS TXT record and file-based verification.
"""
from fastapi import APIRouter, HTTPException, status, Depends, Request
from datetime import datetime, timedelta, timezone
from typing import Dict, Any
import uuid
import dns.resolver
import aiohttp
import logging

from app.models.schemas import (
    VerificationRequest, VerificationResponse, VerificationCheck,
    VerificationMethod, VerificationStatus
)
from app.core.security import (
    get_current_user, generate_verification_token,
    get_dns_txt_record, get_verification_file_content,
    log_audit_event, get_client_ip, Role
)
from app.core.database import projects_collection, verifications_collection
from app.core.config import settings

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/{project_id}/initiate", response_model=VerificationResponse)
async def initiate_verification(
    project_id: str,
    verification_data: VerificationRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Initiate domain ownership verification.
    
    Generates a verification token that must be added as:
    - DNS TXT record: _owasp-scanner-verify.domain.com
    - Or file at: /.well-known/owasp-scanner-verify.txt
    """
    client_ip = get_client_ip(request)
    
    # Get project
    project = await projects_collection().find_one({"_id": project_id})
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Check ownership
    if current_user["role"] == Role.USER and project["owner_id"] != current_user["_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Check if already verified
    if project.get("is_verified"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Domain already verified"
        )
    
    # Generate or get existing verification
    existing_verification = await verifications_collection().find_one({
        "project_id": project_id,
        "expires_at": {"$gt": datetime.now(timezone.utc)}
    })
    
    if existing_verification:
        token = existing_verification["token"]
        expires_at = existing_verification["expires_at"]
    else:
        # Generate new token
        token = generate_verification_token()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
        
        verification_doc = {
            "_id": str(uuid.uuid4()),
            "project_id": project_id,
            "method": verification_data.method.value,
            "token": token,
            "status": VerificationStatus.PENDING.value,
            "attempts": 0,
            "created_at": datetime.now(timezone.utc),
            "expires_at": expires_at
        }
        
        # Delete old verifications
        await verifications_collection().delete_many({"project_id": project_id})
        await verifications_collection().insert_one(verification_doc)
    
    domain = project["domain"]
    
    # Build response based on method
    if verification_data.method == VerificationMethod.DNS_TXT:
        dns_record = get_dns_txt_record(domain)
        instructions = f"""
برای تأیید مالکیت دامنه، یک رکورد DNS TXT اضافه کنید:

نام رکورد: {dns_record}
مقدار: owasp-scanner-verification={token}

توجه: انتشار DNS ممکن است تا ۲۴ ساعت طول بکشد.
        """.strip()
        
        return VerificationResponse(
            project_id=project_id,
            method=verification_data.method,
            token=token,
            instructions=instructions,
            dns_record=dns_record,
            expires_at=expires_at
        )
    
    else:  # FILE method
        file_path = f"/.well-known/{settings.VERIFICATION_FILE_NAME}"
        file_content = get_verification_file_content(token)
        instructions = f"""
برای تأیید مالکیت دامنه، فایل زیر را در سرور خود ایجاد کنید:

مسیر فایل: https://{domain}{file_path}
محتوای فایل: {file_content}

فایل باید از طریق HTTPS قابل دسترسی باشد.
        """.strip()
        
        return VerificationResponse(
            project_id=project_id,
            method=verification_data.method,
            token=token,
            instructions=instructions,
            file_path=file_path,
            file_content=file_content,
            expires_at=expires_at
        )


@router.post("/{project_id}/verify", response_model=VerificationCheck)
async def verify_domain(
    project_id: str,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Verify domain ownership by checking DNS TXT record or verification file.
    """
    client_ip = get_client_ip(request)
    
    # Get project
    project = await projects_collection().find_one({"_id": project_id})
    
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Check ownership
    if current_user["role"] == Role.USER and project["owner_id"] != current_user["_id"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Get verification record
    verification = await verifications_collection().find_one({
        "project_id": project_id,
        "expires_at": {"$gt": datetime.now(timezone.utc)}
    })
    
    if not verification:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending verification found. Please initiate verification first."
        )
    
    # Increment attempts
    await verifications_collection().update_one(
        {"_id": verification["_id"]},
        {"$inc": {"attempts": 1}}
    )
    
    domain = project["domain"]
    token = verification["token"]
    method = VerificationMethod(verification["method"])
    verified = False
    message = ""
    
    try:
        if method == VerificationMethod.DNS_TXT:
            verified, message = await verify_dns_txt(domain, token)
        else:
            verified, message = await verify_file(domain, token)
        
    except Exception as e:
        logger.error(f"Verification error for {domain}: {e}")
        message = f"خطا در فرآیند تأیید: {str(e)}"
    
    if verified:
        # Update project as verified
        await projects_collection().update_one(
            {"_id": project_id},
            {"$set": {
                "is_verified": True,
                "verification_status": VerificationStatus.VERIFIED.value,
                "verified_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }}
        )
        
        # Update verification record
        await verifications_collection().update_one(
            {"_id": verification["_id"]},
            {"$set": {
                "status": VerificationStatus.VERIFIED.value,
                "verified_at": datetime.now(timezone.utc)
            }}
        )
        
        # Audit log
        await log_audit_event(
            user_id=current_user["_id"],
            action="domain_verified",
            resource_type="project",
            resource_id=project_id,
            details={"domain": domain, "method": method.value},
            ip_address=client_ip
        )
        
        logger.info(f"Domain verified: {domain} (method: {method.value})")
    
    return VerificationCheck(
        verified=verified,
        method=method,
        message=message
    )


async def verify_dns_txt(domain: str, token: str) -> tuple[bool, str]:
    """Verify domain via DNS TXT record."""
    txt_record_name = get_dns_txt_record(domain)
    expected_value = f"owasp-scanner-verification={token}"
    
    try:
        # Query DNS
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10
        
        try:
            answers = resolver.resolve(txt_record_name, 'TXT')
            
            for rdata in answers:
                txt_value = str(rdata).strip('"')
                if txt_value == expected_value:
                    return True, "✅ تأیید مالکیت دامنه با موفقیت انجام شد."
            
            return False, f"❌ رکورد DNS TXT یافت شد اما مقدار صحیح نیست. مقدار مورد انتظار: {expected_value}"
            
        except dns.resolver.NXDOMAIN:
            return False, f"❌ رکورد DNS TXT یافت نشد: {txt_record_name}"
        except dns.resolver.NoAnswer:
            return False, f"❌ پاسخی برای رکورد TXT دریافت نشد: {txt_record_name}"
            
    except Exception as e:
        return False, f"❌ خطا در بررسی DNS: {str(e)}"


async def verify_file(domain: str, token: str) -> tuple[bool, str]:
    """Verify domain via file on server."""
    file_url = f"https://{domain}/.well-known/{settings.VERIFICATION_FILE_NAME}"
    expected_content = get_verification_file_content(token)
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                file_url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False  # Allow self-signed certs for testing
            ) as response:
                
                if response.status != 200:
                    return False, f"❌ فایل تأیید یافت نشد (کد: {response.status}). آدرس: {file_url}"
                
                content = await response.text()
                content = content.strip()
                
                if content == expected_content:
                    return True, "✅ تأیید مالکیت دامنه با موفقیت انجام شد."
                else:
                    return False, f"❌ محتوای فایل صحیح نیست. مقدار مورد انتظار: {expected_content}"
                    
    except aiohttp.ClientError as e:
        return False, f"❌ خطا در دسترسی به فایل: {str(e)}"
    except Exception as e:
        return False, f"❌ خطای غیرمنتظره: {str(e)}"


@router.get("/{project_id}/status")
async def get_verification_status(
    project_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get current verification status for a project.
    """
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
    
    verification = await verifications_collection().find_one({"project_id": project_id})
    
    return {
        "project_id": project_id,
        "domain": project["domain"],
        "is_verified": project.get("is_verified", False),
        "verification_status": project.get("verification_status", VerificationStatus.PENDING.value),
        "verified_at": project.get("verified_at"),
        "pending_verification": verification is not None and not project.get("is_verified"),
        "verification_method": verification.get("method") if verification else None,
        "verification_expires_at": verification.get("expires_at") if verification else None
    }