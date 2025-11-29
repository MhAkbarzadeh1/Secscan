"""
Utility helper functions
"""
import re
import hashlib
import secrets
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse


def generate_token(length: int = 32) -> str:
    """Generate a secure random token"""
    return secrets.token_urlsafe(length)


def hash_string(value: str) -> str:
    """Create SHA256 hash of string"""
    return hashlib.sha256(value.encode()).hexdigest()


def is_valid_domain(domain: str) -> bool:
    """Validate domain format"""
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def is_valid_url(url: str) -> bool:
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def normalize_url(url: str) -> str:
    """Normalize URL (remove trailing slash, lowercase)"""
    url = url.lower().strip()
    if url.endswith('/'):
        url = url[:-1]
    return url


def extract_domain(url: str) -> Optional[str]:
    """Extract domain from URL"""
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    except:
        return None


def truncate_string(text: str, max_length: int = 100) -> str:
    """Truncate string with ellipsis"""
    if len(text) <= max_length:
        return text
    return text[:max_length - 3] + "..."


def safe_filename(filename: str) -> str:
    """Sanitize filename"""
    return re.sub(r'[^\w\-_\.]', '_', filename)


def format_bytes(size: int) -> str:
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def get_severity_weight(severity: str) -> int:
    """Get numeric weight for severity"""
    weights = {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'info': 1
    }
    return weights.get(severity.lower(), 0)


def mask_sensitive(text: str, visible_chars: int = 4) -> str:
    """Mask sensitive data"""
    if len(text) <= visible_chars:
        return '*' * len(text)
    return text[:visible_chars] + '*' * (len(text) - visible_chars)