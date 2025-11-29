"""
Application configuration using Pydantic settings.
All sensitive values are loaded from environment variables.
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List
import secrets


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    APP_NAME: str = "OWASP Security Scanner"
    APP_ENV: str = Field(default="development")
    DEBUG: bool = Field(default=False)
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    
    # MongoDB
    MONGODB_URL: str = Field(default="mongodb://mongodb:27017")
    MONGODB_DB_NAME: str = Field(default="owasp_scanner")
    
    # Redis
    REDIS_URL: str = Field(default="redis://redis:6379/0")
    
    # JWT Settings
    JWT_SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # CORS
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173"
          
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60
    SCAN_RATE_LIMIT_PER_MINUTE: int = 10
    
    # Scanner Settings
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_TIMEOUT_SECONDS: int = 3600
    DEFAULT_REQUEST_DELAY_MS: int = 100
    AGGRESSIVE_REQUEST_DELAY_MS: int = 50
    MAX_PAYLOADS_PER_SCAN: int = 1000
    
    # Payload Repository
    PAYLOADS_REPO_URL: str = "https://github.com/swisskyrepo/PayloadsAllTheThings.git"
    PAYLOADS_DIR: str = "/app/payloads"
    
    # Reports
    REPORTS_DIR: str = "/app/reports"
    REPORT_TTL_DAYS: int = 30
    
    # AI Settings (for result triage)
    AI_ENABLED: bool = Field(default=True)
    AI_API_KEY: str = Field(default="")
    AI_MODEL: str = Field(default="gpt-3.5-turbo")
    
    # Domain Verification
    VERIFICATION_TOKEN_LENGTH: int = 32
    VERIFICATION_FILE_NAME: str = "owasp-scanner-verify.txt"
    DNS_TXT_PREFIX: str = "_owasp-scanner-verify"
    
    # Security
    BCRYPT_ROUNDS: int = 12
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15
    
    # Logging
    LOG_LEVEL: str = "INFO"
    AUDIT_LOG_ENABLED: bool = True
    
    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()


# OWASP WSTG Categories
WSTG_CATEGORIES = {
    "INFO": {
        "name": "Information Gathering",
        "code": "WSTG-INFO",
        "tests": [
            {"id": "WSTG-INFO-01", "name": "Conduct Search Engine Discovery"},
            {"id": "WSTG-INFO-02", "name": "Fingerprint Web Server"},
            {"id": "WSTG-INFO-03", "name": "Review Webserver Metafiles"},
            {"id": "WSTG-INFO-04", "name": "Enumerate Applications on Webserver"},
            {"id": "WSTG-INFO-05", "name": "Review Webpage Content for Information Leakage"},
            {"id": "WSTG-INFO-06", "name": "Identify Application Entry Points"},
            {"id": "WSTG-INFO-07", "name": "Map Execution Paths Through Application"},
            {"id": "WSTG-INFO-08", "name": "Fingerprint Web Application Framework"},
            {"id": "WSTG-INFO-09", "name": "Fingerprint Web Application"},
            {"id": "WSTG-INFO-10", "name": "Map Application Architecture"},
        ]
    },
    "CONF": {
        "name": "Configuration and Deploy Management",
        "code": "WSTG-CONF",
        "tests": [
            {"id": "WSTG-CONF-01", "name": "Test Network Infrastructure Configuration"},
            {"id": "WSTG-CONF-02", "name": "Test Application Platform Configuration"},
            {"id": "WSTG-CONF-03", "name": "Test File Extensions Handling"},
            {"id": "WSTG-CONF-04", "name": "Review Old Backup and Unreferenced Files"},
            {"id": "WSTG-CONF-05", "name": "Enumerate Infrastructure and Application Admin Interfaces"},
            {"id": "WSTG-CONF-06", "name": "Test HTTP Methods"},
            {"id": "WSTG-CONF-07", "name": "Test HTTP Strict Transport Security"},
            {"id": "WSTG-CONF-08", "name": "Test RIA Cross Domain Policy"},
            {"id": "WSTG-CONF-09", "name": "Test File Permission"},
            {"id": "WSTG-CONF-10", "name": "Test for Subdomain Takeover"},
            {"id": "WSTG-CONF-11", "name": "Test Cloud Storage"},
        ]
    },
    "IDNT": {
        "name": "Identity Management",
        "code": "WSTG-IDNT",
        "tests": [
            {"id": "WSTG-IDNT-01", "name": "Test Role Definitions"},
            {"id": "WSTG-IDNT-02", "name": "Test User Registration Process"},
            {"id": "WSTG-IDNT-03", "name": "Test Account Provisioning Process"},
            {"id": "WSTG-IDNT-04", "name": "Testing for Account Enumeration"},
            {"id": "WSTG-IDNT-05", "name": "Testing for Weak Username Policy"},
        ]
    },
    "ATHN": {
        "name": "Authentication Testing",
        "code": "WSTG-ATHN",
        "tests": [
            {"id": "WSTG-ATHN-01", "name": "Testing for Credentials Transported over Encrypted Channel"},
            {"id": "WSTG-ATHN-02", "name": "Testing for Default Credentials"},
            {"id": "WSTG-ATHN-03", "name": "Testing for Weak Lock Out Mechanism"},
            {"id": "WSTG-ATHN-04", "name": "Testing for Bypassing Authentication Schema"},
            {"id": "WSTG-ATHN-05", "name": "Testing for Vulnerable Remember Password"},
            {"id": "WSTG-ATHN-06", "name": "Testing for Browser Cache Weaknesses"},
            {"id": "WSTG-ATHN-07", "name": "Testing for Weak Password Policy"},
            {"id": "WSTG-ATHN-08", "name": "Testing for Weak Security Question Answer"},
            {"id": "WSTG-ATHN-09", "name": "Testing for Weak Password Change or Reset"},
            {"id": "WSTG-ATHN-10", "name": "Testing for Weaker Authentication in Alternative Channel"},
        ]
    },
    "ATHZ": {
        "name": "Authorization Testing",
        "code": "WSTG-ATHZ",
        "tests": [
            {"id": "WSTG-ATHZ-01", "name": "Testing Directory Traversal File Include"},
            {"id": "WSTG-ATHZ-02", "name": "Testing for Bypassing Authorization Schema"},
            {"id": "WSTG-ATHZ-03", "name": "Testing for Privilege Escalation"},
            {"id": "WSTG-ATHZ-04", "name": "Testing for Insecure Direct Object References"},
        ]
    },
    "SESS": {
        "name": "Session Management Testing",
        "code": "WSTG-SESS",
        "tests": [
            {"id": "WSTG-SESS-01", "name": "Testing for Session Management Schema"},
            {"id": "WSTG-SESS-02", "name": "Testing for Cookies Attributes"},
            {"id": "WSTG-SESS-03", "name": "Testing for Session Fixation"},
            {"id": "WSTG-SESS-04", "name": "Testing for Exposed Session Variables"},
            {"id": "WSTG-SESS-05", "name": "Testing for Cross Site Request Forgery"},
            {"id": "WSTG-SESS-06", "name": "Testing for Logout Functionality"},
            {"id": "WSTG-SESS-07", "name": "Testing Session Timeout"},
            {"id": "WSTG-SESS-08", "name": "Testing for Session Puzzling"},
            {"id": "WSTG-SESS-09", "name": "Testing for Session Hijacking"},
        ]
    },
    "INPV": {
        "name": "Input Validation Testing",
        "code": "WSTG-INPV",
        "tests": [
            {"id": "WSTG-INPV-01", "name": "Testing for Reflected Cross Site Scripting"},
            {"id": "WSTG-INPV-02", "name": "Testing for Stored Cross Site Scripting"},
            {"id": "WSTG-INPV-03", "name": "Testing for HTTP Verb Tampering"},
            {"id": "WSTG-INPV-04", "name": "Testing for HTTP Parameter Pollution"},
            {"id": "WSTG-INPV-05", "name": "Testing for SQL Injection"},
            {"id": "WSTG-INPV-06", "name": "Testing for LDAP Injection"},
            {"id": "WSTG-INPV-07", "name": "Testing for XML Injection"},
            {"id": "WSTG-INPV-08", "name": "Testing for SSI Injection"},
            {"id": "WSTG-INPV-09", "name": "Testing for XPath Injection"},
            {"id": "WSTG-INPV-10", "name": "Testing for IMAP SMTP Injection"},
            {"id": "WSTG-INPV-11", "name": "Testing for Code Injection"},
            {"id": "WSTG-INPV-12", "name": "Testing for Command Injection"},
            {"id": "WSTG-INPV-13", "name": "Testing for Format String Injection"},
            {"id": "WSTG-INPV-14", "name": "Testing for Incubated Vulnerability"},
            {"id": "WSTG-INPV-15", "name": "Testing for HTTP Splitting Smuggling"},
            {"id": "WSTG-INPV-16", "name": "Testing for HTTP Incoming Requests"},
            {"id": "WSTG-INPV-17", "name": "Testing for Host Header Injection"},
            {"id": "WSTG-INPV-18", "name": "Testing for Server-side Template Injection"},
            {"id": "WSTG-INPV-19", "name": "Testing for Server-Side Request Forgery"},
        ]
    },
    "ERRH": {
        "name": "Error Handling",
        "code": "WSTG-ERRH",
        "tests": [
            {"id": "WSTG-ERRH-01", "name": "Testing for Improper Error Handling"},
            {"id": "WSTG-ERRH-02", "name": "Testing for Stack Traces"},
        ]
    },
    "CRYP": {
        "name": "Cryptography",
        "code": "WSTG-CRYP",
        "tests": [
            {"id": "WSTG-CRYP-01", "name": "Testing for Weak Transport Layer Security"},
            {"id": "WSTG-CRYP-02", "name": "Testing for Padding Oracle"},
            {"id": "WSTG-CRYP-03", "name": "Testing for Sensitive Information Sent via Unencrypted Channels"},
            {"id": "WSTG-CRYP-04", "name": "Testing for Weak Encryption"},
        ]
    },
    "BUSL": {
        "name": "Business Logic Testing",
        "code": "WSTG-BUSL",
        "tests": [
            {"id": "WSTG-BUSL-01", "name": "Test Business Logic Data Validation"},
            {"id": "WSTG-BUSL-02", "name": "Test Ability to Forge Requests"},
            {"id": "WSTG-BUSL-03", "name": "Test Integrity Checks"},
            {"id": "WSTG-BUSL-04", "name": "Test for Process Timing"},
            {"id": "WSTG-BUSL-05", "name": "Test Number of Times a Function Can Be Used"},
            {"id": "WSTG-BUSL-06", "name": "Testing for the Circumvention of Work Flows"},
            {"id": "WSTG-BUSL-07", "name": "Test Defenses Against Application Misuse"},
            {"id": "WSTG-BUSL-08", "name": "Test Upload of Unexpected File Types"},
            {"id": "WSTG-BUSL-09", "name": "Test Upload of Malicious Files"},
        ]
    },
    "CLNT": {
        "name": "Client-side Testing",
        "code": "WSTG-CLNT",
        "tests": [
            {"id": "WSTG-CLNT-01", "name": "Testing for DOM-based Cross Site Scripting"},
            {"id": "WSTG-CLNT-02", "name": "Testing for JavaScript Execution"},
            {"id": "WSTG-CLNT-03", "name": "Testing for HTML Injection"},
            {"id": "WSTG-CLNT-04", "name": "Testing for Client-side URL Redirect"},
            {"id": "WSTG-CLNT-05", "name": "Testing for CSS Injection"},
            {"id": "WSTG-CLNT-06", "name": "Testing for Client-side Resource Manipulation"},
            {"id": "WSTG-CLNT-07", "name": "Testing Cross Origin Resource Sharing"},
            {"id": "WSTG-CLNT-08", "name": "Testing for Cross Site Flashing"},
            {"id": "WSTG-CLNT-09", "name": "Testing for Clickjacking"},
            {"id": "WSTG-CLNT-10", "name": "Testing WebSockets"},
            {"id": "WSTG-CLNT-11", "name": "Testing Web Messaging"},
            {"id": "WSTG-CLNT-12", "name": "Testing Browser Storage"},
            {"id": "WSTG-CLNT-13", "name": "Testing for Cross Site Script Inclusion"},
        ]
    },
    "APIT": {
        "name": "API Testing",
        "code": "WSTG-APIT",
        "tests": [
            {"id": "WSTG-APIT-01", "name": "Testing GraphQL"},
        ]
    }
}


# OWASP Top 10 2021
OWASP_TOP_10 = {
    "A01": {"name": "Broken Access Control", "severity": "critical"},
    "A02": {"name": "Cryptographic Failures", "severity": "critical"},
    "A03": {"name": "Injection", "severity": "critical"},
    "A04": {"name": "Insecure Design", "severity": "high"},
    "A05": {"name": "Security Misconfiguration", "severity": "high"},
    "A06": {"name": "Vulnerable and Outdated Components", "severity": "medium"},
    "A07": {"name": "Identification and Authentication Failures", "severity": "high"},
    "A08": {"name": "Software and Data Integrity Failures", "severity": "high"},
    "A09": {"name": "Security Logging and Monitoring Failures", "severity": "medium"},
    "A10": {"name": "Server-Side Request Forgery", "severity": "high"},
}


# Severity levels
SEVERITY_LEVELS = {
    "critical": {"score": 4, "color": "#dc2626", "persian": "بحرانی"},
    "high": {"score": 3, "color": "#ea580c", "persian": "بالا"},
    "medium": {"score": 2, "color": "#ca8a04", "persian": "متوسط"},
    "low": {"score": 1, "color": "#16a34a", "persian": "پایین"},
    "info": {"score": 0, "color": "#2563eb", "persian": "اطلاعاتی"},
}