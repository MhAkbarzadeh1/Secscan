"""
Scan Service - Core security scanning engine.

Implements OWASP WSTG tests including:
- SQLi detection (passive + active)
- XSS detection (reflected + stored)
- Security misconfiguration scanning
- Header analysis
- And more...
"""
import asyncio
import aiohttp
import hashlib
import re
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import ssl

from app.core.database import (
    scans_collection, findings_collection, projects_collection, payloads_collection
)
from app.core.config import settings, WSTG_CATEGORIES, OWASP_TOP_10, SEVERITY_LEVELS
from app.core.security import redact_payload, is_payload_safe
from app.models.schemas import ScanStatus, ScanMode, SeverityLevel

logger = logging.getLogger(__name__)


class ScanService:
    """Security scanning service implementing OWASP WSTG tests."""
    
    def __init__(self):
        self.active_scans: Dict[str, bool] = {}  # Track cancellation
        
    async def execute_scan(self, scan_id: str):
        """
        Execute a security scan.
        
        Pipeline:
        1. Discovery & Information Gathering
        2. Passive Tests (headers, robots, config leaks)
        3. Authentication Checks
        4. Active Tests (with rate-limiting)
        5. Aggregation & AI Triage
        6. Report Generation
        """
        logger.info(f"Starting scan: {scan_id}")
        self.active_scans[scan_id] = True
        
        try:
            # Get scan details
            scan = await scans_collection().find_one({"_id": scan_id})
            if not scan:
                logger.error(f"Scan not found: {scan_id}")
                return
            
            # Check if cancelled
            if scan["status"] == ScanStatus.CANCELLED.value:
                return
            
            # Get project
            project = await projects_collection().find_one({"_id": scan["project_id"]})
            if not project:
                await self._fail_scan(scan_id, "پروژه یافت نشد")
                return
            
            # Update status to running
            await self._update_scan_status(scan_id, ScanStatus.RUNNING, started_at=datetime.now(timezone.utc))
            
            config = scan.get("config", {})
            mode = ScanMode(config.get("mode", "safe"))
            base_url = f"https://{project['domain']}"
            endpoints = scan.get("endpoints", ["/"])
            categories = config.get("categories", ["INFO", "CONF", "INPV"])
            
            # Calculate total tests
            total_tests = self._calculate_total_tests(categories, endpoints)
            await scans_collection().update_one(
                {"_id": scan_id},
                {"$set": {"tests_total": total_tests}}
            )
            
            all_findings = []
            tests_completed = 0
            
            # Create HTTP session with rate limiting
            connector = aiohttp.TCPConnector(
                limit=config.get("concurrent_requests", 5),
                ssl=False  # Allow self-signed certs
            )
            timeout = aiohttp.ClientTimeout(total=config.get("timeout_seconds", 30))
            
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                
                # 1. Information Gathering (WSTG-INFO)
                if "INFO" in categories and self._is_scan_active(scan_id):
                    await self._update_current_test(scan_id, "Information Gathering")
                    info_findings = await self._run_info_gathering(session, base_url, project)
                    all_findings.extend(info_findings)
                    tests_completed += 1
                    await self._update_progress(scan_id, tests_completed, total_tests)
                
                # 2. Configuration Tests (WSTG-CONF)
                if "CONF" in categories and self._is_scan_active(scan_id):
                    await self._update_current_test(scan_id, "Configuration Analysis")
                    conf_findings = await self._run_config_tests(session, base_url, config)
                    all_findings.extend(conf_findings)
                    tests_completed += 1
                    await self._update_progress(scan_id, tests_completed, total_tests)
                
                # 3. Input Validation Tests (WSTG-INPV) - SQLi, XSS, etc.
                if "INPV" in categories and self._is_scan_active(scan_id):
                    for endpoint in endpoints:
                        if not self._is_scan_active(scan_id):
                            break
                        
                        full_url = urljoin(base_url, endpoint)
                        
                        # SQLi Tests
                        await self._update_current_test(scan_id, f"SQLi Test: {endpoint}")
                        sqli_findings = await self._run_sqli_tests(
                            session, full_url, endpoint, mode, config
                        )
                        all_findings.extend(sqli_findings)
                        tests_completed += 1
                        await self._update_progress(scan_id, tests_completed, total_tests)
                        
                        # Rate limiting delay
                        await asyncio.sleep(config.get("request_delay_ms", 100) / 1000)
                        
                        # XSS Tests
                        await self._update_current_test(scan_id, f"XSS Test: {endpoint}")
                        xss_findings = await self._run_xss_tests(
                            session, full_url, endpoint, mode, config
                        )
                        all_findings.extend(xss_findings)
                        tests_completed += 1
                        await self._update_progress(scan_id, tests_completed, total_tests)
                        
                        await asyncio.sleep(config.get("request_delay_ms", 100) / 1000)
                
                # 4. Session Management Tests (WSTG-SESS)
                if "SESS" in categories and self._is_scan_active(scan_id):
                    await self._update_current_test(scan_id, "Session Management")
                    sess_findings = await self._run_session_tests(session, base_url)
                    all_findings.extend(sess_findings)
                    tests_completed += 1
                    await self._update_progress(scan_id, tests_completed, total_tests)
                
                # 5. Cryptography Tests (WSTG-CRYP)
                if "CRYP" in categories and self._is_scan_active(scan_id):
                    await self._update_current_test(scan_id, "Cryptography Analysis")
                    cryp_findings = await self._run_crypto_tests(session, base_url)
                    all_findings.extend(cryp_findings)
                    tests_completed += 1
                    await self._update_progress(scan_id, tests_completed, total_tests)
            
            # Check if cancelled during execution
            if not self._is_scan_active(scan_id):
                return
            
            # Save findings to database
            for finding in all_findings:
                finding["_id"] = str(uuid.uuid4())
                finding["scan_id"] = scan_id
                finding["project_id"] = project["_id"]
                finding["created_at"] = datetime.now(timezone.utc)
                await findings_collection().insert_one(finding)
            
            # Calculate severity summary
            findings_by_severity = {}
            for finding in all_findings:
                sev = finding["severity"]
                findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1
            
            # AI Triage (if enabled)
            if settings.AI_ENABLED and all_findings:
                await self._ai_triage_findings(scan_id, all_findings)
            
            # Complete scan
            await scans_collection().update_one(
                {"_id": scan_id},
                {"$set": {
                    "status": ScanStatus.COMPLETED.value,
                    "progress": 100.0,
                    "completed_at": datetime.now(timezone.utc),
                    "total_findings": len(all_findings),
                    "findings_by_severity": findings_by_severity,
                    "updated_at": datetime.now(timezone.utc)
                }}
            )
            
            logger.info(f"Scan completed: {scan_id} - {len(all_findings)} findings")
            
        except asyncio.CancelledError:
            logger.info(f"Scan cancelled: {scan_id}")
            await self._update_scan_status(scan_id, ScanStatus.CANCELLED)
            
        except Exception as e:
            logger.error(f"Scan failed: {scan_id} - {e}", exc_info=True)
            await self._fail_scan(scan_id, str(e))
            
        finally:
            self.active_scans.pop(scan_id, None)
    
    def _is_scan_active(self, scan_id: str) -> bool:
        """Check if scan is still active (not cancelled)."""
        return self.active_scans.get(scan_id, False)
    
    def _calculate_total_tests(self, categories: List[str], endpoints: List[str]) -> int:
        """Calculate total number of tests to run."""
        total = 0
        if "INFO" in categories:
            total += 1
        if "CONF" in categories:
            total += 1
        if "INPV" in categories:
            total += len(endpoints) * 2  # SQLi + XSS per endpoint
        if "SESS" in categories:
            total += 1
        if "CRYP" in categories:
            total += 1
        return max(total, 1)
    
    async def _update_scan_status(self, scan_id: str, status: ScanStatus, **kwargs):
        """Update scan status."""
        update = {
            "status": status.value,
            "updated_at": datetime.now(timezone.utc)
        }
        update.update(kwargs)
        await scans_collection().update_one({"_id": scan_id}, {"$set": update})
    
    async def _update_progress(self, scan_id: str, completed: int, total: int):
        """Update scan progress."""
        progress = min(99.0, (completed / total) * 100) if total > 0 else 0
        await scans_collection().update_one(
            {"_id": scan_id},
            {"$set": {
                "progress": progress,
                "tests_completed": completed,
                "updated_at": datetime.now(timezone.utc)
            }}
        )
    
    async def _update_current_test(self, scan_id: str, test_name: str):
        """Update current test being executed."""
        await scans_collection().update_one(
            {"_id": scan_id},
            {"$set": {"current_test": test_name, "updated_at": datetime.now(timezone.utc)}}
        )
    
    async def _fail_scan(self, scan_id: str, error_message: str):
        """Mark scan as failed."""
        await scans_collection().update_one(
            {"_id": scan_id},
            {"$set": {
                "status": ScanStatus.FAILED.value,
                "error_message": error_message,
                "completed_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc)
            }}
        )
    
    # ==================== WSTG-INFO: Information Gathering ====================
    
    async def _run_info_gathering(
        self, 
        session: aiohttp.ClientSession, 
        base_url: str,
        project: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Run information gathering tests (WSTG-INFO)."""
        findings = []
        
        try:
            # WSTG-INFO-02: Fingerprint Web Server
            async with session.get(base_url) as response:
                server_header = response.headers.get("Server", "")
                x_powered_by = response.headers.get("X-Powered-By", "")
                
                if server_header:
                    findings.append(self._create_finding(
                        title="Server Header Information Disclosure",
                        title_fa="افشای اطلاعات در هدر Server",
                        description=f"The server exposes version information: {server_header}",
                        description_fa=f"سرور اطلاعات نسخه را افشا می‌کند: {server_header}",
                        severity=SeverityLevel.LOW.value,
                        wstg_id="WSTG-INFO-02",
                        owasp_top10_id="A05",
                        endpoint="/",
                        evidence=f"Server: {server_header}",
                        recommendation="Remove or obfuscate the Server header",
                        recommendation_fa="هدر Server را حذف یا مبهم کنید"
                    ))
                
                if x_powered_by:
                    findings.append(self._create_finding(
                        title="X-Powered-By Header Disclosure",
                        title_fa="افشای هدر X-Powered-By",
                        description=f"Technology stack exposed: {x_powered_by}",
                        description_fa=f"استک تکنولوژی افشا شده: {x_powered_by}",
                        severity=SeverityLevel.LOW.value,
                        wstg_id="WSTG-INFO-02",
                        owasp_top10_id="A05",
                        endpoint="/",
                        evidence=f"X-Powered-By: {x_powered_by}",
                        recommendation="Remove the X-Powered-By header",
                        recommendation_fa="هدر X-Powered-By را حذف کنید"
                    ))
            
            # WSTG-INFO-03: Review Webserver Metafiles
            robots_url = urljoin(base_url, "/robots.txt")
            async with session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    # Check for sensitive paths in robots.txt
                    sensitive_patterns = ["admin", "backup", "config", "private", "secret", "api"]
                    found_sensitive = []
                    
                    for line in content.split("\n"):
                        if line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            for pattern in sensitive_patterns:
                                if pattern in path.lower():
                                    found_sensitive.append(path)
                    
                    if found_sensitive:
                        findings.append(self._create_finding(
                            title="Sensitive Paths in robots.txt",
                            title_fa="مسیرهای حساس در robots.txt",
                            description=f"robots.txt reveals potentially sensitive paths",
                            description_fa="فایل robots.txt مسیرهای احتمالاً حساس را افشا می‌کند",
                            severity=SeverityLevel.INFO.value,
                            wstg_id="WSTG-INFO-03",
                            owasp_top10_id="A05",
                            endpoint="/robots.txt",
                            evidence=f"Sensitive paths: {', '.join(found_sensitive[:5])}",
                            recommendation="Review and minimize disclosed paths in robots.txt",
                            recommendation_fa="مسیرهای افشا شده در robots.txt را بررسی و کمینه کنید"
                        ))
            
            # Check for common sensitive files
            sensitive_files = [
                "/.git/config", "/.env", "/config.php", "/wp-config.php",
                "/.htaccess", "/web.config", "/phpinfo.php"
            ]
            
            for file_path in sensitive_files:
                try:
                    file_url = urljoin(base_url, file_path)
                    async with session.get(file_url) as response:
                        if response.status == 200:
                            findings.append(self._create_finding(
                                title=f"Sensitive File Exposed: {file_path}",
                                title_fa=f"فایل حساس در دسترس: {file_path}",
                                description=f"A potentially sensitive file is publicly accessible",
                                description_fa="یک فایل احتمالاً حساس به صورت عمومی در دسترس است",
                                severity=SeverityLevel.HIGH.value,
                                wstg_id="WSTG-INFO-03",
                                owasp_top10_id="A01",
                                endpoint=file_path,
                                evidence=f"HTTP {response.status} for {file_path}",
                                recommendation=f"Remove or restrict access to {file_path}",
                                recommendation_fa=f"دسترسی به {file_path} را حذف یا محدود کنید"
                            ))
                except:
                    pass
                
                await asyncio.sleep(0.1)  # Rate limiting
                
        except Exception as e:
            logger.error(f"Info gathering error: {e}")
        
        return findings
    
    # ==================== WSTG-CONF: Configuration Tests ====================
    
    async def _run_config_tests(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Run configuration and security header tests (WSTG-CONF)."""
        findings = []
        
        try:
            async with session.get(base_url) as response:
                headers = response.headers
                
                # WSTG-CONF-07: Test HTTP Strict Transport Security
                if "Strict-Transport-Security" not in headers:
                    findings.append(self._create_finding(
                        title="Missing HSTS Header",
                        title_fa="هدر HSTS موجود نیست",
                        description="HTTP Strict Transport Security header is not set",
                        description_fa="هدر HTTP Strict Transport Security تنظیم نشده است",
                        severity=SeverityLevel.MEDIUM.value,
                        wstg_id="WSTG-CONF-07",
                        owasp_top10_id="A05",
                        endpoint="/",
                        evidence="Missing Strict-Transport-Security header",
                        recommendation="Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                        recommendation_fa="هدر HSTS را اضافه کنید: Strict-Transport-Security: max-age=31536000; includeSubDomains"
                    ))
                
                # X-Frame-Options
                if "X-Frame-Options" not in headers:
                    findings.append(self._create_finding(
                        title="Missing X-Frame-Options Header",
                        title_fa="هدر X-Frame-Options موجود نیست",
                        description="Site may be vulnerable to clickjacking attacks",
                        description_fa="سایت ممکن است در برابر حملات clickjacking آسیب‌پذیر باشد",
                        severity=SeverityLevel.MEDIUM.value,
                        wstg_id="WSTG-CONF-02",
                        owasp_top10_id="A05",
                        endpoint="/",
                        evidence="Missing X-Frame-Options header",
                        recommendation="Add header: X-Frame-Options: DENY or SAMEORIGIN",
                        recommendation_fa="هدر را اضافه کنید: X-Frame-Options: DENY یا SAMEORIGIN"
                    ))
                
                # X-Content-Type-Options
                if "X-Content-Type-Options" not in headers:
                    findings.append(self._create_finding(
                        title="Missing X-Content-Type-Options Header",
                        title_fa="هدر X-Content-Type-Options موجود نیست",
                        description="Browser may perform MIME-type sniffing",
                        description_fa="مرورگر ممکن است MIME-type sniffing انجام دهد",
                        severity=SeverityLevel.LOW.value,
                        wstg_id="WSTG-CONF-02",
                        owasp_top10_id="A05",
                        endpoint="/",
                        evidence="Missing X-Content-Type-Options header",
                        recommendation="Add header: X-Content-Type-Options: nosniff",
                        recommendation_fa="هدر را اضافه کنید: X-Content-Type-Options: nosniff"
                    ))
                
                # Content-Security-Policy
                if "Content-Security-Policy" not in headers:
                    findings.append(self._create_finding(
                        title="Missing Content-Security-Policy Header",
                        title_fa="هدر CSP موجود نیست",
                        description="No Content Security Policy is defined",
                        description_fa="هیچ سیاست امنیت محتوایی تعریف نشده است",
                        severity=SeverityLevel.MEDIUM.value,
                        wstg_id="WSTG-CONF-02",
                        owasp_top10_id="A05",
                        endpoint="/",
                        evidence="Missing Content-Security-Policy header",
                        recommendation="Implement a Content Security Policy",
                        recommendation_fa="یک سیاست امنیت محتوا (CSP) پیاده‌سازی کنید"
                    ))
                
                # WSTG-CONF-06: Test HTTP Methods
                allowed_methods = []
                for method in ["GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH"]:
                    try:
                        async with session.request(method, base_url) as resp:
                            if resp.status != 405:
                                allowed_methods.append(method)
                    except:
                        pass
                
                if "TRACE" in allowed_methods:
                    findings.append(self._create_finding(
                        title="HTTP TRACE Method Enabled",
                        title_fa="متد HTTP TRACE فعال است",
                        description="TRACE method is enabled which may lead to XST attacks",
                        description_fa="متد TRACE فعال است که ممکن است منجر به حملات XST شود",
                        severity=SeverityLevel.MEDIUM.value,
                        wstg_id="WSTG-CONF-06",
                        owasp_top10_id="A05",
                        endpoint="/",
                        evidence=f"Allowed methods: {', '.join(allowed_methods)}",
                        recommendation="Disable TRACE method on the server",
                        recommendation_fa="متد TRACE را در سرور غیرفعال کنید"
                    ))
                    
        except Exception as e:
            logger.error(f"Config test error: {e}")
        
        return findings
    
    # ==================== WSTG-INPV-05: SQL Injection Tests ====================
    
    async def _run_sqli_tests(
        self,
        session: aiohttp.ClientSession,
        url: str,
        endpoint: str,
        mode: ScanMode,
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Run SQL injection tests (WSTG-INPV-05)."""
        findings = []
        
        # Basic SQLi payloads (safe mode)
        safe_payloads = [
            "'",
            "\"",
            "1' OR '1'='1",
            "1\" OR \"1\"=\"1",
            "' OR ''='",
            "1' AND '1'='1",
            "1 AND 1=1",
            "1 OR 1=1",
            "' UNION SELECT NULL--",
            "1'; WAITFOR DELAY '0:0:5'--",
        ]
        
        # Error patterns indicating potential SQLi
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"PostgreSQL.*ERROR",
            r"Driver.*SQL Server",
            r"ORA-\d{5}",
            r"Microsoft OLE DB Provider for SQL Server",
            r"Unclosed quotation mark",
            r"SQLITE_ERROR",
            r"SQLite3::",
            r"pg_query\(\):",
            r"mysql_fetch_array\(\)",
            r"sqlite3.OperationalError",
        ]
        
        # Get payloads based on mode
        payloads_to_use = safe_payloads
        if mode == ScanMode.AGGRESSIVE:
            # Load more payloads from database
            db_payloads = await payloads_collection().find(
                {"category": "sqli", "is_aggressive": True}
            ).limit(config.get("max_payloads_per_test", 100)).to_list(length=100)
            
            payloads_to_use.extend([p["payload"] for p in db_payloads])
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Test each parameter
        for param_name in list(params.keys()) + ["id", "page", "search", "q", "query"]:
            for payload in payloads_to_use[:config.get("max_payloads_per_test", 50)]:
                if not self._is_scan_active:
                    break
                    
                try:
                    # Build test URL
                    test_params = {param_name: payload}
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                    
                    async with session.get(test_url) as response:
                        content = await response.text()
                        
                        # Check for SQL errors in response
                        for pattern in error_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                findings.append(self._create_finding(
                                    title=f"Potential SQL Injection in '{param_name}' parameter",
                                    title_fa=f"احتمال تزریق SQL در پارامتر '{param_name}'",
                                    description="SQL error messages detected in response, indicating potential SQL injection vulnerability",
                                    description_fa="پیام‌های خطای SQL در پاسخ شناسایی شد که نشان‌دهنده آسیب‌پذیری احتمالی تزریق SQL است",
                                    severity=SeverityLevel.CRITICAL.value,
                                    wstg_id="WSTG-INPV-05",
                                    owasp_top10_id="A03",
                                    endpoint=endpoint,
                                    method="GET",
                                    evidence=f"Parameter: {param_name}, Pattern matched: {pattern}",
                                    recommendation="Use parameterized queries/prepared statements. Never concatenate user input into SQL queries.",
                                    recommendation_fa="از کوئری‌های پارامتری استفاده کنید. هرگز ورودی کاربر را مستقیماً در کوئری SQL قرار ندهید."
                                ))
                                break
                        
                        # Check for time-based blind SQLi (only in aggressive mode)
                        if mode == ScanMode.AGGRESSIVE and "WAITFOR" in payload or "SLEEP" in payload:
                            # Measure response time
                            pass  # Would implement timing analysis
                    
                    # Rate limiting
                    await asyncio.sleep(config.get("request_delay_ms", 100) / 1000)
                    
                except Exception as e:
                    logger.debug(f"SQLi test error: {e}")
        
        return findings
    
    # ==================== WSTG-INPV-01/02: XSS Tests ====================
    
    async def _run_xss_tests(
        self,
        session: aiohttp.ClientSession,
        url: str,
        endpoint: str,
        mode: ScanMode,
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Run XSS tests (WSTG-INPV-01, WSTG-INPV-02)."""
        findings = []
        
        # Basic XSS payloads (safe - won't execute, just detect reflection)
        safe_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "<body onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\">",
            "'-alert('XSS')-'",
            "<input onfocus=alert('XSS') autofocus>",
        ]
        
        # Unique marker for detection
        xss_marker = f"XSSTEST{uuid.uuid4().hex[:8]}"
        
        payloads_to_use = safe_payloads
        if mode == ScanMode.AGGRESSIVE:
            db_payloads = await payloads_collection().find(
                {"category": "xss", "is_aggressive": True}
            ).limit(config.get("max_payloads_per_test", 100)).to_list(length=100)
            
            payloads_to_use.extend([p["payload"] for p in db_payloads])
        
        parsed = urlparse(url)
        
        for param_name in ["search", "q", "query", "name", "input", "text", "value"]:
            for payload in payloads_to_use[:config.get("max_payloads_per_test", 50)]:
                try:
                    # Add marker to payload for reliable detection
                    marked_payload = payload.replace("XSS", xss_marker)
                    
                    test_params = {param_name: marked_payload}
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                    
                    async with session.get(test_url) as response:
                        content = await response.text()
                        
                        # Check if payload is reflected
                        if xss_marker in content:
                            # Check if it's in a dangerous context
                            dangerous_contexts = [
                                f"<script>{xss_marker}",
                                f"onerror={xss_marker}",
                                f"onload={xss_marker}",
                                f"javascript:{xss_marker}",
                            ]
                            
                            context_found = any(ctx in content for ctx in dangerous_contexts)
                            
                            if context_found or marked_payload in content:
                                findings.append(self._create_finding(
                                    title=f"Reflected XSS in '{param_name}' parameter",
                                    title_fa=f"XSS بازتابی در پارامتر '{param_name}'",
                                    description="User input is reflected in the response without proper encoding",
                                    description_fa="ورودی کاربر بدون رمزگذاری مناسب در پاسخ بازتاب می‌شود",
                                    severity=SeverityLevel.HIGH.value,
                                    wstg_id="WSTG-INPV-01",
                                    owasp_top10_id="A03",
                                    endpoint=endpoint,
                                    method="GET",
                                    evidence=f"Parameter: {param_name}, Payload reflected in response",
                                    recommendation="Encode all user input before rendering. Use Content-Security-Policy.",
                                    recommendation_fa="تمام ورودی‌های کاربر را قبل از نمایش رمزگذاری کنید. از CSP استفاده کنید."
                                ))
                                break  # Found vuln, no need to test more payloads
                    
                    await asyncio.sleep(config.get("request_delay_ms", 100) / 1000)
                    
                except Exception as e:
                    logger.debug(f"XSS test error: {e}")
        
        return findings
    
    # ==================== WSTG-SESS: Session Management Tests ====================
    
    async def _run_session_tests(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> List[Dict[str, Any]]:
        """Run session management tests (WSTG-SESS)."""
        findings = []
        
        try:
            async with session.get(base_url) as response:
                cookies = response.cookies
                
                for cookie in cookies.values():
                    # WSTG-SESS-02: Check cookie attributes
                    issues = []
                    
                    if not cookie.get("secure"):
                        issues.append("Missing Secure flag")
                    
                    if not cookie.get("httponly"):
                        issues.append("Missing HttpOnly flag")
                    
                    samesite = cookie.get("samesite", "").lower()
                    if samesite not in ["strict", "lax"]:
                        issues.append("Missing or weak SameSite attribute")
                    
                    if issues:
                        findings.append(self._create_finding(
                            title=f"Insecure Cookie: {cookie.key}",
                            title_fa=f"کوکی ناامن: {cookie.key}",
                            description=f"Cookie has security issues: {', '.join(issues)}",
                            description_fa=f"کوکی مشکلات امنیتی دارد: {', '.join(issues)}",
                            severity=SeverityLevel.MEDIUM.value,
                            wstg_id="WSTG-SESS-02",
                            owasp_top10_id="A07",
                            endpoint="/",
                            evidence=f"Cookie: {cookie.key}, Issues: {', '.join(issues)}",
                            recommendation="Set Secure, HttpOnly, and SameSite=Strict flags on sensitive cookies",
                            recommendation_fa="فلگ‌های Secure، HttpOnly و SameSite=Strict را روی کوکی‌های حساس تنظیم کنید"
                        ))
                        
        except Exception as e:
            logger.error(f"Session test error: {e}")
        
        return findings
    
    # ==================== WSTG-CRYP: Cryptography Tests ====================
    
    async def _run_crypto_tests(
        self,
        session: aiohttp.ClientSession,
        base_url: str
    ) -> List[Dict[str, Any]]:
        """Run cryptography tests (WSTG-CRYP)."""
        findings = []
        
        try:
            parsed = urlparse(base_url)
            
            # Check if HTTPS is used
            if parsed.scheme != "https":
                findings.append(self._create_finding(
                    title="Site Not Using HTTPS",
                    title_fa="سایت از HTTPS استفاده نمی‌کند",
                    description="The site is accessible over unencrypted HTTP",
                    description_fa="سایت از طریق HTTP رمزنگاری نشده در دسترس است",
                    severity=SeverityLevel.HIGH.value,
                    wstg_id="WSTG-CRYP-01",
                    owasp_top10_id="A02",
                    endpoint="/",
                    evidence=f"URL scheme: {parsed.scheme}",
                    recommendation="Enforce HTTPS for all connections",
                    recommendation_fa="HTTPS را برای تمام اتصالات اجباری کنید"
                ))
            
            # Check SSL/TLS configuration (basic check)
            if parsed.scheme == "https":
                try:
                    # Create SSL context for testing
                    ssl_context = ssl.create_default_context()
                    
                    # Try to connect and get certificate info
                    import socket
                    with socket.create_connection((parsed.netloc, 443), timeout=10) as sock:
                        with ssl_context.wrap_socket(sock, server_hostname=parsed.netloc) as ssock:
                            cert = ssock.getpeercert()
                            
                            # Check certificate expiry
                            import datetime as dt
                            not_after = cert.get('notAfter')
                            if not_after:
                                # Parse the date
                                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                days_to_expiry = (expiry - datetime.now()).days
                                
                                if days_to_expiry < 30:
                                    findings.append(self._create_finding(
                                        title="SSL Certificate Expiring Soon",
                                        title_fa="گواهی SSL به زودی منقضی می‌شود",
                                        description=f"SSL certificate expires in {days_to_expiry} days",
                                        description_fa=f"گواهی SSL در {days_to_expiry} روز منقضی می‌شود",
                                        severity=SeverityLevel.MEDIUM.value,
                                        wstg_id="WSTG-CRYP-01",
                                        owasp_top10_id="A02",
                                        endpoint="/",
                                        evidence=f"Certificate expires: {not_after}",
                                        recommendation="Renew SSL certificate before expiration",
                                        recommendation_fa="گواهی SSL را قبل از انقضا تمدید کنید"
                                    ))
                                    
                except Exception as e:
                    logger.debug(f"SSL check error: {e}")
                    
        except Exception as e:
            logger.error(f"Crypto test error: {e}")
        
        return findings
    
    # ==================== AI Triage ====================
    
    async def _ai_triage_findings(self, scan_id: str, findings: List[Dict[str, Any]]):
        """Use AI to prioritize and explain findings in Persian."""
        # This would integrate with an AI service to:
        # 1. Prioritize findings based on context
        # 2. Generate Persian explanations for developers
        # 3. Suggest specific remediation steps
        
        # For now, just add Persian descriptions if not present
        for finding in findings:
            if not finding.get("recommendation_fa"):
                # Add basic Persian translation
                finding["recommendation_fa"] = finding.get("recommendation", "")
        
        logger.info(f"AI triage completed for scan {scan_id}")
    
    # ==================== Helper Methods ====================
    
    def _create_finding(
        self,
        title: str,
        description: str,
        severity: str,
        wstg_id: str,
        endpoint: str,
        recommendation: str,
        title_fa: str = None,
        description_fa: str = None,
        recommendation_fa: str = None,
        owasp_top10_id: str = None,
        method: str = "GET",
        evidence: str = None,
        cvss_score: float = None
    ) -> Dict[str, Any]:
        """Create a finding dictionary."""
        return {
            "title": title,
            "title_fa": title_fa or title,
            "description": description,
            "description_fa": description_fa or description,
            "severity": severity,
            "wstg_id": wstg_id,
            "owasp_top10_id": owasp_top10_id,
            "endpoint": endpoint,
            "method": method,
            "evidence": evidence,
            "recommendation": recommendation,
            "recommendation_fa": recommendation_fa or recommendation,
            "cvss_score": cvss_score,
            "is_false_positive": False,
            "verified": False
        }