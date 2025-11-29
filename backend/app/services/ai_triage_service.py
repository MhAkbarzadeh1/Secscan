"""
AI Triage Service - Uses AI for finding prioritization and Persian explanations.

Features:
- Prioritize findings based on context
- Generate Persian explanations for developers
- Suggest specific remediation steps
- Reduce false positives
"""
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.core.config import settings
from app.core.database import findings_collection

logger = logging.getLogger(__name__)


# Pre-defined Persian explanations for common vulnerabilities
PERSIAN_EXPLANATIONS = {
    "WSTG-INPV-05": {
        "title": "تزریق SQL",
        "description": """
تزریق SQL یک آسیب‌پذیری امنیتی است که به مهاجم اجازه می‌دهد کوئری‌های SQL مخرب را از طریق ورودی‌های برنامه اجرا کند.

**خطرات:**
- دسترسی غیرمجاز به پایگاه داده
- سرقت، تغییر یا حذف اطلاعات
- دور زدن احراز هویت
- در موارد شدید، کنترل کامل سرور

**راه‌حل:**
1. از Prepared Statements یا Parameterized Queries استفاده کنید
2. از ORM استفاده کنید
3. ورودی‌های کاربر را اعتبارسنجی و sanitize کنید
4. از اصل حداقل دسترسی (Least Privilege) پیروی کنید
""",
        "severity_justification": "این آسیب‌پذیری می‌تواند منجر به دسترسی کامل به پایگاه داده شود."
    },
    
    "WSTG-INPV-01": {
        "title": "XSS بازتابی (Reflected XSS)",
        "description": """
XSS بازتابی زمانی رخ می‌دهد که ورودی کاربر بدون رمزگذاری مناسب در صفحه وب نمایش داده شود.

**خطرات:**
- سرقت کوکی‌ها و session
- تغییر محتوای صفحه
- فیشینگ
- اجرای اقدامات به نمایندگی از کاربر

**راه‌حل:**
1. تمام خروجی‌ها را HTML encode کنید
2. از Content-Security-Policy استفاده کنید
3. کوکی‌ها را با فلگ HttpOnly تنظیم کنید
4. از کتابخانه‌های template امن استفاده کنید
""",
        "severity_justification": "XSS می‌تواند برای سرقت session و اجرای حملات فیشینگ استفاده شود."
    },
    
    "WSTG-INPV-02": {
        "title": "XSS ذخیره‌شده (Stored XSS)",
        "description": """
XSS ذخیره‌شده خطرناک‌تر از نوع بازتابی است چون payload در سرور ذخیره می‌شود و همه کاربران را تحت تأثیر قرار می‌دهد.

**خطرات:**
- همه موارد XSS بازتابی
- تأثیر گسترده روی تمام کاربران
- حملات worm-like

**راه‌حل:**
1. ورودی‌ها را هنگام ذخیره sanitize کنید
2. خروجی‌ها را هنگام نمایش encode کنید
3. از CSP سختگیرانه استفاده کنید
""",
        "severity_justification": "این نوع XSS تمام کاربران سیستم را در معرض خطر قرار می‌دهد."
    },
    
    "WSTG-CONF-07": {
        "title": "عدم وجود HSTS",
        "description": """
HTTP Strict Transport Security (HSTS) مرورگر را مجبور می‌کند همیشه از HTTPS استفاده کند.

**خطرات بدون HSTS:**
- حملات Man-in-the-Middle
- SSL Stripping
- Downgrade attacks

**راه‌حل:**
1. هدر HSTS را اضافه کنید:
   `Strict-Transport-Security: max-age=31536000; includeSubDomains`
2. سایت را به لیست HSTS preload اضافه کنید
""",
        "severity_justification": "بدون HSTS، کاربران در برابر حملات MITM آسیب‌پذیر هستند."
    },
    
    "WSTG-SESS-02": {
        "title": "کوکی ناامن",
        "description": """
کوکی‌های بدون فلگ‌های امنیتی مناسب می‌توانند توسط مهاجمان سرقت شوند.

**فلگ‌های ضروری:**
- **Secure**: کوکی فقط از طریق HTTPS ارسال شود
- **HttpOnly**: JavaScript نتواند به کوکی دسترسی داشته باشد
- **SameSite**: جلوگیری از CSRF

**راه‌حل:**
```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict
```
""",
        "severity_justification": "کوکی‌های ناامن می‌توانند منجر به سرقت session شوند."
    },
    
    "WSTG-INFO-02": {
        "title": "افشای اطلاعات سرور",
        "description": """
هدرهای HTTP اطلاعات نسخه سرور را افشا می‌کنند که می‌تواند به مهاجمان کمک کند.

**خطرات:**
- شناسایی نسخه‌های آسیب‌پذیر
- حملات هدفمند

**راه‌حل:**
1. هدر Server را حذف یا مبهم کنید
2. هدر X-Powered-By را حذف کنید
3. پیام‌های خطای تفصیلی را غیرفعال کنید
""",
        "severity_justification": "افشای اطلاعات می‌تواند حملات هدفمند را تسهیل کند."
    },
    
    "WSTG-CRYP-01": {
        "title": "رمزنگاری ضعیف یا عدم استفاده از HTTPS",
        "description": """
استفاده نکردن از HTTPS یا استفاده از تنظیمات ضعیف TLS خطرناک است.

**خطرات:**
- شنود ترافیک
- سرقت اطلاعات حساس
- تغییر محتوا توسط مهاجم

**راه‌حل:**
1. از HTTPS برای تمام صفحات استفاده کنید
2. از TLS 1.2 یا بالاتر استفاده کنید
3. از cipher suites قوی استفاده کنید
4. گواهی SSL معتبر داشته باشید
""",
        "severity_justification": "بدون رمزنگاری مناسب، تمام ارتباطات قابل شنود هستند."
    }
}


# Severity score factors
SEVERITY_FACTORS = {
    "data_exposure": 3.0,
    "authentication_bypass": 3.0,
    "remote_code_execution": 4.0,
    "denial_of_service": 2.0,
    "information_disclosure": 1.5,
    "configuration_issue": 1.0
}


class AITriageService:
    """Service for AI-powered finding triage and Persian explanations."""
    
    def __init__(self):
        self.ai_enabled = settings.AI_ENABLED
        self.api_key = settings.AI_API_KEY
    
    async def triage_findings(
        self,
        scan_id: str,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Triage findings using AI or rule-based logic.
        
        Returns findings with:
        - Priority score
        - Persian explanation
        - Confidence level
        - Related findings
        """
        triaged_findings = []
        
        for finding in findings:
            triaged = await self._triage_single_finding(finding)
            triaged_findings.append(triaged)
        
        # Sort by priority
        triaged_findings.sort(
            key=lambda x: (
                -x.get("priority_score", 0),
                SEVERITY_FACTORS.get(x.get("severity"), 0)
            )
        )
        
        return triaged_findings
    
    async def _triage_single_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Triage a single finding."""
        wstg_id = finding.get("wstg_id", "")
        
        # Get Persian explanation
        explanation = PERSIAN_EXPLANATIONS.get(wstg_id, {})
        
        if explanation:
            finding["description_fa"] = explanation.get("description", finding.get("description", ""))
            finding["title_fa"] = explanation.get("title", finding.get("title", ""))
            finding["severity_justification_fa"] = explanation.get("severity_justification", "")
        
        # Calculate priority score
        priority_score = self._calculate_priority_score(finding)
        finding["priority_score"] = priority_score
        
        # Confidence level (based on evidence quality)
        finding["confidence"] = self._assess_confidence(finding)
        
        return finding
    
    def _calculate_priority_score(self, finding: Dict[str, Any]) -> float:
        """Calculate priority score based on severity and context."""
        base_score = {
            "critical": 10.0,
            "high": 7.5,
            "medium": 5.0,
            "low": 2.5,
            "info": 1.0
        }.get(finding.get("severity", "info"), 1.0)
        
        # Adjust based on WSTG category
        wstg_id = finding.get("wstg_id", "")
        
        if "INPV" in wstg_id:  # Input validation - usually high priority
            base_score *= 1.2
        elif "ATHN" in wstg_id:  # Authentication - critical
            base_score *= 1.3
        elif "CRYP" in wstg_id:  # Crypto - important
            base_score *= 1.1
        
        # Adjust based on endpoint sensitivity
        endpoint = finding.get("endpoint", "")
        sensitive_paths = ["admin", "api", "auth", "login", "user", "account", "payment"]
        
        for path in sensitive_paths:
            if path in endpoint.lower():
                base_score *= 1.15
                break
        
        return min(base_score, 15.0)  # Cap at 15
    
    def _assess_confidence(self, finding: Dict[str, Any]) -> str:
        """Assess confidence level of finding."""
        evidence = finding.get("evidence", "")
        
        if not evidence:
            return "low"
        
        # Check evidence quality
        strong_indicators = [
            "error",
            "exception",
            "syntax",
            "stack trace",
            "reflected",
            "executed"
        ]
        
        evidence_lower = evidence.lower()
        matches = sum(1 for ind in strong_indicators if ind in evidence_lower)
        
        if matches >= 2:
            return "high"
        elif matches >= 1:
            return "medium"
        else:
            return "low"
    
    async def generate_persian_summary(
        self,
        findings: List[Dict[str, Any]]
    ) -> str:
        """Generate Persian summary of findings for developers."""
        if not findings:
            return "هیچ آسیب‌پذیری امنیتی یافت نشد. ✅"
        
        # Count by severity
        by_severity = {}
        for f in findings:
            sev = f.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        summary_parts = []
        
        summary_parts.append(f"**خلاصه اسکن امنیتی**\n")
        summary_parts.append(f"تعداد کل یافته‌ها: {len(findings)}\n")
        
        if by_severity.get("critical", 0) > 0:
            summary_parts.append(f"🔴 بحرانی: {by_severity['critical']}")
        if by_severity.get("high", 0) > 0:
            summary_parts.append(f"🟠 بالا: {by_severity['high']}")
        if by_severity.get("medium", 0) > 0:
            summary_parts.append(f"🟡 متوسط: {by_severity['medium']}")
        if by_severity.get("low", 0) > 0:
            summary_parts.append(f"🟢 پایین: {by_severity['low']}")
        if by_severity.get("info", 0) > 0:
            summary_parts.append(f"🔵 اطلاعاتی: {by_severity['info']}")
        
        # Add top priorities
        if findings:
            summary_parts.append("\n**اولویت‌های اصلی:**")
            for i, f in enumerate(findings[:3], 1):
                title = f.get("title_fa") or f.get("title", "")
                summary_parts.append(f"{i}. {title}")
        
        return "\n".join(summary_parts)
    
    async def get_remediation_steps(
        self,
        wstg_id: str,
        language: str = "fa"
    ) -> List[str]:
        """Get step-by-step remediation instructions."""
        
        remediation_steps = {
            "WSTG-INPV-05": {  # SQLi
                "fa": [
                    "۱. تمام کوئری‌های SQL را با Prepared Statements بازنویسی کنید",
                    "۲. از ORM مانند SQLAlchemy یا Prisma استفاده کنید",
                    "۳. ورودی‌ها را قبل از استفاده اعتبارسنجی کنید",
                    "۴. از اصل حداقل دسترسی برای کاربر دیتابیس استفاده کنید",
                    "۵. WAF را برای شناسایی حملات SQLi پیکربندی کنید"
                ],
                "en": [
                    "1. Rewrite all SQL queries using Prepared Statements",
                    "2. Use an ORM like SQLAlchemy or Prisma",
                    "3. Validate all inputs before use",
                    "4. Apply least privilege principle for DB user",
                    "5. Configure WAF to detect SQLi attacks"
                ]
            },
            "WSTG-INPV-01": {  # XSS
                "fa": [
                    "۱. تمام خروجی‌ها را HTML encode کنید",
                    "۲. از template engine با auto-escaping استفاده کنید",
                    "۳. Content-Security-Policy را پیکربندی کنید",
                    "۴. کوکی‌ها را با HttpOnly تنظیم کنید",
                    "۵. از کتابخانه‌های sanitization مانند DOMPurify استفاده کنید"
                ],
                "en": [
                    "1. HTML encode all outputs",
                    "2. Use template engine with auto-escaping",
                    "3. Configure Content-Security-Policy",
                    "4. Set cookies with HttpOnly flag",
                    "5. Use sanitization libraries like DOMPurify"
                ]
            }
        }
        
        steps = remediation_steps.get(wstg_id, {}).get(language, [])
        
        if not steps:
            if language == "fa":
                return ["لطفاً به مستندات OWASP مراجعه کنید برای راهنمای رفع این آسیب‌پذیری"]
            else:
                return ["Please refer to OWASP documentation for remediation guidance"]
        
        return steps