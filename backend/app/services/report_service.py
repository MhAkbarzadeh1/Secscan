"""
Report Service - Generates security scan reports in PDF/HTML/JSON formats.

Supports:
- Persian and English languages
- OWASP compliance mapping
- Severity-based organization
- Executive summary
- Detailed findings
- Remediation recommendations
"""
import os
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from jinja2 import Environment, FileSystemLoader
import aiofiles

from app.core.database import (
    scans_collection, findings_collection, projects_collection, reports_collection
)
from app.core.config import settings, WSTG_CATEGORIES, OWASP_TOP_10, SEVERITY_LEVELS
from app.models.schemas import ReportFormat, SeverityLevel

logger = logging.getLogger(__name__)


class ReportService:
    """Service for generating security scan reports."""
    
    def __init__(self):
        self.reports_dir = settings.REPORTS_DIR
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Setup Jinja2 templates
        templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
        os.makedirs(templates_dir, exist_ok=True)
        
        self.jinja_env = Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=True
        )
        
        # Create default templates
        self._create_default_templates()
    
    def _create_default_templates(self):
        """Create default report templates if they don't exist."""
        templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
        
        # HTML Report Template
        html_template = '''<!DOCTYPE html>
<html lang="{{ language }}" dir="{{ 'rtl' if language == 'fa' else 'ltr' }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: {{ 'Vazirmatn, Tahoma' if language == 'fa' else 'Arial, sans-serif' }};
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            direction: {{ 'rtl' if language == 'fa' else 'ltr' }};
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header {
            background: linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .meta { opacity: 0.9; font-size: 0.95em; }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        .card.critical { border-top: 4px solid #dc2626; }
        .card.high { border-top: 4px solid #ea580c; }
        .card.medium { border-top: 4px solid #ca8a04; }
        .card.low { border-top: 4px solid #16a34a; }
        .card.info { border-top: 4px solid #2563eb; }
        .card .count { font-size: 3em; font-weight: bold; }
        .card .label { color: #666; margin-top: 5px; }
        .section {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .section h2 {
            color: #1e3a5f;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #eee;
        }
        .finding {
            border: 1px solid #eee;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .finding-title { font-size: 1.2em; font-weight: bold; }
        .severity-badge {
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-size: 0.85em;
            font-weight: bold;
        }
        .severity-critical { background: #dc2626; }
        .severity-high { background: #ea580c; }
        .severity-medium { background: #ca8a04; }
        .severity-low { background: #16a34a; }
        .severity-info { background: #2563eb; }
        .finding-meta {
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
            font-size: 0.9em;
            color: #666;
        }
        .finding-description { margin-bottom: 15px; }
        .finding-evidence {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            font-size: 0.9em;
            margin-bottom: 15px;
            overflow-x: auto;
        }
        .finding-recommendation {
            background: #e8f5e9;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #4caf50;
        }
        .footer {
            text-align: center;
            color: #666;
            padding: 20px;
            font-size: 0.9em;
        }
        @media print {
            body { background: white; }
            .section { box-shadow: none; border: 1px solid #ddd; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ title }}</h1>
            <div class="meta">
                <p><strong>{{ 'دامنه' if language == 'fa' else 'Domain' }}:</strong> {{ domain }}</p>
                <p><strong>{{ 'تاریخ اسکن' if language == 'fa' else 'Scan Date' }}:</strong> {{ scan_date }}</p>
                <p><strong>{{ 'تاریخ گزارش' if language == 'fa' else 'Report Date' }}:</strong> {{ report_date }}</p>
            </div>
        </div>
        
        <div class="summary-cards">
            <div class="card critical">
                <div class="count">{{ findings_by_severity.critical | default(0) }}</div>
                <div class="label">{{ 'بحرانی' if language == 'fa' else 'Critical' }}</div>
            </div>
            <div class="card high">
                <div class="count">{{ findings_by_severity.high | default(0) }}</div>
                <div class="label">{{ 'بالا' if language == 'fa' else 'High' }}</div>
            </div>
            <div class="card medium">
                <div class="count">{{ findings_by_severity.medium | default(0) }}</div>
                <div class="label">{{ 'متوسط' if language == 'fa' else 'Medium' }}</div>
            </div>
            <div class="card low">
                <div class="count">{{ findings_by_severity.low | default(0) }}</div>
                <div class="label">{{ 'پایین' if language == 'fa' else 'Low' }}</div>
            </div>
            <div class="card info">
                <div class="count">{{ findings_by_severity.info | default(0) }}</div>
                <div class="label">{{ 'اطلاعاتی' if language == 'fa' else 'Info' }}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>{{ 'خلاصه اجرایی' if language == 'fa' else 'Executive Summary' }}</h2>
            <p>{{ executive_summary }}</p>
        </div>
        
        <div class="section">
            <h2>{{ 'یافته‌های امنیتی' if language == 'fa' else 'Security Findings' }}</h2>
            
            {% for finding in findings %}
            <div class="finding">
                <div class="finding-header">
                    <span class="finding-title">
                        {{ finding.title_fa if language == 'fa' else finding.title }}
                    </span>
                    <span class="severity-badge severity-{{ finding.severity }}">
                        {{ severity_labels[finding.severity] }}
                    </span>
                </div>
                
                <div class="finding-meta">
                    <span><strong>WSTG:</strong> {{ finding.wstg_id }}</span>
                    {% if finding.owasp_top10_id %}
                    <span><strong>OWASP:</strong> {{ finding.owasp_top10_id }}</span>
                    {% endif %}
                    <span><strong>Endpoint:</strong> {{ finding.endpoint }}</span>
                </div>
                
                <div class="finding-description">
                    {{ finding.description_fa if language == 'fa' else finding.description }}
                </div>
                
                {% if finding.evidence and include_evidence %}
                <div class="finding-evidence">
                    <strong>{{ 'شواهد' if language == 'fa' else 'Evidence' }}:</strong><br>
                    {{ finding.evidence }}
                </div>
                {% endif %}
                
                {% if include_remediation %}
                <div class="finding-recommendation">
                    <strong>{{ 'توصیه' if language == 'fa' else 'Recommendation' }}:</strong><br>
                    {{ finding.recommendation_fa if language == 'fa' else finding.recommendation }}
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        
        <div class="footer">
            <p>{{ 'تولید شده توسط OWASP Security Scanner' if language == 'fa' else 'Generated by OWASP Security Scanner' }}</p>
            <p>{{ 'این گزارش محرمانه است و فقط برای استفاده داخلی می‌باشد' if language == 'fa' else 'This report is confidential and for internal use only' }}</p>
        </div>
    </div>
</body>
</html>'''
        
        html_path = os.path.join(templates_dir, "report.html")
        if not os.path.exists(html_path):
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_template)
    
    async def generate_report(
        self,
        report_id: str,
        scan_id: str,
        format: ReportFormat,
        language: str = "fa",
        include_evidence: bool = False,
        include_remediation: bool = True
    ):
        """Generate a security report."""
        logger.info(f"Generating report: {report_id} (format: {format.value})")
        
        try:
            # Get scan and project data
            scan = await scans_collection().find_one({"_id": scan_id})
            if not scan:
                raise ValueError("Scan not found")
            
            project = await projects_collection().find_one({"_id": scan["project_id"]})
            if not project:
                raise ValueError("Project not found")
            
            # Get findings sorted by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            findings = await findings_collection().find(
                {"scan_id": scan_id}
            ).to_list(length=1000)
            
            findings.sort(key=lambda x: severity_order.get(x["severity"], 5))
            
            # Calculate severity counts
            findings_by_severity = {}
            for finding in findings:
                sev = finding["severity"]
                findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1
            
            # Generate executive summary
            executive_summary = self._generate_executive_summary(
                project["domain"],
                findings_by_severity,
                language
            )
            
            # Prepare report data
            report_data = {
                "title": f"گزارش امنیتی - {project['domain']}" if language == "fa" else f"Security Report - {project['domain']}",
                "domain": project["domain"],
                "scan_date": scan.get("started_at", scan["created_at"]).strftime("%Y-%m-%d %H:%M"),
                "report_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
                "language": language,
                "findings": findings,
                "findings_by_severity": findings_by_severity,
                "executive_summary": executive_summary,
                "include_evidence": include_evidence,
                "include_remediation": include_remediation,
                "severity_labels": {
                    "critical": "بحرانی" if language == "fa" else "Critical",
                    "high": "بالا" if language == "fa" else "High",
                    "medium": "متوسط" if language == "fa" else "Medium",
                    "low": "پایین" if language == "fa" else "Low",
                    "info": "اطلاعاتی" if language == "fa" else "Info"
                },
                "scan_config": scan.get("config", {}),
                "total_findings": len(findings)
            }
            
            # Get report file path
            report = await reports_collection().find_one({"_id": report_id})
            file_path = report["file_path"]
            
            # Generate based on format
            if format == ReportFormat.JSON:
                await self._generate_json_report(file_path, report_data)
            elif format == ReportFormat.HTML:
                await self._generate_html_report(file_path, report_data)
            elif format == ReportFormat.PDF:
                await self._generate_pdf_report(file_path, report_data)
            
            # Update report status
            await reports_collection().update_one(
                {"_id": report_id},
                {"$set": {
                    "status": "ready",
                    "file_size": os.path.getsize(file_path),
                    "updated_at": datetime.now(timezone.utc)
                }}
            )
            
            logger.info(f"Report generated: {report_id}")
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}", exc_info=True)
            await reports_collection().update_one(
                {"_id": report_id},
                {"$set": {
                    "status": "failed",
                    "error": str(e),
                    "updated_at": datetime.now(timezone.utc)
                }}
            )
    
    def _generate_executive_summary(
        self,
        domain: str,
        findings_by_severity: Dict[str, int],
        language: str
    ) -> str:
        """Generate executive summary text."""
        total = sum(findings_by_severity.values())
        critical = findings_by_severity.get("critical", 0)
        high = findings_by_severity.get("high", 0)
        
        if language == "fa":
            summary = f"اسکن امنیتی دامنه {domain} انجام شد و در مجموع {total} یافته امنیتی شناسایی شد. "
            
            if critical > 0:
                summary += f"تعداد {critical} آسیب‌پذیری بحرانی شناسایی شده که نیاز به رسیدگی فوری دارند. "
            
            if high > 0:
                summary += f"همچنین {high} آسیب‌پذیری با شدت بالا وجود دارد که باید در اسرع وقت برطرف شوند. "
            
            if critical == 0 and high == 0:
                summary += "هیچ آسیب‌پذیری بحرانی یا با شدت بالا یافت نشد. "
            
            summary += "توصیه می‌شود تمام یافته‌ها بررسی و اقدامات اصلاحی لازم انجام شود."
        else:
            summary = f"Security scan of {domain} completed with {total} total findings. "
            
            if critical > 0:
                summary += f"{critical} critical vulnerabilities require immediate attention. "
            
            if high > 0:
                summary += f"{high} high severity issues should be addressed promptly. "
            
            if critical == 0 and high == 0:
                summary += "No critical or high severity vulnerabilities were found. "
            
            summary += "We recommend reviewing all findings and implementing necessary remediation measures."
        
        return summary
    
    async def _generate_json_report(self, file_path: str, data: Dict[str, Any]):
        """Generate JSON format report."""
        # Clean data for JSON serialization
        clean_data = {
            "report_info": {
                "title": data["title"],
                "domain": data["domain"],
                "scan_date": data["scan_date"],
                "report_date": data["report_date"],
                "language": data["language"]
            },
            "summary": {
                "total_findings": data["total_findings"],
                "findings_by_severity": data["findings_by_severity"],
                "executive_summary": data["executive_summary"]
            },
            "findings": [
                {
                    "id": f.get("_id"),
                    "title": f.get("title"),
                    "title_fa": f.get("title_fa"),
                    "description": f.get("description"),
                    "description_fa": f.get("description_fa"),
                    "severity": f.get("severity"),
                    "wstg_id": f.get("wstg_id"),
                    "owasp_top10_id": f.get("owasp_top10_id"),
                    "endpoint": f.get("endpoint"),
                    "method": f.get("method"),
                    "evidence": f.get("evidence") if data["include_evidence"] else None,
                    "recommendation": f.get("recommendation"),
                    "recommendation_fa": f.get("recommendation_fa"),
                    "cvss_score": f.get("cvss_score")
                }
                for f in data["findings"]
            ],
            "scan_config": data["scan_config"]
        }
        
        async with aiofiles.open(file_path, "w", encoding="utf-8") as f:
            await f.write(json.dumps(clean_data, ensure_ascii=False, indent=2))
    
    async def _generate_html_report(self, file_path: str, data: Dict[str, Any]):
        """Generate HTML format report."""
        template = self.jinja_env.get_template("report.html")
        html_content = template.render(**data)
        
        async with aiofiles.open(file_path, "w", encoding="utf-8") as f:
            await f.write(html_content)
    
    async def _generate_pdf_report(self, file_path: str, data: Dict[str, Any]):
        """Generate PDF format report using WeasyPrint."""
        try:
            from weasyprint import HTML, CSS
            
            # First generate HTML
            template = self.jinja_env.get_template("report.html")
            html_content = template.render(**data)
            
            # Convert to PDF
            html = HTML(string=html_content)
            
            # Add print-friendly CSS
            css = CSS(string='''
                @page { 
                    size: A4; 
                    margin: 2cm;
                }
                body { font-size: 11pt; }
            ''')
            
            html.write_pdf(file_path, stylesheets=[css])
            
        except ImportError:
            logger.warning("WeasyPrint not available, falling back to HTML")
            # Fallback to HTML with .pdf extension
            html_path = file_path.replace(".pdf", ".html")
            await self._generate_html_report(html_path, data)
            
            # Copy HTML to PDF path (user can open in browser)
            import shutil
            shutil.copy(html_path, file_path)
    
    async def cleanup_expired_reports(self):
        """Remove expired reports."""
        now = datetime.now(timezone.utc)
        
        # Find expired reports
        expired = await reports_collection().find(
            {"expires_at": {"$lt": now}}
        ).to_list(length=1000)
        
        for report in expired:
            # Delete file
            if os.path.exists(report["file_path"]):
                try:
                    os.remove(report["file_path"])
                except Exception as e:
                    logger.error(f"Failed to delete report file: {e}")
            
            # Delete record
            await reports_collection().delete_one({"_id": report["_id"]})
        
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired reports")