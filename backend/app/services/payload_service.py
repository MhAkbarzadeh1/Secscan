"""
Payload Service - Manages security payloads from PayloadsAllTheThings repository.

Features:
- Sync payloads from GitHub repository
- Categorize payloads by vulnerability type
- Separate safe and aggressive payloads
- Support for 1000+ payloads per category
- Payload combination and generation
"""
import os
import re
import uuid
import asyncio
import logging
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import aiofiles

from app.core.database import payloads_collection, get_database
from app.core.config import settings
from app.core.security import is_payload_safe
from app.models.schemas import PayloadCategory

logger = logging.getLogger(__name__)


# Mapping of PayloadsAllTheThings folders to our categories
PAYLOAD_MAPPINGS = {
    "SQL Injection": PayloadCategory.SQLI,
    "XSS Injection": PayloadCategory.XSS,
    "Command Injection": PayloadCategory.COMMAND_INJECTION,
    "Directory Traversal": PayloadCategory.PATH_TRAVERSAL,
    "Server Side Request Forgery": PayloadCategory.SSRF,
    "XXE Injection": PayloadCategory.XXE,
    "Server Side Template Injection": PayloadCategory.SSTI,
    "LDAP Injection": PayloadCategory.LDAP_INJECTION,
    "NoSQL Injection": PayloadCategory.NOSQL_INJECTION,
    "CRLF Injection": PayloadCategory.HEADER_INJECTION,
    "Host Header Injection": PayloadCategory.HEADER_INJECTION,
}

# Patterns that indicate aggressive payloads
AGGRESSIVE_PATTERNS = [
    # Destructive SQL
    r"DROP\s+TABLE",
    r"DELETE\s+FROM",
    r"TRUNCATE\s+TABLE",
    r"UPDATE\s+.*SET",
    r"INSERT\s+INTO",
    r"ALTER\s+TABLE",
    r"CREATE\s+TABLE",
    r"xp_cmdshell",
    r"sp_execute",
    
    # Destructive commands
    r"rm\s+-rf",
    r"rm\s+-r",
    r"del\s+/[sfq]",
    r"format\s+c:",
    r"shutdown",
    r"reboot",
    r"mkfs",
    r"dd\s+if=",
    r":\s*\(\)\s*\{",  # Fork bomb
    
    # System access
    r"/etc/passwd",
    r"/etc/shadow",
    r"\\windows\\system32",
    r"cmd\.exe",
    r"powershell",
    
    # Data exfiltration
    r"curl\s+.*\|",
    r"wget\s+.*\|",
    r"nc\s+-e",
    r"bash\s+-i",
    r"python\s+-c.*socket",
    
    # Time delays (could cause DoS)
    r"SLEEP\s*\(\s*\d{2,}",  # Sleep > 10 seconds
    r"WAITFOR\s+DELAY",
    r"BENCHMARK\s*\(",
    r"pg_sleep\s*\(\s*\d{2,}",
]

# Sync status document ID
SYNC_STATUS_ID = "payload_sync_status"


class PayloadService:
    """Service for managing security payloads."""
    
    def __init__(self):
        self.payloads_dir = settings.PAYLOADS_DIR
        self.repo_url = settings.PAYLOADS_REPO_URL
    
    async def _get_sync_collection(self):
        """Get the sync status collection."""
        db = get_database()
        return db.sync_status
    
    async def _get_status_from_db(self) -> Dict[str, Any]:
        """Get sync status from database."""
        collection = await self._get_sync_collection()
        status = await collection.find_one({"_id": SYNC_STATUS_ID})
        
        if not status:
            # Return default status
            return {
                "_id": SYNC_STATUS_ID,
                "is_syncing": False,
                "last_sync": None,
                "last_error": None,
                "progress": 0,
                "message": "Not synced yet"
            }
        
        return status
    
    async def _update_status(self, **kwargs):
        """Update sync status in database."""
        collection = await self._get_sync_collection()
        await collection.update_one(
            {"_id": SYNC_STATUS_ID},
            {"$set": kwargs},
            upsert=True
        )
    
    async def get_sync_status(self) -> Dict[str, Any]:
        """Get current sync status."""
        status = await self._get_status_from_db()
        # Remove _id from response
        return {
            "is_syncing": status.get("is_syncing", False),
            "last_sync": status.get("last_sync"),
            "last_error": status.get("last_error"),
            "progress": status.get("progress", 0),
            "message": status.get("message", "")
        }
    
    async def sync_payloads(self):
        """
        Sync payloads from PayloadsAllTheThings repository.
        
        Process:
        1. Clone or update repository
        2. Parse payload files
        3. Categorize and classify payloads
        4. Store in database with safe/aggressive flags
        """
        # Check if already syncing
        current_status = await self._get_status_from_db()
        if current_status.get("is_syncing", False):
            logger.warning("Sync already in progress")
            return
        
        # Mark as syncing
        await self._update_status(
            is_syncing=True,
            progress=0,
            message="Starting sync...",
            last_error=None
        )
        
        try:
            # Step 1: Clone or update repository
            await self._update_status(progress=5, message="Updating repository...")
            await self._update_repository()
            await self._update_status(progress=20, message="Repository updated")
            
            # Step 2: Clear existing payloads
            await payloads_collection().delete_many({})
            await self._update_status(progress=25, message="Cleared old payloads")
            
            # Step 3: Parse and import payloads
            total_imported = 0
            categories_processed = 0
            total_categories = len(PAYLOAD_MAPPINGS)
            
            for folder_name, category in PAYLOAD_MAPPINGS.items():
                await self._update_status(
                    message=f"Processing {folder_name}..."
                )
                
                count = await self._import_category(folder_name, category)
                total_imported += count
                categories_processed += 1
                
                progress = 25 + int((categories_processed / total_categories) * 60)
                await self._update_status(progress=progress)
                
                logger.info(f"Imported {count} payloads for {category.value}")
            
            # Step 4: Generate additional payloads if needed
            await self._update_status(progress=90, message="Generating variations...")
            for category in PayloadCategory:
                await self._ensure_minimum_payloads(category, min_count=1000)
            
            # Mark as completed
            await self._update_status(
                is_syncing=False,
                progress=100,
                message=f"Sync completed: {total_imported} payloads imported",
                last_sync=datetime.now(timezone.utc),
                last_error=None
            )
            
            logger.info(f"Payload sync completed: {total_imported} total payloads")
            
        except Exception as e:
            logger.error(f"Payload sync failed: {e}", exc_info=True)
            await self._update_status(
                is_syncing=False,
                last_error=str(e),
                message=f"Sync failed: {str(e)}"
            )
    
    async def _update_repository(self):
        """Clone or update the PayloadsAllTheThings repository."""
        os.makedirs(self.payloads_dir, exist_ok=True)
        repo_path = os.path.join(self.payloads_dir, "PayloadsAllTheThings")
        
        if os.path.exists(os.path.join(repo_path, ".git")):
            # Update existing repository
            logger.info("Updating PayloadsAllTheThings repository...")
            process = await asyncio.create_subprocess_exec(
                "git", "pull", "--ff-only",
                cwd=repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.warning(f"Git pull warning: {stderr.decode()}")
        else:
            # Clone repository
            logger.info("Cloning PayloadsAllTheThings repository...")
            process = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", self.repo_url, repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise Exception(f"Git clone failed: {stderr.decode()}")
        
        logger.info("Repository ready")
    
    async def _import_category(self, folder_name: str, category: PayloadCategory) -> int:
        """Import payloads from a category folder."""
        repo_path = os.path.join(self.payloads_dir, "PayloadsAllTheThings")
        category_path = os.path.join(repo_path, folder_name)
        
        if not os.path.exists(category_path):
            logger.warning(f"Category folder not found: {category_path}")
            return 0
        
        payloads = []
        
        # Find all relevant files
        for root, dirs, files in os.walk(category_path):
            for filename in files:
                if filename.endswith((".md", ".txt", ".json")):
                    file_path = os.path.join(root, filename)
                    extracted = await self._extract_payloads_from_file(
                        file_path, category, filename
                    )
                    payloads.extend(extracted)
        
        # Insert payloads in batches
        if payloads:
            # Deduplicate
            seen = set()
            unique_payloads = []
            for p in payloads:
                payload_hash = hash(p["payload"])
                if payload_hash not in seen:
                    seen.add(payload_hash)
                    unique_payloads.append(p)
            
            # Insert in batches of 500
            batch_size = 500
            for i in range(0, len(unique_payloads), batch_size):
                batch = unique_payloads[i:i + batch_size]
                await payloads_collection().insert_many(batch)
        
        return len(payloads)
    
    async def _extract_payloads_from_file(
        self,
        file_path: str,
        category: PayloadCategory,
        filename: str
    ) -> List[Dict[str, Any]]:
        """Extract payloads from a file."""
        payloads = []
        
        try:
            async with aiofiles.open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = await f.read()
            
            if filename.endswith(".md"):
                # Extract from markdown code blocks
                extracted = self._extract_from_markdown(content)
            elif filename.endswith(".txt"):
                # Each line is a payload
                extracted = [line.strip() for line in content.split("\n") if line.strip()]
            elif filename.endswith(".json"):
                # Parse JSON
                import json
                try:
                    data = json.loads(content)
                    extracted = self._extract_from_json(data)
                except:
                    extracted = []
            else:
                extracted = []
            
            # Create payload documents
            for payload_text in extracted:
                if len(payload_text) < 3 or len(payload_text) > 10000:
                    continue
                
                # Check if aggressive
                is_aggressive = self._is_aggressive_payload(payload_text)
                
                payload_doc = {
                    "_id": str(uuid.uuid4()),
                    "payload": payload_text,
                    "category": category.value,
                    "name": self._generate_payload_name(payload_text, category),
                    "description": f"Payload from {filename}",
                    "is_aggressive": is_aggressive,
                    "source": "PayloadsAllTheThings",
                    "source_file": os.path.basename(file_path),
                    "synced_at": datetime.now(timezone.utc)
                }
                payloads.append(payload_doc)
                
        except Exception as e:
            logger.debug(f"Error extracting from {file_path}: {e}")
        
        return payloads
    
    def _extract_from_markdown(self, content: str) -> List[str]:
        """Extract payloads from markdown content."""
        payloads = []
        
        # Extract code blocks
        code_block_pattern = r"```[\w]*\n(.*?)```"
        matches = re.findall(code_block_pattern, content, re.DOTALL)
        for match in matches:
            lines = [line.strip() for line in match.split("\n") if line.strip()]
            payloads.extend(lines)
        
        # Extract inline code
        inline_pattern = r"`([^`]+)`"
        matches = re.findall(inline_pattern, content)
        payloads.extend(matches)
        
        # Extract lines that look like payloads (start with special chars)
        payload_line_pattern = r"^[\s]*(['\"\-<\[\{\(].{5,})$"
        for line in content.split("\n"):
            match = re.match(payload_line_pattern, line)
            if match:
                payloads.append(match.group(1).strip())
        
        return payloads
    
    def _extract_from_json(self, data: Any) -> List[str]:
        """Extract payloads from JSON data."""
        payloads = []
        
        def extract_recursive(obj):
            if isinstance(obj, str):
                payloads.append(obj)
            elif isinstance(obj, list):
                for item in obj:
                    extract_recursive(item)
            elif isinstance(obj, dict):
                for key, value in obj.items():
                    if key.lower() in ["payload", "payloads", "vector", "vectors"]:
                        extract_recursive(value)
        
        extract_recursive(data)
        return payloads
    
    def _is_aggressive_payload(self, payload: str) -> bool:
        """Check if a payload is aggressive (potentially destructive)."""
        payload_upper = payload.upper()
        
        for pattern in AGGRESSIVE_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                return True
        
        return False
    
    def _generate_payload_name(self, payload: str, category: PayloadCategory) -> str:
        """Generate a descriptive name for a payload."""
        # Truncate and clean payload for name
        clean = re.sub(r"[^\w\s]", "", payload)[:30]
        return f"{category.value}_{clean}".replace(" ", "_")
    
    async def _ensure_minimum_payloads(self, category: PayloadCategory, min_count: int = 1000):
        """
        Ensure minimum number of payloads per category.
        
        If less than min_count, generate variations of existing payloads.
        """
        current_count = await payloads_collection().count_documents(
            {"category": category.value}
        )
        
        if current_count >= min_count:
            return
        
        needed = min_count - current_count
        logger.info(f"Generating {needed} additional payloads for {category.value}")
        
        # Get existing payloads as templates
        existing = await payloads_collection().find(
            {"category": category.value}
        ).limit(100).to_list(length=100)
        
        if not existing:
            return
        
        new_payloads = []
        
        for template in existing:
            if len(new_payloads) >= needed:
                break
            
            variations = self._generate_payload_variations(
                template["payload"],
                category
            )
            
            for var in variations:
                if len(new_payloads) >= needed:
                    break
                
                new_payloads.append({
                    "_id": str(uuid.uuid4()),
                    "payload": var,
                    "category": category.value,
                    "name": self._generate_payload_name(var, category),
                    "description": "Generated variation",
                    "is_aggressive": self._is_aggressive_payload(var),
                    "source": "generated",
                    "source_file": "variation",
                    "synced_at": datetime.now(timezone.utc)
                })
        
        if new_payloads:
            await payloads_collection().insert_many(new_payloads)
            logger.info(f"Added {len(new_payloads)} generated payloads for {category.value}")
    
    def _generate_payload_variations(
        self,
        base_payload: str,
        category: PayloadCategory
    ) -> List[str]:
        """Generate variations of a base payload."""
        variations = []
        
        # Encoding variations
        encodings = [
            lambda x: x,  # Original
            lambda x: x.replace(" ", "+"),  # URL space
            lambda x: x.replace(" ", "%20"),  # URL encoded space
            lambda x: x.replace("'", "%27"),  # URL encoded quote
            lambda x: x.replace('"', "%22"),  # URL encoded double quote
            lambda x: x.replace("<", "%3C"),  # URL encoded <
            lambda x: x.replace(">", "%3E"),  # URL encoded >
            lambda x: x.upper(),  # Uppercase
            lambda x: x.lower(),  # Lowercase
            lambda x: "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(x)),  # Mixed case
        ]
        
        for encode_func in encodings:
            try:
                variation = encode_func(base_payload)
                if variation != base_payload and variation not in variations:
                    variations.append(variation)
            except:
                pass
        
        # Category-specific variations
        if category == PayloadCategory.SQLI:
            variations.extend(self._generate_sqli_variations(base_payload))
        elif category == PayloadCategory.XSS:
            variations.extend(self._generate_xss_variations(base_payload))
        
        return variations[:20]  # Limit variations per base
    
    def _generate_sqli_variations(self, base: str) -> List[str]:
        """Generate SQL injection variations."""
        variations = []
        
        # Comment variations
        comments = ["--", "#", "/**/", "-- -", ";--"]
        for comment in comments:
            if comment not in base:
                variations.append(base + comment)
        
        # Quote variations
        if "'" in base:
            variations.append(base.replace("'", "\""))
        if '"' in base:
            variations.append(base.replace('"', "'"))
        
        # Whitespace variations
        variations.append(base.replace(" ", "/**/"))
        variations.append(base.replace(" ", "\t"))
        
        return variations
    
    def _generate_xss_variations(self, base: str) -> List[str]:
        """Generate XSS variations."""
        variations = []
        
        # Event handler variations
        handlers = ["onerror", "onload", "onclick", "onmouseover", "onfocus"]
        for handler in handlers:
            if handler not in base.lower():
                variations.append(base.replace("onerror", handler))
        
        # Tag variations
        tags = ["<img", "<svg", "<body", "<iframe", "<input", "<video"]
        for tag in tags:
            if tag not in base.lower() and "<" in base:
                new_var = re.sub(r"<\w+", tag, base)
                if new_var != base:
                    variations.append(new_var)
        
        return variations
    
    async def get_payloads(
        self,
        category: PayloadCategory,
        is_aggressive: bool = False,
        limit: int = 100
    ) -> List[str]:
        """Get payloads for a specific category."""
        payloads = await payloads_collection().find(
            {
                "category": category.value,
                "is_aggressive": is_aggressive
            }
        ).limit(limit).to_list(length=limit)
        
        return [p["payload"] for p in payloads]
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get payload statistics."""
        pipeline = [
            {"$facet": {
                "total": [{"$count": "count"}],
                "safe": [
                    {"$match": {"is_aggressive": False}},
                    {"$count": "count"}
                ],
                "aggressive": [
                    {"$match": {"is_aggressive": True}},
                    {"$count": "count"}
                ],
                "by_category": [
                    {"$group": {"_id": "$category", "count": {"$sum": 1}}}
                ]
            }}
        ]
        
        result = await payloads_collection().aggregate(pipeline).to_list(length=1)
        
        if not result:
            return {
                "total": 0,
                "safe": 0,
                "aggressive": 0,
                "categories": 0,
                "by_category": {}
            }
        
        data = result[0]
        
        total = data["total"][0]["count"] if data["total"] else 0
        safe = data["safe"][0]["count"] if data["safe"] else 0
        aggressive = data["aggressive"][0]["count"] if data["aggressive"] else 0
        
        by_category = {item["_id"]: item["count"] for item in data.get("by_category", [])}
        
        return {
            "total": total,
            "safe": safe,
            "aggressive": aggressive,
            "categories": len(by_category),
            "by_category": by_category
        }