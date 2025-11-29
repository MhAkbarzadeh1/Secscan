"""
Notification service for alerts and emails
"""
import aiohttp
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class NotificationService:
    """Handle notifications (Telegram, Email, Webhook)"""
    
    def __init__(self):
        self.telegram_token: Optional[str] = None
        self.telegram_chat_id: Optional[str] = None
        self.webhook_url: Optional[str] = None
    
    def configure_telegram(self, token: str, chat_id: str):
        """Configure Telegram bot"""
        self.telegram_token = token
        self.telegram_chat_id = chat_id
    
    def configure_webhook(self, url: str):
        """Configure webhook URL"""
        self.webhook_url = url
    
    async def send_telegram(self, message: str) -> bool:
        """Send Telegram message"""
        if not self.telegram_token or not self.telegram_chat_id:
            return False
        
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": message,
            "parse_mode": "HTML"
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as resp:
                    return resp.status == 200
        except Exception as e:
            logger.error(f"Telegram error: {e}")
            return False
    
    async def send_webhook(self, data: Dict[str, Any]) -> bool:
        """Send webhook notification"""
        if not self.webhook_url:
            return False
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=data) as resp:
                    return resp.status < 400
        except Exception as e:
            logger.error(f"Webhook error: {e}")
            return False
    
    async def notify_scan_complete(self, scan_id: str, findings_count: int, critical_count: int):
        """Notify when scan completes"""
        message = f"""
🔍 <b>اسکن کامل شد</b>

📋 شناسه: <code>{scan_id}</code>
📊 یافته‌ها: {findings_count}
🔴 بحرانی: {critical_count}
"""
        await self.send_telegram(message)
        await self.send_webhook({
            "event": "scan_complete",
            "scan_id": scan_id,
            "findings": findings_count,
            "critical": critical_count
        })
    
    async def notify_critical_finding(self, finding_title: str, endpoint: str):
        """Notify on critical finding"""
        message = f"""
🚨 <b>آسیب‌پذیری بحرانی!</b>

⚠️ {finding_title}
🔗 {endpoint}
"""
        await self.send_telegram(message)


# Global instance
notification_service = NotificationService()