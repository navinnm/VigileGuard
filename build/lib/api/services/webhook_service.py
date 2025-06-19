"""Webhook Service for managing webhook deliveries and notifications"""

import asyncio
import json
import logging
import hmac
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import httpx
from urllib.parse import urlparse

from ..models.webhook import Webhook, WebhookEvent, WebhookDelivery, WebhookStatus


logger = logging.getLogger(__name__)


class WebhookService:
    """Service for managing webhook notifications and deliveries"""
    
    def __init__(self):
        self.webhooks: Dict[str, Webhook] = {}
        self.delivery_queue: List[WebhookDelivery] = []
        self.retry_queue: List[WebhookDelivery] = []
        self.is_processing = False
    
    async def register_webhook(self, webhook: Webhook) -> str:
        """Register a new webhook"""
        self.webhooks[webhook.id] = webhook
        logger.info(f"Registered webhook: {webhook.name} ({webhook.id})")
        return webhook.id
    
    async def get_webhook(self, webhook_id: str) -> Optional[Webhook]:
        """Get webhook by ID"""
        return self.webhooks.get(webhook_id)
    
    async def list_webhooks(self, user_id: str) -> List[Webhook]:
        """List webhooks for a user"""
        return [webhook for webhook in self.webhooks.values() 
                if webhook.user_id == user_id]
    
    async def update_webhook(self, webhook_id: str, updates: Dict[str, Any]) -> bool:
        """Update webhook configuration"""
        webhook = self.webhooks.get(webhook_id)
        if not webhook:
            return False
        
        # Update allowed fields
        for field, value in updates.items():
            if hasattr(webhook, field) and field not in ['id', 'user_id', 'created_at']:
                setattr(webhook, field, value)
        
        webhook.updated_at = datetime.utcnow()
        logger.info(f"Updated webhook: {webhook.name} ({webhook_id})")
        return True
    
    async def delete_webhook(self, webhook_id: str) -> bool:
        """Delete webhook"""
        if webhook_id in self.webhooks:
            webhook = self.webhooks.pop(webhook_id)
            logger.info(f"Deleted webhook: {webhook.name} ({webhook_id})")
            return True
        return False
    
    async def trigger_webhook_event(self, event: WebhookEvent, payload: Dict[str, Any]):
        """Trigger webhook event for all matching webhooks"""
        matching_webhooks = [
            webhook for webhook in self.webhooks.values()
            if webhook.should_trigger(event, payload)
        ]
        
        logger.info(f"Triggering {event.value} event for {len(matching_webhooks)} webhooks")
        
        # Queue webhook deliveries
        for webhook in matching_webhooks:
            delivery = WebhookDelivery(
                id=f"delivery_{webhook.id}_{datetime.utcnow().timestamp()}",
                webhook_id=webhook.id,
                event=event,
                payload=payload
            )
            self.delivery_queue.append(delivery)
        
        # Start processing if not already running
        if not self.is_processing:
            asyncio.create_task(self.process_delivery_queue())
    
    async def process_delivery_queue(self):
        """Process pending webhook deliveries"""
        if self.is_processing:
            return
        
        self.is_processing = True
        
        try:
            while self.delivery_queue or self.retry_queue:
                # Process new deliveries first
                if self.delivery_queue:
                    delivery = self.delivery_queue.pop(0)
                    await self.deliver_webhook(delivery)
                
                # Process retries
                elif self.retry_queue:
                    delivery = self.retry_queue.pop(0)
                    # Check if enough time has passed for retry
                    webhook = self.webhooks.get(delivery.webhook_id)
                    if webhook:
                        time_since_created = (datetime.utcnow() - delivery.created_at).total_seconds()
                        if time_since_created >= webhook.retry_backoff * delivery.attempt_count:
                            await self.deliver_webhook(delivery)
                        else:
                            # Put back in retry queue
                            self.retry_queue.append(delivery)
                
                # Brief pause to prevent tight loop
                await asyncio.sleep(0.1)
        
        except Exception as e:
            logger.error(f"Error processing webhook delivery queue: {e}")
        
        finally:
            self.is_processing = False
    
    async def deliver_webhook(self, delivery: WebhookDelivery):
        """Deliver webhook to endpoint"""
        webhook = self.webhooks.get(delivery.webhook_id)
        if not webhook:
            logger.warning(f"Webhook not found for delivery: {delivery.webhook_id}")
            return
        
        try:
            # Prepare payload
            webhook_payload = {
                "event": delivery.event.value,
                "timestamp": datetime.utcnow().isoformat(),
                "delivery_id": delivery.id,
                "data": delivery.payload
            }
            
            # Create headers
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "VigileGuard-Webhook/3.0.2",
                **webhook.headers
            }
            
            # Add HMAC signature if secret is provided
            if webhook.secret:
                signature = self.create_signature(webhook_payload, webhook.secret)
                headers["X-VigileGuard-Signature"] = signature
                headers["X-VigileGuard-Signature-256"] = f"sha256={signature}"
            
            # Add delivery metadata headers
            headers["X-VigileGuard-Event"] = delivery.event.value
            headers["X-VigileGuard-Delivery"] = delivery.id
            headers["X-VigileGuard-Attempt"] = str(delivery.attempt_count)
            
            # Make HTTP request
            async with httpx.AsyncClient(timeout=webhook.timeout) as client:
                response = await client.post(
                    webhook.url,
                    json=webhook_payload,
                    headers=headers
                )
                
                # Update delivery record
                delivery.status_code = response.status_code
                delivery.response_body = response.text[:1000]  # Limit response body size
                delivery.delivered_at = datetime.utcnow()
                
                if delivery.is_successful():
                    logger.info(f"Webhook delivered successfully: {webhook.name} ({delivery.id})")
                    webhook.record_delivery(True)
                else:
                    logger.warning(f"Webhook delivery failed: {webhook.name} ({delivery.id}) - Status: {response.status_code}")
                    await self.handle_delivery_failure(webhook, delivery)
        
        except httpx.TimeoutException:
            logger.warning(f"Webhook delivery timeout: {webhook.name} ({delivery.id})")
            delivery.error_message = "Request timeout"
            await self.handle_delivery_failure(webhook, delivery)
        
        except httpx.RequestError as e:
            logger.warning(f"Webhook delivery request error: {webhook.name} ({delivery.id}) - {str(e)}")
            delivery.error_message = str(e)
            await self.handle_delivery_failure(webhook, delivery)
        
        except Exception as e:
            logger.error(f"Unexpected webhook delivery error: {webhook.name} ({delivery.id}) - {str(e)}")
            delivery.error_message = str(e)
            await self.handle_delivery_failure(webhook, delivery)
    
    async def handle_delivery_failure(self, webhook: Webhook, delivery: WebhookDelivery):
        """Handle failed webhook delivery"""
        webhook.record_delivery(False)
        
        # Retry if under max retry limit
        if delivery.attempt_count < webhook.max_retries:
            delivery.attempt_count += 1
            self.retry_queue.append(delivery)
            logger.info(f"Webhook delivery queued for retry {delivery.attempt_count}/{webhook.max_retries}: {webhook.name}")
        else:
            logger.error(f"Webhook delivery failed permanently after {webhook.max_retries} attempts: {webhook.name}")
    
    def create_signature(self, payload: Dict[str, Any], secret: str) -> str:
        """Create HMAC signature for webhook payload"""
        payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        signature = hmac.new(
            secret.encode('utf-8'),
            payload_bytes,
            hashlib.sha256
        ).hexdigest()
        return signature
    
    def verify_signature(self, payload: Dict[str, Any], signature: str, secret: str) -> bool:
        """Verify webhook signature"""
        expected_signature = self.create_signature(payload, secret)
        return hmac.compare_digest(signature, expected_signature)
    
    async def get_webhook_stats(self, webhook_id: str) -> Optional[Dict[str, Any]]:
        """Get webhook delivery statistics"""
        webhook = self.webhooks.get(webhook_id)
        if not webhook:
            return None
        
        return {
            "webhook_id": webhook.id,
            "name": webhook.name,
            "status": webhook.status.value,
            "total_deliveries": webhook.delivery_count,
            "successful_deliveries": webhook.success_count,
            "failed_deliveries": webhook.failure_count,
            "success_rate": webhook.get_success_rate(),
            "last_triggered": webhook.last_triggered.isoformat() if webhook.last_triggered else None,
            "events": [event.value for event in webhook.events],
            "created_at": webhook.created_at.isoformat(),
            "updated_at": webhook.updated_at.isoformat()
        }
    
    async def test_webhook(self, webhook_id: str) -> Dict[str, Any]:
        """Send test webhook delivery"""
        webhook = self.webhooks.get(webhook_id)
        if not webhook:
            return {"error": "Webhook not found"}
        
        # Create test payload
        test_payload = {
            "event": "webhook.test",
            "timestamp": datetime.utcnow().isoformat(),
            "webhook_id": webhook_id,
            "message": "This is a test webhook delivery from VigileGuard"
        }
        
        # Create test delivery
        delivery = WebhookDelivery(
            id=f"test_{webhook_id}_{datetime.utcnow().timestamp()}",
            webhook_id=webhook_id,
            event=WebhookEvent.SCAN_COMPLETED,  # Use existing event
            payload=test_payload
        )
        
        # Deliver immediately
        await self.deliver_webhook(delivery)
        
        return {
            "delivery_id": delivery.id,
            "status_code": delivery.status_code,
            "success": delivery.is_successful(),
            "response": delivery.response_body,
            "error": delivery.error_message
        }
    
    async def create_slack_webhook(self, user_id: str, name: str, webhook_url: str, 
                                 events: List[WebhookEvent], channel: str = "#security") -> str:
        """Create Slack-specific webhook with proper formatting"""
        webhook = Webhook(
            id=f"slack_{user_id}_{datetime.utcnow().timestamp()}",
            name=name,
            url=webhook_url,
            events=events,
            user_id=user_id,
            headers={"Content-Type": "application/json"},
            filters={"format": "slack"}  # Custom filter for Slack formatting
        )
        
        return await self.register_webhook(webhook)
    
    async def create_teams_webhook(self, user_id: str, name: str, webhook_url: str,
                                 events: List[WebhookEvent]) -> str:
        """Create Microsoft Teams-specific webhook"""
        webhook = Webhook(
            id=f"teams_{user_id}_{datetime.utcnow().timestamp()}",
            name=name,
            url=webhook_url,
            events=events,
            user_id=user_id,
            headers={"Content-Type": "application/json"},
            filters={"format": "teams"}
        )
        
        return await self.register_webhook(webhook)
    
    async def create_discord_webhook(self, user_id: str, name: str, webhook_url: str,
                                   events: List[WebhookEvent]) -> str:
        """Create Discord-specific webhook"""
        webhook = Webhook(
            id=f"discord_{user_id}_{datetime.utcnow().timestamp()}",
            name=name,
            url=webhook_url,
            events=events,
            user_id=user_id,
            headers={"Content-Type": "application/json"},
            filters={"format": "discord"}
        )
        
        return await self.register_webhook(webhook)
    
    def format_slack_payload(self, event: WebhookEvent, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format payload for Slack webhook"""
        color_map = {
            "critical": "#ff0000",
            "high": "#ff8c00",
            "medium": "#ffd700",
            "low": "#32cd32",
            "passed": "#28a745"
        }
        
        scan_data = data.get("scan", {})
        status = scan_data.get("status", "unknown")
        critical_count = scan_data.get("summary", {}).get("critical", 0)
        high_count = scan_data.get("summary", {}).get("high", 0)
        
        # Determine color and emoji
        if critical_count > 0:
            color = color_map["critical"]
            emoji = "🚨"
        elif high_count > 0:
            color = color_map["high"]
            emoji = "⚠️"
        elif status == "completed":
            color = color_map["passed"]
            emoji = "✅"
        else:
            color = "#6c757d"
            emoji = "🔍"
        
        return {
            "text": f"{emoji} VigileGuard Security Scan {event.value.replace('scan.', '').title()}",
            "attachments": [
                {
                    "color": color,
                    "fields": [
                        {
                            "title": "Target",
                            "value": scan_data.get("target", "N/A"),
                            "short": True
                        },
                        {
                            "title": "Status",
                            "value": status.title(),
                            "short": True
                        },
                        {
                            "title": "Critical Issues",
                            "value": str(critical_count),
                            "short": True
                        },
                        {
                            "title": "High Issues",
                            "value": str(high_count),
                            "short": True
                        }
                    ],
                    "ts": datetime.utcnow().timestamp()
                }
            ]
        }
    
    def format_teams_payload(self, event: WebhookEvent, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format payload for Microsoft Teams webhook"""
        scan_data = data.get("scan", {})
        status = scan_data.get("status", "unknown")
        critical_count = scan_data.get("summary", {}).get("critical", 0)
        high_count = scan_data.get("summary", {}).get("high", 0)
        
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF0000" if critical_count > 0 else "FFA500" if high_count > 0 else "28A745",
            "summary": f"VigileGuard Security Scan {event.value}",
            "sections": [
                {
                    "activityTitle": f"🛡️ VigileGuard Security Scan",
                    "activitySubtitle": f"Event: {event.value.replace('scan.', '').title()}",
                    "facts": [
                        {"name": "Target", "value": scan_data.get("target", "N/A")},
                        {"name": "Status", "value": status.title()},
                        {"name": "Critical Issues", "value": str(critical_count)},
                        {"name": "High Issues", "value": str(high_count)},
                        {"name": "Timestamp", "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}
                    ]
                }
            ]
        }
    
    def format_discord_payload(self, event: WebhookEvent, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format payload for Discord webhook"""
        scan_data = data.get("scan", {})
        status = scan_data.get("status", "unknown")
        critical_count = scan_data.get("summary", {}).get("critical", 0)
        high_count = scan_data.get("summary", {}).get("high", 0)
        
        # Determine color (Discord uses decimal color codes)
        if critical_count > 0:
            color = 16711680  # Red
        elif high_count > 0:
            color = 16753920  # Orange
        elif status == "completed":
            color = 2664261   # Green
        else:
            color = 7105644   # Gray
        
        return {
            "embeds": [
                {
                    "title": f"🛡️ VigileGuard Security Scan",
                    "description": f"Event: {event.value.replace('scan.', '').title()}",
                    "color": color,
                    "fields": [
                        {"name": "Target", "value": scan_data.get("target", "N/A"), "inline": True},
                        {"name": "Status", "value": status.title(), "inline": True},
                        {"name": "Critical Issues", "value": str(critical_count), "inline": True},
                        {"name": "High Issues", "value": str(high_count), "inline": True}
                    ],
                    "timestamp": datetime.utcnow().isoformat(),
                    "footer": {
                        "text": "VigileGuard Security Audit Engine",
                        "icon_url": "https://example.com/vigileguard-icon.png"
                    }
                }
            ]
        }