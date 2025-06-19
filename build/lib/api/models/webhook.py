"""Webhook Models"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


class WebhookEvent(Enum):
    """Webhook event types"""
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    CRITICAL_FINDING = "finding.critical"
    HIGH_FINDING = "finding.high"
    COMPLIANCE_CHANGE = "compliance.change"


class WebhookStatus(Enum):
    """Webhook delivery status"""
    ACTIVE = "active"
    DISABLED = "disabled"
    FAILED = "failed"


@dataclass
class WebhookDelivery:
    """Webhook delivery attempt record"""
    id: str
    webhook_id: str
    event: WebhookEvent
    payload: Dict[str, Any]
    status_code: Optional[int] = None
    response_body: Optional[str] = None
    error_message: Optional[str] = None
    attempt_count: int = 1
    delivered_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def is_successful(self) -> bool:
        """Check if delivery was successful"""
        return self.status_code is not None and 200 <= self.status_code < 300


@dataclass  
class Webhook:
    """Webhook configuration model"""
    id: str
    name: str
    url: str
    events: List[WebhookEvent]
    user_id: str
    status: WebhookStatus = WebhookStatus.ACTIVE
    secret: Optional[str] = None  # for HMAC signature verification
    
    # Configuration
    headers: Dict[str, str] = field(default_factory=dict)
    timeout: int = 30  # seconds
    max_retries: int = 3
    retry_backoff: int = 300  # seconds between retries
    
    # Filters
    filters: Dict[str, Any] = field(default_factory=dict)  # event filtering rules
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    last_triggered: Optional[datetime] = None
    
    # Statistics
    delivery_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    
    def should_trigger(self, event: WebhookEvent, payload: Dict[str, Any]) -> bool:
        """Check if webhook should trigger for given event and payload"""
        if self.status != WebhookStatus.ACTIVE:
            return False
        
        if event not in self.events:
            return False
        
        # Apply filters if configured
        if self.filters:
            return self._matches_filters(payload)
        
        return True
    
    def _matches_filters(self, payload: Dict[str, Any]) -> bool:
        """Check if payload matches configured filters"""
        for filter_key, filter_value in self.filters.items():
            payload_value = payload.get(filter_key)
            
            if isinstance(filter_value, list):
                if payload_value not in filter_value:
                    return False
            elif payload_value != filter_value:
                return False
        
        return True
    
    def record_delivery(self, success: bool) -> None:
        """Record webhook delivery attempt"""
        self.delivery_count += 1
        self.last_triggered = datetime.utcnow()
        
        if success:
            self.success_count += 1
        else:
            self.failure_count += 1
            
        # Disable webhook if too many consecutive failures
        if self.failure_count > 10 and self.success_count == 0:
            self.status = WebhookStatus.FAILED
    
    def get_success_rate(self) -> float:
        """Calculate webhook success rate"""
        if self.delivery_count == 0:
            return 100.0
        return (self.success_count / self.delivery_count) * 100.0