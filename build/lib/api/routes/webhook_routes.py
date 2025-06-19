"""Webhook Management API Routes"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, Field, HttpUrl

from ..auth.rbac import RBACManager, Permission
from ..models.user import User
from ..models.webhook import Webhook, WebhookEvent, WebhookStatus
from ..services.webhook_service import WebhookService
from .auth_routes import get_current_user


# Pydantic models for API requests/responses
class WebhookCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    url: HttpUrl
    events: List[WebhookEvent]
    secret: Optional[str] = Field(None, min_length=8, max_length=256)
    headers: Dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(30, ge=5, le=300)
    max_retries: int = Field(3, ge=0, le=10)
    retry_backoff: int = Field(300, ge=60, le=3600)
    filters: Dict[str, Any] = Field(default_factory=dict)


class WebhookUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    url: Optional[HttpUrl] = None
    events: Optional[List[WebhookEvent]] = None
    status: Optional[WebhookStatus] = None
    secret: Optional[str] = Field(None, min_length=8, max_length=256)
    headers: Optional[Dict[str, str]] = None
    timeout: Optional[int] = Field(None, ge=5, le=300)
    max_retries: Optional[int] = Field(None, ge=0, le=10)
    retry_backoff: Optional[int] = Field(None, ge=60, le=3600)
    filters: Optional[Dict[str, Any]] = None


class WebhookResponse(BaseModel):
    id: str
    name: str
    url: str
    events: List[str]
    status: str
    created_at: str
    updated_at: str
    last_triggered: Optional[str] = None
    delivery_count: int
    success_count: int
    failure_count: int
    success_rate: float


class WebhookStatsResponse(BaseModel):
    webhook_id: str
    name: str
    status: str
    total_deliveries: int
    successful_deliveries: int
    failed_deliveries: int
    success_rate: float
    last_triggered: Optional[str] = None
    events: List[str]
    created_at: str
    updated_at: str


class SlackWebhookRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    webhook_url: HttpUrl
    events: List[WebhookEvent]
    channel: str = Field("#security", min_length=1, max_length=100)


class TeamsWebhookRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    webhook_url: HttpUrl
    events: List[WebhookEvent]


class DiscordWebhookRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    webhook_url: HttpUrl
    events: List[WebhookEvent]


class WebhookTestResponse(BaseModel):
    delivery_id: str
    status_code: Optional[int] = None
    success: bool
    response: Optional[str] = None
    error: Optional[str] = None


# Initialize components
webhook_router = APIRouter(prefix="/webhooks", tags=["webhooks"])
webhook_service = WebhookService()
rbac_manager = RBACManager()


def require_webhook_permission(permission: Permission):
    """Dependency to check webhook permissions"""
    def permission_checker(current_user: User = Depends(get_current_user)) -> User:
        if not rbac_manager.has_permission(current_user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission.value}"
            )
        return current_user
    return permission_checker


@webhook_router.post("/", response_model=WebhookResponse)
async def create_webhook(
    webhook_data: WebhookCreateRequest,
    current_user: User = Depends(require_webhook_permission(Permission.WEBHOOK_CREATE))
):
    """Create a new webhook"""
    
    # Create webhook object
    webhook = Webhook(
        id=f"webhook_{current_user.id}_{datetime.utcnow().timestamp()}",
        name=webhook_data.name,
        url=str(webhook_data.url),
        events=webhook_data.events,
        user_id=current_user.id,
        secret=webhook_data.secret,
        headers=webhook_data.headers,
        timeout=webhook_data.timeout,
        max_retries=webhook_data.max_retries,
        retry_backoff=webhook_data.retry_backoff,
        filters=webhook_data.filters
    )
    
    # Register webhook
    webhook_id = await webhook_service.register_webhook(webhook)
    
    return WebhookResponse(
        id=webhook.id,
        name=webhook.name,
        url=webhook.url,
        events=[event.value for event in webhook.events],
        status=webhook.status.value,
        created_at=webhook.created_at.isoformat(),
        updated_at=webhook.updated_at.isoformat(),
        last_triggered=webhook.last_triggered.isoformat() if webhook.last_triggered else None,
        delivery_count=webhook.delivery_count,
        success_count=webhook.success_count,
        failure_count=webhook.failure_count,
        success_rate=webhook.get_success_rate()
    )


@webhook_router.get("/", response_model=List[WebhookResponse])
async def list_webhooks(
    current_user: User = Depends(require_webhook_permission(Permission.WEBHOOK_READ))
):
    """List user's webhooks"""
    
    webhooks = await webhook_service.list_webhooks(current_user.id)
    
    return [
        WebhookResponse(
            id=webhook.id,
            name=webhook.name,
            url=webhook.url,
            events=[event.value for event in webhook.events],
            status=webhook.status.value,
            created_at=webhook.created_at.isoformat(),
            updated_at=webhook.updated_at.isoformat(),
            last_triggered=webhook.last_triggered.isoformat() if webhook.last_triggered else None,
            delivery_count=webhook.delivery_count,
            success_count=webhook.success_count,
            failure_count=webhook.failure_count,
            success_rate=webhook.get_success_rate()
        )
        for webhook in webhooks
    ]


@webhook_router.get("/{webhook_id}", response_model=WebhookResponse)
async def get_webhook(
    webhook_id: str,
    current_user: User = Depends(require_webhook_permission(Permission.WEBHOOK_READ))
):
    """Get webhook details"""
    
    webhook = await webhook_service.get_webhook(webhook_id)
    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found"
        )
    
    # Check ownership (or admin)
    if webhook.user_id != current_user.id and not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this webhook"
        )
    
    return WebhookResponse(
        id=webhook.id,
        name=webhook.name,
        url=webhook.url,
        events=[event.value for event in webhook.events],
        status=webhook.status.value,
        created_at=webhook.created_at.isoformat(),
        updated_at=webhook.updated_at.isoformat(),
        last_triggered=webhook.last_triggered.isoformat() if webhook.last_triggered else None,
        delivery_count=webhook.delivery_count,
        success_count=webhook.success_count,
        failure_count=webhook.failure_count,
        success_rate=webhook.get_success_rate()
    )


@webhook_router.put("/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(
    webhook_id: str,
    webhook_data: WebhookUpdateRequest,
    current_user: User = Depends(require_webhook_permission(Permission.WEBHOOK_UPDATE))
):
    """Update webhook configuration"""
    
    webhook = await webhook_service.get_webhook(webhook_id)
    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found"
        )
    
    # Check ownership
    if webhook.user_id != current_user.id and not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this webhook"
        )
    
    # Prepare updates
    updates = {}
    for field, value in webhook_data.dict(exclude_unset=True).items():
        if value is not None:
            if field == "url":
                updates[field] = str(value)
            else:
                updates[field] = value
    
    # Update webhook
    success = await webhook_service.update_webhook(webhook_id, updates)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to update webhook"
        )
    
    # Return updated webhook
    updated_webhook = await webhook_service.get_webhook(webhook_id)
    return WebhookResponse(
        id=updated_webhook.id,
        name=updated_webhook.name,
        url=updated_webhook.url,
        events=[event.value for event in updated_webhook.events],
        status=updated_webhook.status.value,
        created_at=updated_webhook.created_at.isoformat(),
        updated_at=updated_webhook.updated_at.isoformat(),
        last_triggered=updated_webhook.last_triggered.isoformat() if updated_webhook.last_triggered else None,
        delivery_count=updated_webhook.delivery_count,
        success_count=updated_webhook.success_count,
        failure_count=updated_webhook.failure_count,
        success_rate=updated_webhook.get_success_rate()
    )


@webhook_router.delete("/{webhook_id}")
async def delete_webhook(
    webhook_id: str,
    current_user: User = Depends(require_webhook_permission(Permission.WEBHOOK_DELETE))
):
    """Delete webhook"""
    
    webhook = await webhook_service.get_webhook(webhook_id)
    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found"
        )
    
    # Check ownership
    if webhook.user_id != current_user.id and not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this webhook"
        )
    
    success = await webhook_service.delete_webhook(webhook_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to delete webhook"
        )
    
    return {"message": "Webhook deleted successfully"}


@webhook_router.post("/{webhook_id}/test", response_model=WebhookTestResponse)
async def test_webhook(
    webhook_id: str,
    current_user: User = Depends(require_webhook_permission(Permission.WEBHOOK_UPDATE))
):
    """Send test webhook delivery"""
    
    webhook = await webhook_service.get_webhook(webhook_id)
    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found"
        )
    
    # Check ownership
    if webhook.user_id != current_user.id and not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this webhook"
        )
    
    # Send test webhook
    result = await webhook_service.test_webhook(webhook_id)
    
    return WebhookTestResponse(
        delivery_id=result["delivery_id"],
        status_code=result["status_code"],
        success=result["success"],
        response=result["response"],
        error=result["error"]
    )


@webhook_router.get("/{webhook_id}/stats", response_model=WebhookStatsResponse)
async def get_webhook_stats(
    webhook_id: str,
    current_user: User = Depends(require_webhook_permission(Permission.WEBHOOK_READ))
):
    """Get webhook delivery statistics"""
    
    webhook = await webhook_service.get_webhook(webhook_id)
    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found"
        )
    
    # Check ownership
    if webhook.user_id != current_user.id and not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this webhook"
        )
    
    stats = await webhook_service.get_webhook_stats(webhook_id)
    if not stats:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook statistics not found"
        )
    
    return WebhookStatsResponse(**stats)


# Platform-specific webhook creation endpoints
@webhook_router.post("/slack", response_model=WebhookResponse)
async def create_slack_webhook(
    slack_data: SlackWebhookRequest,
    current_user: User = Depends(require_webhook_permission(Permission.WEBHOOK_CREATE))
):
    """Create Slack-specific webhook with proper formatting"""
    
    webhook_id = await webhook_service.create_slack_webhook(
        current_user.id,
        slack_data.name,
        str(slack_data.webhook_url),
        slack_data.events,
        slack_data.channel
    )
    
    webhook = await webhook_service.get_webhook(webhook_id)
    return WebhookResponse(
        id=webhook.id,
        name=webhook.name,
        url=webhook.url,
        events=[event.value for event in webhook.events],
        status=webhook.status.value,
        created_at=webhook.created_at.isoformat(),
        updated_at=webhook.updated_at.isoformat(),
        last_triggered=webhook.last_triggered.isoformat() if webhook.last_triggered else None,
        delivery_count=webhook.delivery_count,
        success_count=webhook.success_count,
        failure_count=webhook.failure_count,
        success_rate=webhook.get_success_rate()
    )


@webhook_router.post("/teams", response_model=WebhookResponse)
async def create_teams_webhook(
    teams_data: TeamsWebhookRequest,
    current_user: User = Depends(require_webhook_permission(Permission.WEBHOOK_CREATE))
):
    """Create Microsoft Teams-specific webhook"""
    
    webhook_id = await webhook_service.create_teams_webhook(
        current_user.id,
        teams_data.name,
        str(teams_data.webhook_url),
        teams_data.events
    )
    
    webhook = await webhook_service.get_webhook(webhook_id)
    return WebhookResponse(
        id=webhook.id,
        name=webhook.name,
        url=webhook.url,
        events=[event.value for event in webhook.events],
        status=webhook.status.value,
        created_at=webhook.created_at.isoformat(),
        updated_at=webhook.updated_at.isoformat(),
        last_triggered=webhook.last_triggered.isoformat() if webhook.last_triggered else None,
        delivery_count=webhook.delivery_count,
        success_count=webhook.success_count,
        failure_count=webhook.failure_count,
        success_rate=webhook.get_success_rate()
    )


@webhook_router.post("/discord", response_model=WebhookResponse)
async def create_discord_webhook(
    discord_data: DiscordWebhookRequest,
    current_user: User = Depends(require_webhook_permission(Permission.WEBHOOK_CREATE))
):
    """Create Discord-specific webhook"""
    
    webhook_id = await webhook_service.create_discord_webhook(
        current_user.id,
        discord_data.name,
        str(discord_data.webhook_url),
        discord_data.events
    )
    
    webhook = await webhook_service.get_webhook(webhook_id)
    return WebhookResponse(
        id=webhook.id,
        name=webhook.name,
        url=webhook.url,
        events=[event.value for event in webhook.events],
        status=webhook.status.value,
        created_at=webhook.created_at.isoformat(),
        updated_at=webhook.updated_at.isoformat(),
        last_triggered=webhook.last_triggered.isoformat() if webhook.last_triggered else None,
        delivery_count=webhook.delivery_count,
        success_count=webhook.success_count,
        failure_count=webhook.failure_count,
        success_rate=webhook.get_success_rate()
    )


@webhook_router.get("/events/types")
async def list_webhook_events():
    """List available webhook event types"""
    return {
        "events": [
            {
                "name": event.value,
                "description": {
                    WebhookEvent.SCAN_STARTED: "Triggered when a security scan starts",
                    WebhookEvent.SCAN_COMPLETED: "Triggered when a security scan completes successfully",
                    WebhookEvent.SCAN_FAILED: "Triggered when a security scan fails",
                    WebhookEvent.CRITICAL_FINDING: "Triggered when critical security issues are found",
                    WebhookEvent.HIGH_FINDING: "Triggered when high severity issues are found",
                    WebhookEvent.COMPLIANCE_CHANGE: "Triggered when compliance status changes"
                }.get(event, "No description available")
            }
            for event in WebhookEvent
        ]
    }