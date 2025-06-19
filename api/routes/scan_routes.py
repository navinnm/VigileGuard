"""Scan Management API Routes"""

import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Depends, status, BackgroundTasks
from pydantic import BaseModel, Field

from ..auth.rbac import RBACManager, Permission
from ..models.user import User
from ..models.scan import Scan, ScanStatus, ScanResult, SeverityLevel
from ..services.scan_service import ScanService
from ..services.webhook_service import WebhookService
from ..models.webhook import WebhookEvent
from .auth_routes import get_current_user


# Pydantic models for API requests/responses
class ScanCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    target: str = Field(..., min_length=1, max_length=255)
    checkers: List[str] = Field(default_factory=list)
    config: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ScanResponse(BaseModel):
    id: str
    name: str
    target: str
    status: str
    created_by: str
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration: Optional[float] = None
    checkers: List[str]
    tags: List[str]
    summary: Dict[str, int]
    metadata: Dict[str, Any]
    error_message: Optional[str] = None


class ScanResultResponse(BaseModel):
    check_id: str
    check_name: str
    severity: str
    status: str
    message: str
    details: Dict[str, Any]
    remediation: Optional[str] = None
    references: List[str]


class ScanDetailResponse(BaseModel):
    id: str
    name: str
    target: str
    status: str
    created_by: str
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    duration: Optional[float] = None
    checkers: List[str]
    config: Dict[str, Any]
    tags: List[str]
    summary: Dict[str, int]
    results: List[ScanResultResponse]
    metadata: Dict[str, Any]
    error_message: Optional[str] = None


# Initialize components
scan_router = APIRouter(prefix="/scans", tags=["scans"])
scan_service = ScanService()
webhook_service = WebhookService()
rbac_manager = RBACManager()


def require_scan_permission(permission: Permission):
    """Dependency to check scan permissions"""
    def permission_checker(current_user: User = Depends(get_current_user)) -> User:
        if not rbac_manager.has_permission(current_user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission.value}"
            )
        return current_user
    return permission_checker


async def trigger_scan_webhooks(event: WebhookEvent, scan_data: Dict[str, Any]):
    """Helper to trigger webhook events for scans"""
    try:
        await webhook_service.trigger_webhook_event(event, {"scan": scan_data})
    except Exception as e:
        # Log error but don't fail the scan
        print(f"Webhook error: {e}")


@scan_router.post("/", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_scan_permission(Permission.SCAN_CREATE))
):
    """Create a new security scan"""
    
    # Create scan object
    scan = Scan(
        id=f"scan_{uuid.uuid4().hex}",
        name=scan_data.name,
        target=scan_data.target,
        status=ScanStatus.PENDING,
        created_by=current_user.id,
        created_at=datetime.utcnow(),
        checkers=scan_data.checkers or ["all"],
        config=scan_data.config,
        tags=scan_data.tags,
        metadata=scan_data.metadata
    )
    
    # Store scan
    scan_id = await scan_service.create_scan(scan)
    
    # Trigger webhook
    background_tasks.add_task(
        trigger_scan_webhooks,
        WebhookEvent.SCAN_STARTED,
        {
            "id": scan.id,
            "name": scan.name,
            "target": scan.target,
            "status": scan.status.value,
            "created_by": scan.created_by,
            "created_at": scan.created_at.isoformat()
        }
    )
    
    return ScanResponse(
        id=scan.id,
        name=scan.name,
        target=scan.target,
        status=scan.status.value,
        created_by=scan.created_by,
        created_at=scan.created_at.isoformat(),
        checkers=scan.checkers,
        tags=scan.tags,
        summary=scan.summary,
        metadata=scan.metadata
    )


@scan_router.get("/", response_model=List[ScanResponse])
async def list_scans(
    limit: int = 50,
    offset: int = 0,
    status: Optional[ScanStatus] = None,
    created_by: Optional[str] = None,
    current_user: User = Depends(require_scan_permission(Permission.SCAN_READ))
):
    """List security scans"""
    
    filters = {}
    if status:
        filters["status"] = status
    if created_by and (created_by == current_user.id or rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN)):
        filters["created_by"] = created_by
    elif not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        filters["created_by"] = current_user.id  # Users can only see their own scans
    
    scans = await scan_service.list_scans(limit, offset, filters)
    
    return [
        ScanResponse(
            id=scan.id,
            name=scan.name,
            target=scan.target,
            status=scan.status.value,
            created_by=scan.created_by,
            created_at=scan.created_at.isoformat(),
            started_at=scan.started_at.isoformat() if scan.started_at else None,
            completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
            duration=scan.duration,
            checkers=scan.checkers,
            tags=scan.tags,
            summary=scan.summary,
            metadata=scan.metadata,
            error_message=scan.error_message
        )
        for scan in scans
    ]


@scan_router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: str,
    current_user: User = Depends(require_scan_permission(Permission.SCAN_READ))
):
    """Get scan details with results"""
    
    scan = await scan_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Check ownership or admin access
    if scan.created_by != current_user.id and not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this scan"
        )
    
    return ScanDetailResponse(
        id=scan.id,
        name=scan.name,
        target=scan.target,
        status=scan.status.value,
        created_by=scan.created_by,
        created_at=scan.created_at.isoformat(),
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        duration=scan.duration,
        checkers=scan.checkers,
        config=scan.config,
        tags=scan.tags,
        summary=scan.summary,
        results=[
            ScanResultResponse(
                check_id=result.check_id,
                check_name=result.check_name,
                severity=result.severity.value,
                status=result.status,
                message=result.message,
                details=result.details,
                remediation=result.remediation,
                references=result.references
            )
            for result in scan.results
        ],
        metadata=scan.metadata,
        error_message=scan.error_message
    )


@scan_router.post("/{scan_id}/run")
async def run_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_scan_permission(Permission.SCAN_RUN))
):
    """Start scan execution"""
    
    scan = await scan_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Check ownership or run permission
    if scan.created_by != current_user.id and not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to run this scan"
        )
    
    # Check if scan can be started
    if scan.status not in [ScanStatus.PENDING, ScanStatus.FAILED]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot start scan in {scan.status.value} status"
        )
    
    # Start scan execution
    success = await scan_service.start_scan(scan_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to start scan"
        )
    
    # Add background task to execute scan
    background_tasks.add_task(execute_scan_background, scan_id)
    
    return {"message": "Scan started successfully", "scan_id": scan_id}


@scan_router.delete("/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user: User = Depends(require_scan_permission(Permission.SCAN_DELETE))
):
    """Delete a scan"""
    
    scan = await scan_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Check ownership or admin access
    if scan.created_by != current_user.id and not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to delete this scan"
        )
    
    # Cannot delete running scans
    if scan.status == ScanStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete running scan"
        )
    
    success = await scan_service.delete_scan(scan_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to delete scan"
        )
    
    return {"message": "Scan deleted successfully"}


@scan_router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    current_user: User = Depends(require_scan_permission(Permission.SCAN_RUN))
):
    """Cancel a running scan"""
    
    scan = await scan_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Check ownership or admin access
    if scan.created_by != current_user.id and not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to cancel this scan"
        )
    
    # Can only cancel running scans
    if scan.status != ScanStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan in {scan.status.value} status"
        )
    
    success = await scan_service.cancel_scan(scan_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to cancel scan"
        )
    
    return {"message": "Scan cancelled successfully"}


@scan_router.get("/{scan_id}/results", response_model=List[ScanResultResponse])
async def get_scan_results(
    scan_id: str,
    severity: Optional[SeverityLevel] = None,
    status_filter: Optional[str] = None,
    current_user: User = Depends(require_scan_permission(Permission.SCAN_READ))
):
    """Get scan results with optional filtering"""
    
    scan = await scan_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Check ownership or admin access
    if scan.created_by != current_user.id and not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this scan"
        )
    
    results = scan.results
    
    # Apply filters
    if severity:
        results = [r for r in results if r.severity == severity]
    if status_filter:
        results = [r for r in results if r.status == status_filter]
    
    return [
        ScanResultResponse(
            check_id=result.check_id,
            check_name=result.check_name,
            severity=result.severity.value,
            status=result.status,
            message=result.message,
            details=result.details,
            remediation=result.remediation,
            references=result.references
        )
        for result in results
    ]


@scan_router.get("/{scan_id}/summary")
async def get_scan_summary(
    scan_id: str,
    current_user: User = Depends(require_scan_permission(Permission.SCAN_READ))
):
    """Get scan summary statistics"""
    
    scan = await scan_service.get_scan(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Check ownership or admin access
    if scan.created_by != current_user.id and not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this scan"
        )
    
    return {
        "scan_id": scan.id,
        "name": scan.name,
        "target": scan.target,
        "status": scan.status.value,
        "summary": scan.summary,
        "compliance_score": scan.get_compliance_score(),
        "is_critical": scan.is_critical(),
        "is_high_risk": scan.is_high_risk(),
        "duration": scan.duration,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
    }


async def execute_scan_background(scan_id: str):
    """Background task to execute security scan"""
    try:
        # Execute the actual scan
        success = await scan_service.execute_scan(scan_id)
        
        # Get updated scan
        scan = await scan_service.get_scan(scan_id)
        if not scan:
            return
        
        # Prepare webhook data
        webhook_data = {
            "id": scan.id,
            "name": scan.name,
            "target": scan.target,
            "status": scan.status.value,
            "summary": scan.summary,
            "compliance_score": scan.get_compliance_score(),
            "duration": scan.duration,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None
        }
        
        # Trigger appropriate webhook events
        if success and scan.status == ScanStatus.COMPLETED:
            await trigger_scan_webhooks(WebhookEvent.SCAN_COMPLETED, webhook_data)
            
            # Check for critical/high findings
            if scan.is_critical():
                await trigger_scan_webhooks(WebhookEvent.CRITICAL_FINDING, webhook_data)
            elif scan.is_high_risk():
                await trigger_scan_webhooks(WebhookEvent.HIGH_FINDING, webhook_data)
        
        elif scan.status == ScanStatus.FAILED:
            await trigger_scan_webhooks(WebhookEvent.SCAN_FAILED, webhook_data)
    
    except Exception as e:
        # Log error and update scan status
        print(f"Scan execution error: {e}")
        await scan_service.fail_scan(scan_id, str(e))