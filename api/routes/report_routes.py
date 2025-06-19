"""Report Generation and Export API Routes"""

import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Depends, status, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from ..auth.rbac import RBACManager, Permission
from ..models.user import User
from ..models.report import Report, ReportFormat, ReportStatus, ComplianceFramework
from ..services.report_service import ReportService
from .auth_routes import get_current_user


# Pydantic models for API requests/responses
class ReportCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    scan_ids: List[str] = Field(..., min_items=1)
    format: ReportFormat = ReportFormat.JSON
    template: str = Field("default", min_length=1)
    sections: List[str] = Field(default_factory=list)
    filters: Dict[str, Any] = Field(default_factory=dict)
    compliance_frameworks: List[ComplianceFramework] = Field(default_factory=list)


class ReportResponse(BaseModel):
    id: str
    name: str
    scan_ids: List[str]
    format: str
    status: str
    created_by: str
    created_at: str
    generated_at: Optional[str] = None
    expires_at: Optional[str] = None
    file_size: Optional[int] = None
    download_url: Optional[str] = None
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int


class ReportExportRequest(BaseModel):
    scan_ids: List[str] = Field(..., min_items=1)
    format: ReportFormat
    template: Optional[str] = "default"
    filters: Dict[str, Any] = Field(default_factory=dict)
    compliance_frameworks: List[ComplianceFramework] = Field(default_factory=list)


# Initialize components
report_router = APIRouter(prefix="/reports", tags=["reports"])
report_service = ReportService()
rbac_manager = RBACManager()


def require_report_permission(permission: Permission):
    """Dependency to check report permissions"""
    def permission_checker(current_user: User = Depends(get_current_user)) -> User:
        if not rbac_manager.has_permission(current_user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission.value}"
            )
        return current_user
    return permission_checker


@report_router.post("/", response_model=ReportResponse)
async def create_report(
    report_data: ReportCreateRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_report_permission(Permission.REPORT_CREATE))
):
    """Create a new report"""
    
    # Create report object
    report = Report(
        id=f"report_{uuid.uuid4().hex}",
        name=report_data.name,
        scan_ids=report_data.scan_ids,
        format=report_data.format,
        status=ReportStatus.PENDING,
        created_by=current_user.id,
        created_at=datetime.utcnow(),
        template=report_data.template,
        sections=report_data.sections,
        filters=report_data.filters
    )
    
    # Store report
    report_id = await report_service.create_report(report)
    
    # Start report generation in background
    background_tasks.add_task(generate_report_background, report_id)
    
    return ReportResponse(
        id=report.id,
        name=report.name,
        scan_ids=report.scan_ids,
        format=report.format.value,
        status=report.status.value,
        created_by=report.created_by,
        created_at=report.created_at.isoformat(),
        total_findings=report.total_findings,
        critical_findings=report.critical_findings,
        high_findings=report.high_findings,
        medium_findings=report.medium_findings,
        low_findings=report.low_findings
    )


@report_router.get("/", response_model=List[ReportResponse])
async def list_reports(
    limit: int = 50,
    offset: int = 0,
    format_filter: Optional[ReportFormat] = None,
    status_filter: Optional[ReportStatus] = None,
    current_user: User = Depends(require_report_permission(Permission.REPORT_READ))
):
    """List reports"""
    
    filters = {}
    if format_filter:
        filters["format"] = format_filter
    if status_filter:
        filters["status"] = status_filter
    
    # Users can only see their own reports unless admin
    if not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        filters["created_by"] = current_user.id
    
    reports = await report_service.list_reports(limit, offset, filters)
    
    return [
        ReportResponse(
            id=report.id,
            name=report.name,
            scan_ids=report.scan_ids,
            format=report.format.value,
            status=report.status.value,
            created_by=report.created_by,
            created_at=report.created_at.isoformat(),
            generated_at=report.generated_at.isoformat() if report.generated_at else None,
            expires_at=report.expires_at.isoformat() if report.expires_at else None,
            file_size=report.file_size,
            download_url=report.download_url,
            total_findings=report.total_findings,
            critical_findings=report.critical_findings,
            high_findings=report.high_findings,
            medium_findings=report.medium_findings,
            low_findings=report.low_findings
        )
        for report in reports
    ]


@report_router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: str,
    current_user: User = Depends(require_report_permission(Permission.REPORT_READ))
):
    """Get report details"""
    
    report = await report_service.get_report(report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Check ownership or admin access
    if report.created_by != current_user.id and not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this report"
        )
    
    return ReportResponse(
        id=report.id,
        name=report.name,
        scan_ids=report.scan_ids,
        format=report.format.value,
        status=report.status.value,
        created_by=report.created_by,
        created_at=report.created_at.isoformat(),
        generated_at=report.generated_at.isoformat() if report.generated_at else None,
        expires_at=report.expires_at.isoformat() if report.expires_at else None,
        file_size=report.file_size,
        download_url=report.download_url,
        total_findings=report.total_findings,
        critical_findings=report.critical_findings,
        high_findings=report.high_findings,
        medium_findings=report.medium_findings,
        low_findings=report.low_findings
    )


@report_router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    current_user: User = Depends(require_report_permission(Permission.REPORT_READ))
):
    """Download report file"""
    
    report = await report_service.get_report(report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Check ownership or admin access
    if report.created_by != current_user.id and not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this report"
        )
    
    # Check if report is ready for download
    if not report.is_ready_for_download():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Report is not ready for download"
        )
    
    # Return file
    filename = f"{report.name}.{report.format.value}"
    return FileResponse(
        path=report.file_path,
        filename=filename,
        media_type="application/octet-stream"
    )


@report_router.post("/export")
async def export_report(
    export_data: ReportExportRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_report_permission(Permission.REPORT_EXPORT))
):
    """Quick report export without storing"""
    
    # Create temporary report
    report = Report(
        id=f"export_{uuid.uuid4().hex}",
        name=f"Export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
        scan_ids=export_data.scan_ids,
        format=export_data.format,
        status=ReportStatus.PENDING,
        created_by=current_user.id,
        created_at=datetime.utcnow(),
        template=export_data.template or "default",
        filters=export_data.filters
    )
    
    # Generate report synchronously for export
    success = await report_service.generate_report(report.id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate report"
        )
    
    # Return file immediately
    filename = f"{report.name}.{report.format.value}"
    return FileResponse(
        path=report.file_path,
        filename=filename,
        media_type="application/octet-stream"
    )


@report_router.delete("/{report_id}")
async def delete_report(
    report_id: str,
    current_user: User = Depends(require_report_permission(Permission.REPORT_DELETE))
):
    """Delete a report"""
    
    report = await report_service.get_report(report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Check ownership or admin access
    if report.created_by != current_user.id and not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to delete this report"
        )
    
    success = await report_service.delete_report(report_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to delete report"
        )
    
    return {"message": "Report deleted successfully"}


@report_router.get("/{report_id}/compliance/{framework}")
async def get_compliance_report(
    report_id: str,
    framework: ComplianceFramework,
    current_user: User = Depends(require_report_permission(Permission.REPORT_READ))
):
    """Get compliance-specific report view"""
    
    report = await report_service.get_report(report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found"
        )
    
    # Check ownership or admin access
    if report.created_by != current_user.id and not rbac_manager.has_permission(current_user.role, Permission.SYSTEM_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this report"
        )
    
    compliance_score = report.get_compliance_score(framework)
    compliance_mappings = [
        {
            "framework": mapping.framework.value,
            "control_id": mapping.control_id,
            "control_name": mapping.control_name,
            "status": mapping.status,
            "score": mapping.score,
            "findings": mapping.findings
        }
        for mapping in report.compliance_mappings
        if mapping.framework == framework
    ]
    
    return {
        "report_id": report_id,
        "framework": framework.value,
        "compliance_score": compliance_score,
        "total_controls": len(compliance_mappings),
        "compliant_controls": len([m for m in compliance_mappings if m["status"] == "COMPLIANT"]),
        "non_compliant_controls": len([m for m in compliance_mappings if m["status"] == "NON_COMPLIANT"]),
        "mappings": compliance_mappings
    }


@report_router.get("/templates/")
async def list_report_templates():
    """List available report templates"""
    
    templates = await report_service.list_templates()
    return {"templates": templates}


@report_router.get("/formats/")
async def list_report_formats():
    """List supported report formats"""
    
    return {
        "formats": [
            {
                "value": fmt.value,
                "name": fmt.name,
                "description": {
                    ReportFormat.JSON: "Machine-readable JSON format",
                    ReportFormat.HTML: "Interactive HTML report",
                    ReportFormat.PDF: "Printable PDF document",
                    ReportFormat.CSV: "Comma-separated values for spreadsheets",
                    ReportFormat.XML: "Structured XML format"
                }.get(fmt, "No description available")
            }
            for fmt in ReportFormat
        ]
    }


async def generate_report_background(report_id: str):
    """Background task to generate report"""
    try:
        success = await report_service.generate_report(report_id)
        if not success:
            await report_service.fail_report(report_id, "Report generation failed")
    except Exception as e:
        await report_service.fail_report(report_id, str(e))