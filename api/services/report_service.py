"""Report Service for generating and managing security reports"""

import json
import os
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import logging

from ..models.report import Report, ReportFormat, ReportStatus, ComplianceFramework, ReportSection
from ..models.scan import Scan


logger = logging.getLogger(__name__)


class ReportService:
    """Service for managing security report generation and lifecycle"""
    
    def __init__(self):
        self.reports: Dict[str, Report] = {}
        self.report_templates = {
            "default": "Standard security report template",
            "executive": "Executive summary template",
            "technical": "Detailed technical report",
            "compliance": "Compliance-focused report"
        }
    
    async def create_report(self, report: Report) -> str:
        """Create and store a new report"""
        self.reports[report.id] = report
        logger.info(f"Created report: {report.name} ({report.id})")
        return report.id
    
    async def get_report(self, report_id: str) -> Optional[Report]:
        """Get report by ID"""
        return self.reports.get(report_id)
    
    async def list_reports(self, limit: int = 50, offset: int = 0,
                          filters: Optional[Dict[str, Any]] = None) -> List[Report]:
        """List reports with pagination and filtering"""
        reports = list(self.reports.values())
        
        # Apply filters
        if filters:
            for key, value in filters.items():
                if key == "format" and isinstance(value, ReportFormat):
                    reports = [r for r in reports if r.format == value]
                elif key == "status" and isinstance(value, ReportStatus):
                    reports = [r for r in reports if r.status == value]
                elif key == "created_by":
                    reports = [r for r in reports if r.created_by == value]
                elif hasattr(Report, key):
                    reports = [r for r in reports if getattr(r, key) == value]
        
        # Sort by creation time (newest first)
        reports.sort(key=lambda r: r.created_at, reverse=True)
        
        # Apply pagination
        return reports[offset:offset + limit]
    
    async def generate_report(self, report_id: str) -> bool:
        """Generate report content and file"""
        report = self.reports.get(report_id)
        if not report:
            return False
        
        try:
            report.status = ReportStatus.GENERATING
            
            # Mock scan data for demo (replace with actual scan service integration)
            scan_data = self._get_mock_scan_data(report.scan_ids)
            
            # Process scan data
            await self._process_scan_data(report, scan_data)
            
            # Generate report content
            content = await self._generate_report_content(report, scan_data)
            
            # Save report file
            file_path = await self._save_report_file(report, content)
            
            # Update report
            report.status = ReportStatus.COMPLETED
            report.generated_at = datetime.utcnow()
            report.expires_at = datetime.utcnow() + timedelta(days=30)  # 30 day expiry
            report.file_path = file_path
            report.file_size = os.path.getsize(file_path) if file_path else None
            report.download_url = f"/api/v1/reports/{report_id}/download"
            
            logger.info(f"Generated report: {report.name} ({report_id})")
            return True
        
        except Exception as e:
            report.status = ReportStatus.FAILED
            report.error_message = str(e)
            logger.error(f"Report generation failed: {report.name} ({report_id}) - {str(e)}")
            return False
    
    def _get_mock_scan_data(self, scan_ids: List[str]) -> List[Dict[str, Any]]:
        """Get mock scan data for demo purposes"""
        mock_scans = []
        
        for scan_id in scan_ids:
            mock_scans.append({
                "id": scan_id,
                "name": f"Security Scan {scan_id[-8:]}",
                "target": "demo.vigileguard.local",
                "status": "completed",
                "created_at": datetime.utcnow().isoformat(),
                "completed_at": datetime.utcnow().isoformat(),
                "summary": {
                    "critical": 2,
                    "high": 5,
                    "medium": 12,
                    "low": 8,
                    "total": 27,
                    "passed": 15,
                    "failed": 27
                },
                "results": [
                    {
                        "check_id": "ssh_config",
                        "check_name": "SSH Configuration",
                        "severity": "medium",
                        "status": "PASS",
                        "message": "SSH configuration is secure"
                    },
                    {
                        "check_id": "firewall_status",
                        "check_name": "Firewall Status",
                        "severity": "critical",
                        "status": "FAIL",
                        "message": "Firewall is not enabled"
                    },
                    {
                        "check_id": "file_permissions",
                        "check_name": "File Permissions",
                        "severity": "high",
                        "status": "FAIL",
                        "message": "Found world-writable files"
                    }
                ]
            })
        
        return mock_scans
    
    async def _process_scan_data(self, report: Report, scan_data: List[Dict[str, Any]]):
        """Process scan data and update report statistics"""
        total_findings = 0
        critical_findings = 0
        high_findings = 0
        medium_findings = 0
        low_findings = 0
        
        for scan in scan_data:
            summary = scan.get("summary", {})
            critical_findings += summary.get("critical", 0)
            high_findings += summary.get("high", 0)
            medium_findings += summary.get("medium", 0)
            low_findings += summary.get("low", 0)
            total_findings += summary.get("failed", 0)
        
        report.total_findings = total_findings
        report.critical_findings = critical_findings
        report.high_findings = high_findings
        report.medium_findings = medium_findings
        report.low_findings = low_findings
        
        # Generate executive summary
        report.executive_summary = self._generate_executive_summary(report, scan_data)
        
        # Add compliance mappings
        await self._add_compliance_mappings(report, scan_data)
    
    def _generate_executive_summary(self, report: Report, scan_data: List[Dict[str, Any]]) -> str:
        """Generate executive summary"""
        risk_level = report.get_risk_level()
        scan_count = len(scan_data)
        
        summary = f"""
# Executive Summary

This security assessment report covers {scan_count} security scan{'s' if scan_count != 1 else ''} 
conducted on the specified infrastructure components.

## Key Findings

- **Total Security Issues**: {report.total_findings}
- **Critical Issues**: {report.critical_findings}
- **High Severity Issues**: {report.high_findings}
- **Medium Severity Issues**: {report.medium_findings}
- **Low Severity Issues**: {report.low_findings}

## Risk Assessment

**Overall Risk Level**: {risk_level}

"""
        
        if report.critical_findings > 0:
            summary += f"⚠️ **IMMEDIATE ACTION REQUIRED**: {report.critical_findings} critical security issues require immediate attention.\n\n"
        
        if report.high_findings > 0:
            summary += f"⚠️ **HIGH PRIORITY**: {report.high_findings} high severity issues should be addressed promptly.\n\n"
        
        if report.critical_findings == 0 and report.high_findings == 0:
            summary += "✅ No critical or high severity issues were identified.\n\n"
        
        summary += """
## Recommendations

1. Address all critical and high severity findings as priority
2. Implement regular security scanning in CI/CD pipeline
3. Review and update security policies based on findings
4. Consider implementing additional security controls

For detailed findings and remediation steps, please review the complete report sections below.
"""
        
        return summary.strip()
    
    async def _add_compliance_mappings(self, report: Report, scan_data: List[Dict[str, Any]]):
        """Add compliance framework mappings"""
        # This would typically map scan results to compliance controls
        # For demo purposes, we'll add some mock mappings
        
        from ..models.report import ComplianceMapping
        
        # PCI DSS mappings
        report.compliance_mappings.append(ComplianceMapping(
            framework=ComplianceFramework.PCI_DSS,
            control_id="2.2.1",
            control_name="Configure system security parameters",
            status="NON_COMPLIANT" if report.critical_findings > 0 else "COMPLIANT",
            findings=["Firewall configuration issues"] if report.critical_findings > 0 else [],
            score=85.0 if report.critical_findings == 0 else 65.0
        ))
        
        # SOC 2 mappings
        report.compliance_mappings.append(ComplianceMapping(
            framework=ComplianceFramework.SOC2,
            control_id="CC6.1",
            control_name="Logical and physical access controls",
            status="COMPLIANT" if report.high_findings == 0 else "NON_COMPLIANT",
            findings=["File permission issues"] if report.high_findings > 0 else [],
            score=90.0 if report.high_findings == 0 else 70.0
        ))
    
    async def _generate_report_content(self, report: Report, scan_data: List[Dict[str, Any]]) -> Any:
        """Generate report content based on format"""
        
        if report.format == ReportFormat.JSON:
            return self._generate_json_report(report, scan_data)
        elif report.format == ReportFormat.HTML:
            return self._generate_html_report(report, scan_data)
        elif report.format == ReportFormat.CSV:
            return self._generate_csv_report(report, scan_data)
        else:
            # Default to JSON
            return self._generate_json_report(report, scan_data)
    
    def _generate_json_report(self, report: Report, scan_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate JSON format report"""
        return {
            "report_info": {
                "id": report.id,
                "name": report.name,
                "generated_at": report.generated_at.isoformat() if report.generated_at else None,
                "template": report.template,
                "format": report.format.value
            },
            "executive_summary": report.executive_summary,
            "statistics": {
                "total_findings": report.total_findings,
                "critical_findings": report.critical_findings,
                "high_findings": report.high_findings,
                "medium_findings": report.medium_findings,
                "low_findings": report.low_findings,
                "risk_level": report.get_risk_level(),
                "scans_included": len(scan_data)
            },
            "compliance": [
                {
                    "framework": mapping.framework.value,
                    "control_id": mapping.control_id,
                    "control_name": mapping.control_name,
                    "status": mapping.status,
                    "score": mapping.score
                }
                for mapping in report.compliance_mappings
            ],
            "scans": scan_data,
            "metadata": report.metadata
        }
    
    def _generate_html_report(self, report: Report, scan_data: List[Dict[str, Any]]) -> str:
        """Generate HTML format report"""
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>VigileGuard Security Report - {report.name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ border-bottom: 2px solid #333; padding-bottom: 20px; }}
        .summary {{ background: #f5f5f5; padding: 20px; margin: 20px 0; }}
        .finding {{ margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
        .compliance {{ margin: 20px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ VigileGuard Security Report</h1>
        <h2>{report.name}</h2>
        <p><strong>Generated:</strong> {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC') if report.generated_at else 'N/A'}</p>
        <p><strong>Risk Level:</strong> <span style="color: {'red' if report.get_risk_level() == 'CRITICAL' else 'orange' if report.get_risk_level() == 'HIGH' else 'green'}">{report.get_risk_level()}</span></p>
    </div>
    
    <div class="summary">
        <h3>📊 Summary Statistics</h3>
        <ul>
            <li><strong>Total Issues:</strong> {report.total_findings}</li>
            <li><strong>Critical:</strong> <span style="color: red">{report.critical_findings}</span></li>
            <li><strong>High:</strong> <span style="color: orange">{report.high_findings}</span></li>
            <li><strong>Medium:</strong> <span style="color: #ffc107">{report.medium_findings}</span></li>
            <li><strong>Low:</strong> <span style="color: green">{report.low_findings}</span></li>
        </ul>
    </div>
    
    <div>
        <h3>📋 Executive Summary</h3>
        <pre>{report.executive_summary}</pre>
    </div>
    
    <div class="compliance">
        <h3>✅ Compliance Status</h3>
        <table>
            <tr>
                <th>Framework</th>
                <th>Control</th>
                <th>Status</th>
                <th>Score</th>
            </tr>
"""
        
        for mapping in report.compliance_mappings:
            status_color = "green" if mapping.status == "COMPLIANT" else "red"
            html_content += f"""
            <tr>
                <td>{mapping.framework.value.upper()}</td>
                <td>{mapping.control_id} - {mapping.control_name}</td>
                <td style="color: {status_color}">{mapping.status}</td>
                <td>{mapping.score:.1f}%</td>
            </tr>
"""
        
        html_content += """
        </table>
    </div>
    
    <div>
        <h3>🔍 Detailed Findings</h3>
"""
        
        for scan in scan_data:
            html_content += f"""
        <h4>Scan: {scan['name']} ({scan['target']})</h4>
"""
            for result in scan.get('results', []):
                severity_class = result['severity'].lower()
                html_content += f"""
        <div class="finding {severity_class}">
            <strong>{result['check_name']}</strong> 
            <span style="float: right; color: {'red' if result['status'] == 'FAIL' else 'green'}">{result['status']}</span>
            <br>
            <small>Severity: {result['severity'].upper()}</small>
            <p>{result['message']}</p>
        </div>
"""
        
        html_content += """
    </div>
    
    <div style="margin-top: 40px; font-size: 12px; color: #666;">
        <p>Generated by VigileGuard Security Audit Engine v3.0.5</p>
    </div>
</body>
</html>
"""
        
        return html_content
    
    def _generate_csv_report(self, report: Report, scan_data: List[Dict[str, Any]]) -> str:
        """Generate CSV format report"""
        
        csv_content = "Scan ID,Scan Name,Target,Check ID,Check Name,Severity,Status,Message\n"
        
        for scan in scan_data:
            for result in scan.get('results', []):
                csv_content += f'"{scan["id"]}","{scan["name"]}","{scan["target"]}","{result["check_id"]}","{result["check_name"]}","{result["severity"]}","{result["status"]}","{result["message"]}"\n'
        
        return csv_content
    
    async def _save_report_file(self, report: Report, content: Any) -> str:
        """Save report content to file"""
        
        # Create reports directory
        reports_dir = "/tmp/vigileguard_reports"
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generate filename
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"{report.id}_{timestamp}.{report.format.value}"
        file_path = os.path.join(reports_dir, filename)
        
        # Save content based on format
        if report.format == ReportFormat.JSON:
            with open(file_path, 'w') as f:
                json.dump(content, f, indent=2)
        else:
            # Text-based formats (HTML, CSV, etc.)
            with open(file_path, 'w') as f:
                f.write(str(content))
        
        return file_path
    
    async def delete_report(self, report_id: str) -> bool:
        """Delete a report and its file"""
        
        report = self.reports.get(report_id)
        if not report:
            return False
        
        # Delete file if it exists
        if report.file_path and os.path.exists(report.file_path):
            try:
                os.unlink(report.file_path)
            except Exception as e:
                logger.warning(f"Failed to delete report file: {e}")
        
        # Remove from storage
        del self.reports[report_id]
        logger.info(f"Deleted report: {report.name} ({report_id})")
        return True
    
    async def fail_report(self, report_id: str, error_message: str):
        """Mark report as failed"""
        
        report = self.reports.get(report_id)
        if not report:
            return
        
        report.status = ReportStatus.FAILED
        report.error_message = error_message
        logger.error(f"Failed report: {report.name} ({report_id}) - {error_message}")
    
    async def list_templates(self) -> List[Dict[str, str]]:
        """List available report templates"""
        
        return [
            {"name": name, "description": description}
            for name, description in self.report_templates.items()
        ]
    
    async def cleanup_expired_reports(self) -> int:
        """Clean up expired reports"""
        
        expired_count = 0
        now = datetime.utcnow()
        
        for report_id in list(self.reports.keys()):
            report = self.reports[report_id]
            if report.expires_at and report.expires_at < now:
                await self.delete_report(report_id)
                expired_count += 1
        
        return expired_count