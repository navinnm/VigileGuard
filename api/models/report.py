"""Report Models"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


class ReportFormat(Enum):
    """Report output formats"""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    CSV = "csv"
    XML = "xml"


class ReportStatus(Enum):
    """Report generation status"""
    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    PCI_DSS = "pci_dss"
    SOC2 = "soc2"
    ISO_27001 = "iso_27001"
    NIST = "nist"
    CIS = "cis"
    GDPR = "gdpr"


@dataclass
class ReportSection:
    """Individual report section"""
    id: str
    title: str
    content: str
    data: Dict[str, Any] = field(default_factory=dict)
    charts: List[Dict[str, Any]] = field(default_factory=list)
    order: int = 0


@dataclass
class ComplianceMapping:
    """Compliance framework mapping"""
    framework: ComplianceFramework
    control_id: str
    control_name: str
    status: str  # COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE
    findings: List[str] = field(default_factory=list)
    score: float = 0.0


@dataclass
class Report:
    """Security report model"""
    id: str
    name: str
    scan_ids: List[str]
    format: ReportFormat
    status: ReportStatus
    created_by: str
    created_at: datetime
    
    # Generation metadata
    generated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    download_url: Optional[str] = None
    
    # Report configuration
    template: str = "default"
    sections: List[str] = field(default_factory=list)
    filters: Dict[str, Any] = field(default_factory=dict)
    
    # Content
    executive_summary: str = ""
    sections_data: List[ReportSection] = field(default_factory=list)
    compliance_mappings: List[ComplianceMapping] = field(default_factory=list)
    
    # Statistics
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    
    def add_section(self, section: ReportSection) -> None:
        """Add section to report"""
        self.sections_data.append(section)
        self.sections_data.sort(key=lambda x: x.order)
    
    def get_compliance_score(self, framework: ComplianceFramework) -> float:
        """Get compliance score for specific framework"""
        mappings = [m for m in self.compliance_mappings if m.framework == framework]
        if not mappings:
            return 0.0
        
        total_score = sum(m.score for m in mappings)
        return total_score / len(mappings)
    
    def get_risk_level(self) -> str:
        """Determine overall risk level based on findings"""
        if self.critical_findings > 0:
            return "CRITICAL"
        elif self.high_findings > 0:
            return "HIGH"
        elif self.medium_findings > 0:
            return "MEDIUM"
        elif self.low_findings > 0:
            return "LOW"
        else:
            return "CLEAN"
    
    def is_ready_for_download(self) -> bool:
        """Check if report is ready for download"""
        return (self.status == ReportStatus.COMPLETED and 
                self.file_path is not None and
                (self.expires_at is None or self.expires_at > datetime.utcnow()))
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get report summary statistics"""
        return {
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "low_findings": self.low_findings,
            "risk_level": self.get_risk_level(),
            "scans_included": len(self.scan_ids),
            "compliance_frameworks": len(set(m.framework for m in self.compliance_mappings))
        }