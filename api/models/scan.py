"""Scan Management Models"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


class ScanStatus(Enum):
    """Scan execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(Enum):
    """Security issue severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ScanResult:
    """Individual security check result"""
    check_id: str
    check_name: str
    severity: SeverityLevel
    status: str  # PASS, FAIL, WARN, SKIP
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)


@dataclass
class Scan:
    """Security scan model"""
    id: str
    name: str
    target: str  # hostname, IP, or URL
    status: ScanStatus
    created_by: str  # user_id
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration: Optional[float] = None  # seconds
    
    # Configuration
    config: Dict[str, Any] = field(default_factory=dict)
    checkers: List[str] = field(default_factory=list)  # enabled checker modules
    
    # Results
    results: List[ScanResult] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)  # severity counts
    error_message: Optional[str] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    
    def add_result(self, result: ScanResult) -> None:
        """Add scan result and update summary"""
        self.results.append(result)
        self._update_summary()
    
    def _update_summary(self) -> None:
        """Update severity summary counts"""
        self.summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "total": 0,
            "passed": 0,
            "failed": 0
        }
        
        for result in self.results:
            self.summary["total"] += 1
            if result.status == "FAIL":
                self.summary["failed"] += 1
                self.summary[result.severity.value] += 1
            elif result.status == "PASS":
                self.summary["passed"] += 1
    
    def get_findings_by_severity(self, severity: SeverityLevel) -> List[ScanResult]:
        """Get all findings of specific severity"""
        return [r for r in self.results if r.severity == severity and r.status == "FAIL"]
    
    def is_critical(self) -> bool:
        """Check if scan found critical issues"""
        return self.summary.get("critical", 0) > 0
    
    def is_high_risk(self) -> bool:
        """Check if scan found high severity issues"""
        return self.summary.get("high", 0) > 0 or self.is_critical()
    
    def get_compliance_score(self) -> float:
        """Calculate compliance score (0-100)"""
        if self.summary.get("total", 0) == 0:
            return 100.0
        
        passed = self.summary.get("passed", 0)
        total = self.summary.get("total", 0)
        return (passed / total) * 100.0