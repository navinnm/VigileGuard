#!/usr/bin/env python3
"""
VigileGuard - Linux Security Audit Tool
========================================

A comprehensive security audit tool for Linux systems with Phase 1 and Phase 2 features.

Phase 1 Features:
- File permission analysis
- User account security checks
- SSH configuration review
- System information gathering

Phase 2 Features:
- Web server security auditing (Apache, Nginx)
- Network security analysis
- Enhanced HTML reporting
- Compliance mapping (PCI DSS, SOC 2, NIST, ISO 27001)
- Notification integrations (Email, Slack, Webhooks)
- Trend tracking and analysis

Repository: https://github.com/navinnm/VigileGuard
License: MIT
"""

__version__ = "2.0.0"
__author__ = "VigileGuard Development Team"
__license__ = "MIT"
__repository__ = "https://github.com/navinnm/VigileGuard"

# Import core classes and functions
from .vigileguard import (
    SeverityLevel,
    Finding,
    SecurityChecker,
    FilePermissionChecker,
    UserAccountChecker,
    SSHConfigChecker,
    SystemInfoChecker,
    AuditEngine
)

# Try to import Phase 2 components
try:
    from .web_security_checkers import (
        WebServerSecurityChecker,
        NetworkSecurityChecker
    )
    from .enhanced_reporting import (
        HTMLReporter,
        ComplianceMapper,
        TrendTracker,
        ReportManager
    )
    from .phase2_integration import (
        ConfigurationManager,
        NotificationManager,
        WebhookIntegration,
        SchedulingManager,
        Phase2AuditEngine
    )
    PHASE2_AVAILABLE = True
    
    # Export Phase 2 components
    __all__ = [
        # Core components
        'SeverityLevel', 'Finding', 'SecurityChecker', 'AuditEngine',
        
        # Phase 1 checkers
        'FilePermissionChecker', 'UserAccountChecker', 'SSHConfigChecker', 'SystemInfoChecker',
        
        # Phase 2 checkers
        'WebServerSecurityChecker', 'NetworkSecurityChecker',
        
        # Phase 2 reporting
        'HTMLReporter', 'ComplianceMapper', 'TrendTracker', 'ReportManager',
        
        # Phase 2 integration
        'ConfigurationManager', 'NotificationManager', 'WebhookIntegration',
        'SchedulingManager', 'Phase2AuditEngine',
        
        # Metadata
        '__version__', 'PHASE2_AVAILABLE'
    ]
    
except ImportError as e:
    PHASE2_AVAILABLE = False
    
    # Export only Phase 1 components
    __all__ = [
        # Core components
        'SeverityLevel', 'Finding', 'SecurityChecker', 'AuditEngine',
        
        # Phase 1 checkers
        'FilePermissionChecker', 'UserAccountChecker', 'SSHConfigChecker', 'SystemInfoChecker',
        
        # Metadata
        '__version__', 'PHASE2_AVAILABLE'
    ]


def get_version():
    """Get VigileGuard version string"""
    phase = "Phase 1 + 2" if PHASE2_AVAILABLE else "Phase 1"
    return f"VigileGuard {__version__} ({phase})"


def check_phase2_availability():
    """Check if Phase 2 components are available"""
    return PHASE2_AVAILABLE


def get_available_checkers():
    """Get list of available security checkers"""
    checkers = [
        'FilePermissionChecker',
        'UserAccountChecker', 
        'SSHConfigChecker',
        'SystemInfoChecker'
    ]
    
    if PHASE2_AVAILABLE:
        checkers.extend([
            'WebServerSecurityChecker',
            'NetworkSecurityChecker'
        ])
    
    return checkers


def get_available_formats():
    """Get list of available output formats"""
    formats = ['console', 'json']
    
    if PHASE2_AVAILABLE:
        formats.extend(['html', 'compliance', 'executive', 'all'])
    
    return formats


def create_audit_engine(config_path=None, environment=None):
    """Create appropriate audit engine based on available components"""
    if PHASE2_AVAILABLE:
        return Phase2AuditEngine(config_path, environment)
    else:
        return AuditEngine(config_path)


# Module-level configuration
import logging

# Setup default logging
logging.getLogger(__name__).addHandler(logging.NullHandler())

# Display version info when imported
if __name__ != "__main__":
    import sys
    if hasattr(sys.stdout, 'isatty') and sys.stdout.isatty():
        try:
            from rich.console import Console
            console = Console()
            console.print(f"✅ {get_version()} loaded successfully", style="green")
        except ImportError:
            print(f"✅ {get_version()} loaded successfully")