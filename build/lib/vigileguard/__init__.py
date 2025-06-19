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

__version__ = "3.0.6"
__author__ = "VigileGuard Development Team"
__license__ = "MIT"
__repository__ = "https://github.com/navinnm/VigileGuard"

# Import core classes and functions
try:
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
    CORE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Core VigileGuard components not available: {e}")
    CORE_AVAILABLE = False

# Try to import Phase 2 components
PHASE2_AVAILABLE = False
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
    
    # Export all components if Phase 2 is available
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
        
        # Metadata and utilities
        '__version__', 'PHASE2_AVAILABLE', 'CORE_AVAILABLE',
        'get_version', 'check_phase2_availability', 'get_available_checkers',
        'get_available_formats', 'create_audit_engine'
    ]
    
except ImportError as e:
    print(f"Info: Phase 2 components not available: {e}")
    PHASE2_AVAILABLE = False
    
    # Export only Phase 1 components if available
    if CORE_AVAILABLE:
        __all__ = [
            # Core components
            'SeverityLevel', 'Finding', 'SecurityChecker', 'AuditEngine',
            
            # Phase 1 checkers
            'FilePermissionChecker', 'UserAccountChecker', 'SSHConfigChecker', 'SystemInfoChecker',
            
            # Metadata and utilities
            '__version__', 'PHASE2_AVAILABLE', 'CORE_AVAILABLE',
            'get_version', 'check_phase2_availability', 'get_available_checkers',
            'get_available_formats', 'create_audit_engine'
        ]
    else:
        __all__ = ['__version__', 'PHASE2_AVAILABLE', 'CORE_AVAILABLE']


def get_version():
    """Get VigileGuard version string"""
    if PHASE2_AVAILABLE:
        phase = "Phase 1 + 2"
    elif CORE_AVAILABLE:
        phase = "Phase 1"
    else:
        phase = "Limited"
    return f"VigileGuard {__version__} ({phase})"


def check_phase2_availability():
    """Check if Phase 2 components are available"""
    return PHASE2_AVAILABLE


def get_available_checkers():
    """Get list of available security checkers"""
    checkers = []
    
    if CORE_AVAILABLE:
        checkers.extend([
            'FilePermissionChecker',
            'UserAccountChecker', 
            'SSHConfigChecker',
            'SystemInfoChecker'
        ])
    
    if PHASE2_AVAILABLE:
        checkers.extend([
            'WebServerSecurityChecker',
            'NetworkSecurityChecker'
        ])
    
    return checkers


def get_available_formats():
    """Get list of available output formats"""
    formats = ['console']
    
    if CORE_AVAILABLE:
        formats.append('json')
    
    if PHASE2_AVAILABLE:
        formats.extend(['html', 'compliance', 'executive', 'all'])
    
    return formats


def create_audit_engine(config_path=None, environment=None):
    """Create appropriate audit engine based on available components"""
    if PHASE2_AVAILABLE:
        return Phase2AuditEngine(config_path, environment)
    elif CORE_AVAILABLE:
        return AuditEngine(config_path)
    else:
        raise ImportError("No VigileGuard components available. Please check installation.")


def get_installation_status():
    """Get detailed installation status"""
    status = {
        'core_available': CORE_AVAILABLE,
        'phase2_available': PHASE2_AVAILABLE,
        'version': __version__,
        'missing_components': []
    }
    
    if not CORE_AVAILABLE:
        status['missing_components'].append('vigileguard.py (Core module)')
    
    if not PHASE2_AVAILABLE:
        missing_phase2 = []
        try:
            from .web_security_checkers import WebServerSecurityChecker
        except ImportError:
            missing_phase2.append('web_security_checkers.py')
            
        try:
            from .enhanced_reporting import HTMLReporter
        except ImportError:
            missing_phase2.append('enhanced_reporting.py')
            
        try:
            from .phase2_integration import Phase2AuditEngine
        except ImportError:
            missing_phase2.append('phase2_integration.py')
        
        if missing_phase2:
            status['missing_components'].extend(missing_phase2)
    
    return status


def print_installation_status():
    """Print detailed installation status"""
    status = get_installation_status()
    
    print(f"🛡️ VigileGuard {status['version']} Installation Status")
    print("=" * 50)
    
    if status['core_available']:
        print("✅ Core components: Available")
    else:
        print("❌ Core components: Missing")
    
    if status['phase2_available']:
        print("✅ Phase 2 components: Available")
    else:
        print("⚠️  Phase 2 components: Not available")
    
    if status['missing_components']:
        print("\nMissing components:")
        for component in status['missing_components']:
            print(f"  • {component}")
        print("\nTo enable all features, ensure all component files are present.")
    else:
        print("\n🎉 All components available!")
    
    print(f"\nAvailable checkers: {len(get_available_checkers())}")
    print(f"Available formats: {', '.join(get_available_formats())}")


# Module-level configuration
import logging

# Setup default logging
logging.getLogger(__name__).addHandler(logging.NullHandler())

# Display version info when imported (only if in interactive mode)
if __name__ != "__main__":
    import sys
    try:
        # Only show version info in interactive sessions
        if hasattr(sys, 'ps1') or (hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()):
            try:
                from rich.console import Console
                console = Console()
                console.print(f"✅ {get_version()} loaded successfully", style="green")
                if not PHASE2_AVAILABLE:
                    console.print("💡 Install Phase 2 components for enhanced features", style="blue")
            except ImportError:
                print(f"✅ {get_version()} loaded successfully")
                if not PHASE2_AVAILABLE:
                    print("💡 Install Phase 2 components for enhanced features")
    except:
        # Silently ignore any errors during version display
        pass


# Entry point for CLI usage
def main():
    """Main entry point for VigileGuard CLI"""
    if CORE_AVAILABLE:
        # Use Phase 3 CLI with full features (includes Phase 1 & 2)
        from .vigileguard import main
        return main()
    else:
        print("❌ Error: VigileGuard components not available")
        print("Please ensure all required files are present and properly installed.")
        return 1


if __name__ == "__main__":
    exit(main())