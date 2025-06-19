#!/usr/bin/env python3
"""
Debug script to identify import issues in VigileGuard
"""

import sys
import traceback

def test_basic_imports():
    """Test basic Python and system imports"""
    print("=== Testing Basic Imports ===")
    __version__ = "3.0.5"
    print(f"VigileGuard Debug Script Version: {__version__}")
    try:
        import os
        print("✅ os module imported")
    except Exception as e:
        print(f"❌ os module failed: {e}")
    
    try:
        import sys
        print("✅ sys module imported")
    except Exception as e:
        print(f"❌ sys module failed: {e}")
    
    try:
        import json
        print("✅ json module imported")
    except Exception as e:
        print(f"❌ json module failed: {e}")

def test_rich_imports():
    """Test rich library imports"""
    print("\n=== Testing Rich Library Imports ===")
    
    try:
        import rich
        print(f"✅ rich library imported (version: {rich.__version__})")
    except Exception as e:
        print(f"❌ rich library failed: {e}")
        return False
    
    try:
        from rich.console import Console
        print("✅ Console imported from rich")
    except Exception as e:
        print(f"❌ Console import failed: {e}")
        return False
    
    try:
        from rich.panel import Panel
        print("✅ Panel imported from rich")
    except Exception as e:
        print(f"❌ Panel import failed: {e}")
        return False
    
    try:
        from rich.table import Table
        print("✅ Table imported from rich")
    except Exception as e:
        print(f"❌ Table import failed: {e}")
        return False
    
    try:
        from rich.progress import Progress, SpinnerColumn, TextColumn
        print("✅ Progress components imported from rich")
    except Exception as e:
        print(f"❌ Progress components failed: {e}")
        return False
    
    return True

def test_rich_functionality():
    """Test basic rich functionality"""
    print("\n=== Testing Rich Functionality ===")
    
    try:
        from rich.console import Console
        from rich.panel import Panel
        
        console = Console()
        test_panel = Panel.fit("Test Panel", style="bold blue")
        console.print(test_panel)
        print("✅ Panel.fit() works correctly")
        return True
    except Exception as e:
        print(f"❌ Panel.fit() failed: {e}")
        traceback.print_exc()
        return False

def test_click_import():
    """Test click library import"""
    print("\n=== Testing Click Library ===")
    
    try:
        import click
        print(f"✅ click library imported (version: {click.__version__})")
        return True
    except Exception as e:
        print(f"❌ click library failed: {e}")
        return False

def test_vigileguard_imports():
    """Test VigileGuard module imports"""
    print("\n=== Testing VigileGuard Module Imports ===")
    
    # Test if vigileguard.py can be imported
    try:
        import vigileguard
        print("✅ vigileguard module imported successfully")
    except Exception as e:
        print(f"❌ vigileguard module import failed: {e}")
        traceback.print_exc()
        return False
    
    # Test individual classes
    try:
        from vigileguard import SeverityLevel, Finding, SecurityChecker
        print("✅ Core classes imported from vigileguard")
    except Exception as e:
        print(f"❌ Core classes import failed: {e}")
        traceback.print_exc()
        return False
    
    return True

def test_phase2_imports():
    """Test Phase 2 module imports"""
    print("\n=== Testing Phase 2 Module Imports ===")
    
    # Test web_security_checkers
    try:
        from web_security_checkers import WebServerSecurityChecker, NetworkSecurityChecker
        print("✅ Web security checkers imported")
    except Exception as e:
        print(f"❌ Web security checkers failed: {e}")
        traceback.print_exc()
    
    # Test enhanced_reporting
    try:
        from enhanced_reporting import HTMLReporter, ComplianceMapper, ReportManager
        print("✅ Enhanced reporting imported")
    except Exception as e:
        print(f"❌ Enhanced reporting failed: {e}")
        traceback.print_exc()
    
    # Test phase2_integration
    try:
        from phase2_integration import ConfigurationManager, NotificationManager
        print("✅ Phase 2 integration imported")
    except Exception as e:
        print(f"❌ Phase 2 integration failed: {e}")
        traceback.print_exc()

def test_minimal_execution():
    """Test minimal VigileGuard execution"""
    print("\n=== Testing Minimal Execution ===")
    
    try:
        from vigileguard import FilePermissionChecker
        checker = FilePermissionChecker()
        print("✅ FilePermissionChecker instantiated")
        
        # Don't actually run the check, just test instantiation
        print("✅ Minimal execution test passed")
        return True
    except Exception as e:
        print(f"❌ Minimal execution failed: {e}")
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("VigileGuard Import Debug Script")
    print("=" * 50)
    
    test_basic_imports()
    
    if test_rich_imports():
        test_rich_functionality()
    
    test_click_import()
    
    # Only test VigileGuard imports if basic imports work
    if test_vigileguard_imports():
        test_minimal_execution()
    
    test_phase2_imports()
    
    print("\n" + "=" * 50)
    print("Debug script completed!")
    print("\nIf you see any ❌ errors above, those need to be fixed.")
    print("If all basic tests pass but VigileGuard still fails, there may be")
    print("a runtime issue in the actual execution code.")

if __name__ == "__main__":
    main()