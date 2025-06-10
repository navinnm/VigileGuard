#!/usr/bin/env python3
"""
SecurePulse Test Suite
Basic tests for Phase 1 functionality
"""

import unittest
import tempfile
import os
import json
from unittest.mock import patch, mock_open, MagicMock
import sys

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from securepulse.main import (
        FilePermissionChecker, UserAccountChecker, SSHConfigChecker,
        SystemInfoChecker, AuditEngine, SeverityLevel, Finding
    )
except ImportError:
    # If running as standalone script
    from vigileguard import (
        FilePermissionChecker, UserAccountChecker, SSHConfigChecker,
        SystemInfoChecker, AuditEngine, SeverityLevel, Finding
    )

class TestSeverityLevel(unittest.TestCase):
    """Test SeverityLevel enum"""
    
    def test_severity_levels(self):
        """Test that all severity levels exist"""
        self.assertEqual(SeverityLevel.CRITICAL.value, "CRITICAL")
        self.assertEqual(SeverityLevel.HIGH.value, "HIGH")
        self.assertEqual(SeverityLevel.MEDIUM.value, "MEDIUM")
        self.assertEqual(SeverityLevel.LOW.value, "LOW")
        self.assertEqual(SeverityLevel.INFO.value, "INFO")

class TestFinding(unittest.TestCase):
    """Test Finding dataclass"""
    
    def test_finding_creation(self):
        """Test creating a finding"""
        finding = Finding(
            category="Test",
            severity=SeverityLevel.HIGH,
            title="Test Finding",
            description="Test description",
            recommendation="Test recommendation"
        )
        
        self.assertEqual(finding.category, "Test")
        self.assertEqual(finding.severity, SeverityLevel.HIGH)
        self.assertEqual(finding.title, "Test Finding")
        self.assertEqual(finding.description, "Test description")
        self.assertEqual(finding.recommendation, "Test recommendation")
    
    def test_finding_to_dict(self):
        """Test converting finding to dictionary"""
        finding = Finding(
            category="Test",
            severity=SeverityLevel.HIGH,
            title="Test Finding",
            description="Test description", 
            recommendation="Test recommendation",
            details={"key": "value"}
        )
        
        result = finding.to_dict()
        
        self.assertEqual(result["category"], "Test")
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["details"], {"key": "value"})

class TestFilePermissionChecker(unittest.TestCase):
    """Test FilePermissionChecker"""
    
    def setUp(self):
        self.checker = FilePermissionChecker()
    
    @patch('subprocess.run')
    def test_world_writable_files_found(self, mock_run):
        """Test detection of world-writable files"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="/etc/test_file\n/var/test_file2\n",
            stderr=""
        )
        
        self.checker._check_world_writable_files()
        
        self.assertEqual(len(self.checker.findings), 1)
        finding = self.checker.findings[0]
        self.assertEqual(finding.category, "File Permissions")
        self.assertEqual(finding.severity, SeverityLevel.HIGH)
        self.assertIn("World-writable", finding.title)
    
    @patch('subprocess.run')
    def test_no_world_writable_files(self, mock_run):
        """Test when no world-writable files are found"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr=""
        )
        
        self.checker._check_world_writable_files()
        
        self.assertEqual(len(self.checker.findings), 0)
    
    @patch('os.path.exists')
    @patch('os.stat')
    @patch('pwd.getpwuid')
    @patch('grp.getgrgid')
    def test_sensitive_file_permissions(self, mock_grp, mock_pwd, mock_stat, mock_exists):
        """Test checking sensitive file permissions"""
        mock_exists.return_value = True
        
        # Mock incorrect permissions
        mock_stat.return_value = MagicMock()
        mock_stat.return_value.st_mode = 0o100644  # Wrong permissions for /etc/shadow
        mock_stat.return_value.st_uid = 0
        mock_stat.return_value.st_gid = 0
        
        mock_pwd.return_value = MagicMock()
        mock_pwd.return_value.pw_name = "root"
        
        mock_grp.return_value = MagicMock()
        mock_grp.return_value.gr_name = "root"
        
        self.checker._check_sensitive_files()
        
        # Should find issue with /etc/shadow permissions
        shadow_findings = [f for f in self.checker.findings if "/etc/shadow" in f.title]
        self.assertTrue(len(shadow_findings) > 0)

class TestUserAccountChecker(unittest.TestCase):
    """Test UserAccountChecker"""
    
    def setUp(self):
        self.checker = UserAccountChecker()
    
    def test_empty_passwords_detection(self):
        """Test detection of empty passwords"""
        shadow_content = "user1:$6$salt$hash:18000:0:99999:7:::\nuser2::18000:0:99999:7:::\n"
        
        with patch("builtins.open", mock_open(read_data=shadow_content)):
            self.checker._check_empty_passwords()
        
        self.assertEqual(len(self.checker.findings), 1)
        finding = self.checker.findings[0]
        self.assertEqual(finding.severity, SeverityLevel.CRITICAL)
        self.assertIn("empty passwords", finding.title)
    
    def test_duplicate_uids_detection(self):
        """Test detection of duplicate UIDs"""
        passwd_content = "user1:x:1000:1000::/home/user1:/bin/bash\nuser2:x:1000:1001::/home/user2:/bin/bash\n"
        
        with patch("builtins.open", mock_open(read_data=passwd_content)):
            self.checker._check_duplicate_uids()
        
        self.assertEqual(len(self.checker.findings), 1)
        finding = self.checker.findings[0]
        self.assertEqual(finding.severity, SeverityLevel.HIGH)
        self.assertIn("Duplicate UIDs", finding.title)

class TestSSHConfigChecker(unittest.TestCase):
    """Test SSHConfigChecker"""
    
    def setUp(self):
        self.checker = SSHConfigChecker()
    
    @patch('os.path.exists')
    def test_ssh_not_installed(self, mock_exists):
        """Test when SSH is not installed"""
        mock_exists.return_value = False
        
        findings = self.checker.check()
        
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].title, "SSH server not installed")
        self.assertEqual(findings[0].severity, SeverityLevel.INFO)
    
    @patch('os.path.exists')
    def test_insecure_ssh_config(self, mock_exists):
        """Test detection of insecure SSH configuration"""
        mock_exists.return_value = True
        
        ssh_config = """
# SSH Configuration
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords no
"""
        
        with patch("builtins.open", mock_open(read_data=ssh_config)):
            self.checker._check_ssh_config()
        
        # Should find issues with root login and password auth
        root_login_findings = [f for f in self.checker.findings if "permitrootlogin" in f.title]
        password_auth_findings = [f for f in self.checker.findings if "passwordauthentication" in f.title]
        
        self.assertTrue(len(root_login_findings) > 0)
        self.assertTrue(len(password_auth_findings) > 0)

class TestSystemInfoChecker(unittest.TestCase):
    """Test SystemInfoChecker"""
    
    def setUp(self):
        self.checker = SystemInfoChecker()
    
    @patch('os.path.exists')
    def test_os_version_check(self, mock_exists):
        """Test OS version checking"""
        mock_exists.return_value = True
        
        os_release_content = """
NAME="Ubuntu"
VERSION="20.04.3 LTS (Focal Fossa)"
VERSION_ID="20.04"
PRETTY_NAME="Ubuntu 20.04.3 LTS"
"""
        
        with patch("builtins.open", mock_open(read_data=os_release_content)):
            self.checker._check_os_version()
        
        self.assertTrue(len(self.checker.findings) > 0)
        info_finding = self.checker.findings[0]
        self.assertEqual(info_finding.category, "System Info")
        self.assertIn("Operating System", info_finding.title)
    
    @patch('subprocess.run')
    def test_risky_services_detection(self, mock_run):
        """Test detection of risky services"""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="telnet.service active running\nssh.service active running\n",
            stderr=""
        )
        
        self.checker._check_running_services()
        
        # Should find telnet as risky service
        telnet_findings = [f for f in self.checker.findings if "telnet" in f.title]
        self.assertTrue(len(telnet_findings) > 0)
        
        telnet_finding = telnet_findings[0]
        self.assertEqual(telnet_finding.severity, SeverityLevel.CRITICAL)

class TestAuditEngine(unittest.TestCase):
    """Test AuditEngine"""
    
    def setUp(self):
        self.engine = AuditEngine()
    
    def test_config_loading_defaults(self):
        """Test loading default configuration"""
        self.assertEqual(self.engine.config["output_format"], "console")
        self.assertEqual(self.engine.config["severity_filter"], "INFO")
        self.assertEqual(self.engine.config["excluded_checks"], [])
    
    @patch('yaml.safe_load')
    @patch('builtins.open')
    @patch('os.path.exists')
    def test_config_loading_from_file(self, mock_exists, mock_open_func, mock_yaml):
        """Test loading configuration from file"""
        mock_exists.return_value = True
        mock_yaml.return_value = {
            "output_format": "json",
            "severity_filter": "HIGH"
        }
        
        engine = AuditEngine("test_config.yaml")
        
        self.assertEqual(engine.config["output_format"], "json")
        self.assertEqual(engine.config["severity_filter"], "HIGH")
    
    def test_json_report_generation(self):
        """Test JSON report generation"""
        # Add some test findings
        finding = Finding(
            category="Test",
            severity=SeverityLevel.HIGH,
            title="Test Finding",
            description="Test description",
            recommendation="Test recommendation"
        )
        self.engine.all_findings = [finding]
        
        json_report = self.engine._generate_json_report()
        report_data = json.loads(json_report)
        
        self.assertIn("scan_info", report_data)
        self.assertIn("summary", report_data)
        self.assertIn("findings", report_data)
        self.assertEqual(report_data["summary"]["total_findings"], 1)
        self.assertEqual(report_data["summary"]["by_severity"]["HIGH"], 1)

class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_full_audit_run(self):
        """Test running a complete audit"""
        engine = AuditEngine()
        
        # Mock various system calls to prevent actual system inspection
        with patch('subprocess.run') as mock_run, \
             patch('os.path.exists') as mock_exists, \
             patch('builtins.open', mock_open(read_data="")) as mock_file:
            
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            mock_exists.return_value = False
            
            findings = engine.run_audit()
            
            # Should have some findings (at least system info)
            self.assertIsInstance(findings, list)
    
    def test_severity_filtering(self):
        """Test that findings can be filtered by severity"""
        findings = [
            Finding("Test", SeverityLevel.CRITICAL, "Critical", "desc", "rec"),
            Finding("Test", SeverityLevel.HIGH, "High", "desc", "rec"),
            Finding("Test", SeverityLevel.MEDIUM, "Medium", "desc", "rec"),
            Finding("Test", SeverityLevel.LOW, "Low", "desc", "rec"),
            Finding("Test", SeverityLevel.INFO, "Info", "desc", "rec"),
        ]
        
        # Test filtering logic (would be implemented in config handling)
        severity_order = [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFO]
        
        def filter_by_severity(findings_list, min_severity):
            min_index = severity_order.index(min_severity)
            return [f for f in findings_list if severity_order.index(f.severity) <= min_index]
        
        high_and_above = filter_by_severity(findings, SeverityLevel.HIGH)
        self.assertEqual(len(high_and_above), 2)  # CRITICAL and HIGH
        
        medium_and_above = filter_by_severity(findings, SeverityLevel.MEDIUM)
        self.assertEqual(len(medium_and_above), 3)  # CRITICAL, HIGH, and MEDIUM

if __name__ == '__main__':
    # Create a test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestSeverityLevel,
        TestFinding,
        TestFilePermissionChecker,
        TestUserAccountChecker,
        TestSSHConfigChecker,
        TestSystemInfoChecker,
        TestAuditEngine,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run the tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)