#!/usr/bin/env python3
"""
VigileGuard - Linux Security Audit Tool (Phase 1)
A comprehensive security audit tool for Linux systems

Repository: https://github.com/navinnm/VigileGuard
Author: VigileGuard Development Team
License: MIT
Version: 1.0.0
"""

import os
import sys
import json
import yaml
import subprocess
import stat
import pwd
import grp
import re
import argparse
import platform
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum

try:
    import click
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.text import Text
except ImportError:
    print("Error: Required dependencies not installed.")
    print("Install with: pip install click rich")
    sys.exit(1)

# Global console for rich output
console = Console()

class SeverityLevel(Enum):
    """Security finding severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Finding:
    """Represents a security finding"""
    category: str
    severity: SeverityLevel
    title: str
    description: str
    recommendation: str
    details: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        result = asdict(self)
        result['severity'] = self.severity.value
        return result

class SecurityChecker:
    """Base class for all security checkers"""
    
    def __init__(self):
        self.findings: List[Finding] = []
        
    def check(self) -> List[Finding]:
        """Run the security check - to be implemented by subclasses"""
        raise NotImplementedError
        
    def add_finding(self, category: str, severity: SeverityLevel, title: str, 
                   description: str, recommendation: str, details: Dict = None):
        """Add a security finding"""
        finding = Finding(
            category=category,
            severity=severity,
            title=title,
            description=description,
            recommendation=recommendation,
            details=details or {}
        )
        self.findings.append(finding)
        
    def run_command(self, command: str) -> tuple:
        """Execute a shell command and return output"""
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=30
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

class FilePermissionChecker(SecurityChecker):
    """Check file and directory permissions for security issues"""
    
    def check(self) -> List[Finding]:
        """Run file permission checks"""
        console.print("🔍 Checking file permissions...", style="yellow")
        
        # Check world-writable files
        self._check_world_writable_files()
        
        # Check SUID/SGID binaries
        self._check_suid_sgid_files()
        
        # Check sensitive file permissions
        self._check_sensitive_files()
        
        # Check home directory permissions
        self._check_home_directories()
        
        return self.findings
    
    def _check_world_writable_files(self):
        """Find world-writable files and directories"""
        cmd = "find /etc /usr /var -type f -perm -002 2>/dev/null | head -20"
        returncode, stdout, stderr = self.run_command(cmd)
        
        if returncode == 0 and stdout.strip():
            files = [f for f in stdout.strip().split('\n') if f]
            if files:
                self.add_finding(
                    category="File Permissions",
                    severity=SeverityLevel.HIGH,
                    title="World-writable files found",
                    description=f"Found {len(files)} world-writable files in system directories",
                    recommendation="Remove world-write permissions: chmod o-w <filename>",
                    details={"files": files[:10]}  # Limit to first 10
                )
    
    def _check_suid_sgid_files(self):
        """Find SUID and SGID binaries"""
        cmd = "find /usr /bin /sbin -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null"
        returncode, stdout, stderr = self.run_command(cmd)
        
        if returncode == 0 and stdout.strip():
            files = stdout.strip().split('\n')
            
            # Known safe SUID/SGID files (common ones)
            safe_files = {
                '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/passwd', 
                '/usr/bin/chsh', '/usr/bin/chfn', '/usr/bin/newgrp',
                '/usr/bin/gpasswd', '/bin/ping', '/bin/mount', '/bin/umount'
            }
            
            suspicious_files = [f for f in files if f not in safe_files]
            
            if suspicious_files:
                self.add_finding(
                    category="File Permissions",
                    severity=SeverityLevel.MEDIUM,
                    title="Unusual SUID/SGID binaries found",
                    description=f"Found {len(suspicious_files)} potentially unnecessary SUID/SGID files",
                    recommendation="Review each file and remove SUID/SGID bits if not needed: chmod u-s <filename>",
                    details={"files": suspicious_files}
                )
    
    def _check_sensitive_files(self):
        """Check permissions on sensitive system files"""
        sensitive_files = {
            '/etc/passwd': (0o644, 'root', 'root'),
            '/etc/shadow': (0o640, 'root', 'shadow'),
            '/etc/group': (0o644, 'root', 'root'),
            '/etc/gshadow': (0o640, 'root', 'shadow'),
            '/etc/sudoers': (0o440, 'root', 'root'),
        }
        
        for filepath, (expected_mode, expected_owner, expected_group) in sensitive_files.items():
            if os.path.exists(filepath):
                try:
                    stat_info = os.stat(filepath)
                    actual_mode = stat.S_IMODE(stat_info.st_mode)
                    actual_owner = pwd.getpwuid(stat_info.st_uid).pw_name
                    actual_group = grp.getgrgid(stat_info.st_gid).gr_name
                    
                    issues = []
                    if actual_mode != expected_mode:
                        issues.append(f"mode {oct(actual_mode)} (expected {oct(expected_mode)})")
                    if actual_owner != expected_owner:
                        issues.append(f"owner {actual_owner} (expected {expected_owner})")
                    if actual_group != expected_group:
                        issues.append(f"group {actual_group} (expected {expected_group})")
                    
                    if issues:
                        self.add_finding(
                            category="File Permissions",
                            severity=SeverityLevel.HIGH,
                            title=f"Incorrect permissions on {filepath}",
                            description=f"Security-sensitive file has incorrect {', '.join(issues)}",
                            recommendation=f"Fix with: chown {expected_owner}:{expected_group} {filepath} && chmod {oct(expected_mode)} {filepath}",
                            details={"file": filepath, "issues": issues}
                        )
                except (OSError, KeyError):
                    pass
    
    def _check_home_directories(self):
        """Check home directory permissions"""
        cmd = "find /home -maxdepth 1 -type d -perm -002 2>/dev/null"
        returncode, stdout, stderr = self.run_command(cmd)
        
        if returncode == 0 and stdout.strip():
            dirs = [d for d in stdout.strip().split('\n') if d and d != '/home']
            if dirs:
                self.add_finding(
                    category="File Permissions",
                    severity=SeverityLevel.MEDIUM,
                    title="World-writable home directories found",
                    description=f"Found {len(dirs)} world-writable home directories",
                    recommendation="Remove world-write permissions: chmod o-w <directory>",
                    details={"directories": dirs}
                )

class UserAccountChecker(SecurityChecker):
    """Check user accounts and authentication settings"""
    
    def check(self) -> List[Finding]:
        """Run user account security checks"""
        console.print("👥 Checking user accounts...", style="yellow")
        
        # Check for accounts with empty passwords
        self._check_empty_passwords()
        
        # Check for duplicate UIDs
        self._check_duplicate_uids()
        
        # Check sudo configuration
        self._check_sudo_config()
        
        # Check password policies
        self._check_password_policies()
        
        return self.findings
    
    def _check_empty_passwords(self):
        """Check for accounts with empty passwords"""
        try:
            with open('/etc/shadow', 'r') as f:
                lines = f.readlines()
            
            empty_password_accounts = []
            for line in lines:
                if line.strip():
                    parts = line.split(':')
                    if len(parts) >= 2 and parts[1] == '':
                        empty_password_accounts.append(parts[0])
            
            if empty_password_accounts:
                self.add_finding(
                    category="User Accounts",
                    severity=SeverityLevel.CRITICAL,
                    title="Accounts with empty passwords found",
                    description=f"Found {len(empty_password_accounts)} accounts with empty passwords",
                    recommendation="Set passwords for all accounts or disable them: passwd <username> or usermod -L <username>",
                    details={"accounts": empty_password_accounts}
                )
        except (OSError, PermissionError):
            self.add_finding(
                category="User Accounts",
                severity=SeverityLevel.INFO,
                title="Cannot read /etc/shadow",
                description="Insufficient permissions to check for empty passwords",
                recommendation="Run VigileGuard with appropriate privileges"
            )
    
    def _check_duplicate_uids(self):
        """Check for duplicate UIDs"""
        uid_map = {}
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 3:
                            username = parts[0]
                            uid = parts[2]
                            
                            if uid in uid_map:
                                uid_map[uid].append(username)
                            else:
                                uid_map[uid] = [username]
            
            duplicates = {uid: users for uid, users in uid_map.items() if len(users) > 1}
            
            if duplicates:
             self.add_finding(
                category="User Accounts",
                severity=SeverityLevel.HIGH,
                title="Duplicate UIDs found",
                description=f"Found {len(duplicates)} UIDs assigned to multiple users",
                recommendation="Assign unique UIDs to each user account",
                details={"duplicates": duplicates},  # ← Added comma here
             )
        except OSError:
            pass

    def _check_sudo_config(self):
        """Check sudo configuration"""
        if os.path.exists('/etc/sudoers'):
            cmd = "sudo -l 2>/dev/null || echo 'Cannot check sudo'"
            returncode, stdout, stderr = self.run_command(cmd)
            
            # Check for dangerous sudo configurations
            try:
                # This requires appropriate permissions
                cmd = "grep -E '(NOPASSWD:ALL|%.*ALL.*NOPASSWD)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true"
                returncode, stdout, stderr = self.run_command(cmd)
                
                if stdout.strip():
                    self.add_finding(
                        category="User Accounts",
                        severity=SeverityLevel.HIGH,
                        title="Permissive sudo configuration found",
                        description="Found sudo rules that allow passwordless execution of all commands",
                        recommendation="Review sudo configuration and require passwords for sensitive operations",
                        details={"matches": stdout.strip().split('\n')}
                    )
            except:
                pass
    
    def _check_password_policies(self):
        """Check password policy configuration"""
        # Check if PAM password quality is configured
        pam_files = ['/etc/pam.d/common-password', '/etc/pam.d/system-auth']
        
        pam_configured = False
        for pam_file in pam_files:
            if os.path.exists(pam_file):
                try:
                    with open(pam_file, 'r') as f:
                        content = f.read()
                        if 'pam_pwquality' in content or 'pam_cracklib' in content:
                            pam_configured = True
                            break
                except OSError:
                    pass
        
        if not pam_configured:
            self.add_finding(
                category="User Accounts",
                severity=SeverityLevel.MEDIUM,
                title="No password quality checking configured",
                description="PAM password quality modules not found",
                recommendation="Configure pam_pwquality or pam_cracklib for password strength checking",
                details={}
            )

class SSHConfigChecker(SecurityChecker):
    """Check SSH configuration for security issues"""
    
    def check(self) -> List[Finding]:
        """Run SSH configuration checks"""
        console.print("🔑 Checking SSH configuration...", style="yellow")
        
        if not os.path.exists('/etc/ssh/sshd_config'):
            self.add_finding(
                category="SSH",
                severity=SeverityLevel.INFO,
                title="SSH server not installed",
                description="SSH server configuration not found",
                recommendation="Install and configure SSH server if remote access is needed"
            )
            return self.findings
        
        self._check_ssh_config()
        self._check_ssh_keys()
        
        return self.findings
    
    def _check_ssh_config(self):
        """Analyze SSH configuration file"""
        try:
            with open('/etc/ssh/sshd_config', 'r') as f:
                config_lines = f.readlines()
        except OSError:
            return
        
        config = {}
        for line in config_lines:
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split(None, 1)
                if len(parts) == 2:
                    config[parts[0].lower()] = parts[1]
        
        # Security checks
        security_settings = {
            'permitrootlogin': ('no', SeverityLevel.HIGH, 
                              "Root login should be disabled",
                              "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"),
            'passwordauthentication': ('no', SeverityLevel.MEDIUM,
                                     "Password authentication should be disabled",
                                     "Set 'PasswordAuthentication no' and use key-based authentication"),
            'permitemptypasswords': ('no', SeverityLevel.CRITICAL,
                                   "Empty passwords should not be permitted",
                                   "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config"),
            'protocol': ('2', SeverityLevel.HIGH,
                        "Only SSH protocol version 2 should be used",
                        "Set 'Protocol 2' in /etc/ssh/sshd_config"),
        }
        
        for setting, (expected_value, severity, description, recommendation) in security_settings.items():
            actual_value = config.get(setting, 'default')
            
            # Handle default values
            if setting == 'permitrootlogin' and actual_value == 'default':
                actual_value = 'yes'  # Default is usually yes
            elif setting == 'passwordauthentication' and actual_value == 'default':
                actual_value = 'yes'  # Default is usually yes
            elif setting == 'permitemptypasswords' and actual_value == 'default':
                actual_value = 'no'   # Default is usually no
            
            if actual_value.lower() != expected_value.lower():
                self.add_finding(
                    category="SSH",
                    severity=severity,
                    title=f"Insecure SSH setting: {setting}",
                    description=f"{description}. Current: {actual_value}",
                    recommendation=recommendation,
                    details={"setting": setting, "current": actual_value, "recommended": expected_value}
                )
        
        # Check for specific port configuration
        port = config.get('port', '22')
        if port == '22':
            self.add_finding(
                category="SSH",
                severity=SeverityLevel.LOW,
                title="SSH running on default port",
                description="SSH is running on the default port 22",
                recommendation="Consider changing SSH port to a non-standard port for security through obscurity",
                details={"current_port": port}
            )
    
    def _check_ssh_keys(self):
        """Check SSH host keys and user keys"""
        # Check host key permissions
        host_key_files = [
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_ecdsa_key',
            '/etc/ssh/ssh_host_ed25519_key'
        ]
        
        for key_file in host_key_files:
            if os.path.exists(key_file):
                try:
                    stat_info = os.stat(key_file)
                    mode = stat.S_IMODE(stat_info.st_mode)
                    
                    if mode != 0o600:
                        self.add_finding(
                            category="SSH",
                            severity=SeverityLevel.HIGH,
                            title=f"Incorrect permissions on SSH host key",
                            description=f"SSH host key {key_file} has permissions {oct(mode)} (should be 600)",
                            recommendation=f"Fix permissions: chmod 600 {key_file}",
                            details={"file": key_file, "current_mode": oct(mode)}
                        )
                except OSError:
                    pass

class SystemInfoChecker(SecurityChecker):
    """Gather basic system information and check for security-relevant details"""
    
    def check(self) -> List[Finding]:
        """Run system information checks"""
        console.print("💻 Gathering system information...", style="yellow")
        
        self._check_os_version()
        self._check_kernel_version()
        self._check_running_services()
        
        return self.findings
    
    def _check_os_version(self):
        """Check OS version and support status"""
        try:
            # Get OS release information
            os_info = {}
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            os_info[key] = value.strip('"')
            
            os_name = os_info.get('NAME', 'Unknown')
            os_version = os_info.get('VERSION', 'Unknown')
            
            self.add_finding(
                category="System Info",
                severity=SeverityLevel.INFO,
                title="Operating System Information",
                description=f"Running {os_name} {os_version}",
                recommendation="Ensure OS is supported and receiving security updates",
                details={"os_info": os_info}
            )
            
            # Check for end-of-life versions (simplified check)
            if 'ubuntu' in os_name.lower():
                version_num = os_info.get('VERSION_ID', '')
                if version_num in ['14.04', '16.04']:  # Example EOL versions
                    self.add_finding(
                        category="System Info",
                        severity=SeverityLevel.HIGH,
                        title="End-of-life operating system",
                        description=f"Ubuntu {version_num} is no longer supported",
                        recommendation="Upgrade to a supported Ubuntu version",
                        details={"version": version_num}
                    )
                    
        except OSError:
            pass
    
    def _check_kernel_version(self):
        """Check kernel version"""
        kernel_version = platform.release()
        
        self.add_finding(
            category="System Info",
            severity=SeverityLevel.INFO,
            title="Kernel Information",
            description=f"Running kernel version {kernel_version}",
            recommendation="Keep kernel updated to latest version for security patches",
            details={"kernel_version": kernel_version}
        )
    
    def _check_running_services(self):
        """Check for potentially risky running services"""
        risky_services = {
            'telnet': SeverityLevel.CRITICAL,
            'rsh': SeverityLevel.CRITICAL,
            'ftp': SeverityLevel.HIGH,
            'tftp': SeverityLevel.HIGH,
            'finger': SeverityLevel.MEDIUM,
            'rlogin': SeverityLevel.CRITICAL
        }
        
        # Check systemd services
        cmd = "systemctl list-units --type=service --state=active --no-pager --no-legend 2>/dev/null || true"
        returncode, stdout, stderr = self.run_command(cmd)
        
        if returncode == 0 and stdout:
            active_services = []
            for line in stdout.split('\n'):
                if line.strip():
                    service_name = line.split()[0].replace('.service', '')
                    active_services.append(service_name)
            
            found_risky = []
            for service in active_services:
                for risky_service, severity in risky_services.items():
                    if risky_service in service.lower():
                        found_risky.append((service, severity))
            
            if found_risky:
                for service, severity in found_risky:
                    self.add_finding(
                        category="System Info",
                        severity=severity,
                        title=f"Risky service running: {service}",
                        description=f"Potentially insecure service '{service}' is active",
                        recommendation=f"Consider disabling {service} if not needed: systemctl disable {service}",
                        details={"service": service}
                    )

class AuditEngine:
    """Main audit engine that coordinates all security checks"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_config(config_file)
        self.checkers = [
            FilePermissionChecker(),
            UserAccountChecker(), 
            SSHConfigChecker(),
            SystemInfoChecker()
        ]
        self.all_findings: List[Finding] = []
    
    def _load_config(self, config_file: Optional[str]) -> Dict[str, Any]:
        """Load configuration from file or use defaults"""
        default_config = {
            "output_format": "console",
            "severity_filter": "INFO",
            "excluded_checks": [],
            "custom_rules": {}
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                        custom_config = yaml.safe_load(f)
                    else:
                        custom_config = json.load(f)
                default_config.update(custom_config)
            except Exception as e:
                console.print(f"Warning: Could not load config file: {e}", style="yellow")
        
        return default_config
    
    def run_audit(self) -> List[Finding]:
        """Run all security checks"""
        console.print(Panel.fit("🛡️ VigileGuard Security Audit", style="bold blue"))
        console.print(f"Starting audit at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        console.print()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            for checker in self.checkers:
                task = progress.add_task(f"Running {checker.__class__.__name__}...", total=None)
                try:
                    findings = checker.check()
                    self.all_findings.extend(findings)
                    progress.update(task, completed=True)
                except Exception as e:
                    console.print(f"Error in {checker.__class__.__name__}: {e}", style="red")
                    progress.update(task, completed=True)
        
        return self.all_findings
    
    def generate_report(self, format_type: str = "console") -> str:
        """Generate audit report in specified format"""
        if format_type == "console":
            return self._generate_console_report()
        elif format_type == "json":
            return self._generate_json_report()
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def _generate_console_report(self) -> str:
        """Generate console-friendly report"""
        console.print()
        console.print(Panel.fit("📊 Audit Results", style="bold green"))
        
        # Count findings by severity
        severity_counts = {level: 0 for level in SeverityLevel}
        for finding in self.all_findings:
            severity_counts[finding.severity] += 1
        
        # Summary table
        summary_table = Table(title="Summary")
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", justify="right")
        
        severity_colors = {
            SeverityLevel.CRITICAL: "red",
            SeverityLevel.HIGH: "orange1", 
            SeverityLevel.MEDIUM: "yellow",
            SeverityLevel.LOW: "blue",
            SeverityLevel.INFO: "green"
        }
        
        for severity, count in severity_counts.items():
            if count > 0:
                color = severity_colors.get(severity, "white")
                summary_table.add_row(severity.value, str(count), style=color)
        
        console.print(summary_table)
        console.print()
        
        # Detailed findings
        if self.all_findings:
            for finding in sorted(self.all_findings, key=lambda x: list(SeverityLevel).index(x.severity)):
                color = severity_colors.get(finding.severity, "white")
                
                finding_panel = Panel(
                    f"[bold]{finding.title}[/bold]\n\n"
                    f"[italic]{finding.description}[/italic]\n\n"
                    f"💡 [bold]Recommendation:[/bold] {finding.recommendation}",
                    title=f"[{color}]{finding.severity.value}[/{color}] - {finding.category}",
                    border_style=color
                )
                console.print(finding_panel)
                console.print()
        else:
            console.print("✅ No security issues found!", style="bold green")
        
        return ""
    
    def _generate_json_report(self) -> str:
        """Generate JSON report"""
        report = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "tool": "VigileGuard",
                "version": "1.0.0",
                "hostname": platform.node(),
                "repository": "https://github.com/navinnm/VigileGuard"
            },
            "summary": {
                "total_findings": len(self.all_findings),
                "by_severity": {}
            },
            "findings": [finding.to_dict() for finding in self.all_findings]
        }
        
        # Count by severity
        for finding in self.all_findings:
            severity = finding.severity.value
            report["summary"]["by_severity"][severity] = report["summary"]["by_severity"].get(severity, 0) + 1
        
        return json.dumps(report, indent=2)

@click.command()
@click.option('--config', '-c', help='Configuration file path')
@click.option('--output', '-o', help='Output file path')
@click.option('--format', '-f', 'output_format', default='console', 
              type=click.Choice(['console', 'json']), help='Output format')
@click.option('--debug', is_flag=True, help='Enable debug output')
@click.version_option(version='1.0.0')
def main(config: Optional[str], output: Optional[str], output_format: str, debug: bool):
    """
    VigileGuard - Linux Security Audit Tool
    
    Performs comprehensive security audits of Linux systems including:
    - File permission analysis
    - User account security checks  
    - SSH configuration review
    - System information gathering
    
    Repository: https://github.com/navinnm/VigileGuard
    """
    try:
        # Initialize audit engine
        engine = AuditEngine(config)
        
        # Run the audit
        findings = engine.run_audit()
        
        # Generate report
        if output_format == 'console' and not output:
            # Display directly to console
            engine.generate_report('console')
        else:
            # Generate report content
            report_content = engine.generate_report(output_format)
            
            if output:
                # Write to file
                with open(output, 'w') as f:
                    f.write(report_content)
                console.print(f"Report saved to {output}", style="green")
            else:
                # Print to stdout
                print(report_content)
        
        # Exit with error code if critical/high issues found
        critical_high_count = sum(1 for f in findings 
                                if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH])
        
        if critical_high_count > 0:
            console.print(f"\n⚠️  Found {critical_high_count} critical/high severity issues", style="red")
            sys.exit(1)
        else:
            console.print(f"\n✅ Audit completed successfully", style="green")
            sys.exit(0)
            
    except KeyboardInterrupt:
        console.print("\n❌ Audit interrupted by user", style="red")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n❌ Error during audit: {e}", style="red")
        if debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()