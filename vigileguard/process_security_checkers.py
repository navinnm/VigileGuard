#!/usr/bin/env python3
"""
Process and Service Security Checkers for VigileGuard
=====================================================

This module provides security checkers for running processes, systemd services,
and privilege escalation opportunities.

Author: VigileGuard Development Team
License: MIT
"""

import os
import re
import json
import subprocess
import pwd
import grp
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum

try:
    from .vigileguard import Finding, SeverityLevel, SecurityChecker
except ImportError:
    # Fallback for standalone usage
    import sys
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from vigileguard import Finding, SeverityLevel, SecurityChecker


@dataclass
class ProcessInfo:
    """Process information"""
    pid: int
    name: str
    user: str
    command: str
    executable: str
    capabilities: List[str]
    open_files: List[str]


@dataclass
class ServiceInfo:
    """Service information"""
    name: str
    status: str
    user: str
    group: str
    executable: str
    config_file: str


class ProcessSecurityChecker(SecurityChecker):
    """Process security checker"""
    
    def __init__(self):
        super().__init__()
        self.dangerous_processes = {
            'nc', 'netcat', 'ncat', 'socat', 'telnet', 'rsh', 'rlogin',
            'wget', 'curl', 'python', 'python3', 'perl', 'ruby', 'php',
            'bash', 'sh', 'zsh', 'tcsh', 'csh'
        }
        self.suspicious_locations = {
            '/tmp', '/var/tmp', '/dev/shm', '/home', '/var/www'
        }
    
    def _get_process_list(self) -> List[Dict[str, str]]:
        """Get list of running processes"""
        try:
            result = subprocess.run(['ps', 'axo', 'pid,user,comm,command'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return []
            
            processes = []
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            
            for line in lines:
                parts = line.strip().split(None, 3)
                if len(parts) >= 4:
                    processes.append({
                        'pid': parts[0],
                        'user': parts[1],
                        'comm': parts[2],
                        'command': parts[3]
                    })
            
            return processes
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return []
    
    def _check_process_capabilities(self, pid: str) -> List[str]:
        """Check process capabilities"""
        cap_file = f"/proc/{pid}/status"
        capabilities = []
        
        try:
            with open(cap_file, 'r') as f:
                content = f.read()
            
            # Parse capabilities
            cap_lines = [line for line in content.split('\n') if line.startswith('Cap')]
            for line in cap_lines:
                if 'CapEff:' in line and not line.endswith('0000000000000000'):
                    capabilities.append("Effective capabilities set")
                if 'CapPrm:' in line and not line.endswith('0000000000000000'):
                    capabilities.append("Permitted capabilities set")
                if 'CapInh:' in line and not line.endswith('0000000000000000'):
                    capabilities.append("Inheritable capabilities set")
        except (IOError, OSError):
            pass
        
        return capabilities
    
    def check_suspicious_processes(self):
        """Check for suspicious running processes"""
        processes = self._get_process_list()
        if not processes:
            return
        
        suspicious_procs = []
        root_procs = []
        network_procs = []
        
        for proc in processes:
            user = proc['user']
            command = proc['command'].lower()
            comm = proc['comm'].lower()
            pid = proc['pid']
            
            # Check for processes running as root
            if user == 'root':
                root_procs.append({
                    'pid': pid,
                    'command': proc['command'][:100],  # Truncate long commands
                    'comm': comm
                })
            
            # Check for dangerous processes
            if any(dangerous in comm for dangerous in self.dangerous_processes):
                suspicious_procs.append({
                    'pid': pid,
                    'user': user,
                    'command': proc['command'][:100],
                    'reason': f"Dangerous process: {comm}"
                })
            
            # Check for processes running from suspicious locations
            for location in self.suspicious_locations:
                if location in command:
                    suspicious_procs.append({
                        'pid': pid,
                        'user': user,
                        'command': proc['command'][:100],
                        'reason': f"Running from suspicious location: {location}"
                    })
                    break
            
            # Check for network tools
            if any(net_tool in comm for net_tool in ['nc', 'netcat', 'ncat', 'socat']):
                network_procs.append({
                    'pid': pid,
                    'user': user,
                    'command': proc['command'][:100],
                    'tool': comm
                })
        
        # Report suspicious processes
        if suspicious_procs:
            self.findings.append(Finding(
                category="Process Security",
                severity=SeverityLevel.HIGH,
                title="Suspicious processes detected",
                description=f"Found {len(suspicious_procs)} suspicious running processes",
                recommendation="Investigate suspicious processes and terminate if malicious",
                details={
                    "suspicious_processes": suspicious_procs[:10],  # Limit output
                    "total_count": len(suspicious_procs)
                }
            ))
        
        # Report excessive root processes
        if len(root_procs) > 50:
            self.findings.append(Finding(
                category="Process Security",
                severity=SeverityLevel.MEDIUM,
                title="Many processes running as root",
                description=f"Found {len(root_procs)} processes running as root",
                recommendation="Review processes running as root and apply principle of least privilege",
                details={
                    "root_process_count": len(root_procs),
                    "sample_processes": root_procs[:10]
                }
            ))
        
        # Report network tools
        if network_procs:
            self.findings.append(Finding(
                category="Process Security",
                severity=SeverityLevel.MEDIUM,
                title="Network tools running",
                description=f"Found {len(network_procs)} network tools running",
                recommendation="Verify network tools are authorized and necessary",
                details={"network_processes": network_procs}
            ))
    
    def check_process_capabilities(self):
        """Check for processes with elevated capabilities"""
        processes = self._get_process_list()
        if not processes:
            return
        
        elevated_procs = []
        
        for proc in processes:
            pid = proc['pid']
            capabilities = self._check_process_capabilities(pid)
            
            if capabilities and proc['user'] != 'root':
                elevated_procs.append({
                    'pid': pid,
                    'user': proc['user'],
                    'command': proc['command'][:100],
                    'capabilities': capabilities
                })
        
        if elevated_procs:
            self.findings.append(Finding(
                category="Process Security",
                severity=SeverityLevel.MEDIUM,
                title="Non-root processes with capabilities",
                description=f"Found {len(elevated_procs)} non-root processes with elevated capabilities",
                recommendation="Review processes with capabilities and ensure they're necessary",
                details={"elevated_processes": elevated_procs[:10]}
            ))
    
    def check_process_limits(self):
        """Check system process limits"""
        try:
            # Check current process count
            result = subprocess.run(['ps', 'ax'], capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                process_count = len(result.stdout.strip().split('\n')) - 1  # Exclude header
                
                # Check against system limits
                try:
                    with open('/proc/sys/kernel/pid_max', 'r') as f:
                        pid_max = int(f.read().strip())
                    
                    utilization = (process_count / pid_max) * 100
                    
                    if utilization > 80:
                        self.findings.append(Finding(
                            category="Process Security",
                            severity=SeverityLevel.HIGH,
                            title="High process count",
                            description=f"Process count ({process_count}) is {utilization:.1f}% of system limit",
                            recommendation="Investigate high process count and potential process exhaustion attack",
                            details={
                                "current_processes": process_count,
                                "max_processes": pid_max,
                                "utilization_percent": round(utilization, 1)
                            }
                        ))
                    elif utilization > 60:
                        self.findings.append(Finding(
                            category="Process Security",
                            severity=SeverityLevel.MEDIUM,
                            title="Elevated process count",
                            description=f"Process count ({process_count}) is {utilization:.1f}% of system limit",
                            recommendation="Monitor process count and investigate if unusual",
                            details={
                                "current_processes": process_count,
                                "max_processes": pid_max,
                                "utilization_percent": round(utilization, 1)
                            }
                        ))
                        
                except (IOError, ValueError):
                    pass
                    
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
    
    def run(self):
        """Run all process security checks"""
        self.check_suspicious_processes()
        self.check_process_capabilities()
        self.check_process_limits()


class SystemdServiceChecker(SecurityChecker):
    """SystemD service security checker"""
    
    def __init__(self):
        super().__init__()
        self.systemctl_available = self._check_systemctl_available()
        self.security_options = {
            'PrivateTmp', 'ProtectSystem', 'ProtectHome', 'NoNewPrivileges',
            'PrivateDevices', 'ProtectKernelTunables', 'ProtectControlGroups',
            'RestrictRealtime', 'MemoryDenyWriteExecute', 'RestrictNamespaces'
        }
    
    def _check_systemctl_available(self) -> bool:
        """Check if systemctl is available"""
        try:
            result = subprocess.run(['systemctl', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _get_running_services(self) -> List[str]:
        """Get list of running services"""
        if not self.systemctl_available:
            return []
        
        try:
            result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return []
            
            services = []
            for line in result.stdout.split('\n'):
                if '.service' in line and 'running' in line:
                    service_name = line.split()[0]
                    services.append(service_name)
            
            return services
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return []
    
    def _get_service_properties(self, service: str) -> Dict[str, str]:
        """Get service properties"""
        if not self.systemctl_available:
            return {}
        
        try:
            result = subprocess.run(['systemctl', 'show', service], 
                                  capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                return {}
            
            properties = {}
            for line in result.stdout.split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    properties[key] = value
            
            return properties
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return {}
    
    def check_service_security(self):
        """Check systemd service security configurations"""
        if not self.systemctl_available:
            return
        
        services = self._get_running_services()
        if not services:
            return
        
        insecure_services = []
        root_services = []
        
        for service in services[:20]:  # Limit to first 20 services to avoid timeout
            properties = self._get_service_properties(service)
            if not properties:
                continue
            
            security_issues = []
            
            # Check if running as root
            user = properties.get('User', 'root')
            if user == 'root' or user == '':
                root_services.append(service)
            
            # Check security options
            for option in self.security_options:
                value = properties.get(option, '')
                if option == 'PrivateTmp' and value != 'yes':
                    security_issues.append(f"{option} not enabled")
                elif option == 'ProtectSystem' and value not in ['strict', 'yes', 'full']:
                    security_issues.append(f"{option} not properly configured")
                elif option == 'ProtectHome' and value not in ['yes', 'read-only']:
                    security_issues.append(f"{option} not enabled")
                elif option == 'NoNewPrivileges' and value != 'yes':
                    security_issues.append(f"{option} not enabled")
            
            if security_issues:
                insecure_services.append({
                    'service': service,
                    'user': user,
                    'issues': security_issues[:5]  # Limit issues per service
                })
        
        # Report insecure services
        if insecure_services:
            self.findings.append(Finding(
                category="Service Security",
                severity=SeverityLevel.MEDIUM,
                title="Services with security hardening opportunities",
                description=f"Found {len(insecure_services)} services that could be hardened",
                recommendation="Enable systemd security options like PrivateTmp, ProtectSystem, NoNewPrivileges",
                details={
                    "insecure_services": insecure_services[:10],
                    "total_count": len(insecure_services)
                }
            ))
        
        # Report services running as root
        if len(root_services) > 10:
            self.findings.append(Finding(
                category="Service Security",
                severity=SeverityLevel.MEDIUM,
                title="Many services running as root",
                description=f"Found {len(root_services)} services running as root",
                recommendation="Create dedicated users for services and apply principle of least privilege",
                details={
                    "root_services": root_services[:15],
                    "total_count": len(root_services)
                }
            ))
    
    def check_failed_services(self):
        """Check for failed services"""
        if not self.systemctl_available:
            return
        
        try:
            result = subprocess.run(['systemctl', 'list-units', '--failed', '--no-pager'], 
                                  capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                failed_services = []
                for line in result.stdout.split('\n'):
                    if 'failed' in line and '.service' in line:
                        service_name = line.split()[0]
                        failed_services.append(service_name)
                
                if failed_services:
                    self.findings.append(Finding(
                        category="Service Security",
                        severity=SeverityLevel.MEDIUM,
                        title="Failed services detected",
                        description=f"Found {len(failed_services)} failed services",
                        recommendation="Investigate and fix failed services to prevent security issues",
                        details={"failed_services": failed_services}
                    ))
                    
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
    
    def run(self):
        """Run all systemd service checks"""
        if not self.systemctl_available:
            self.findings.append(Finding(
                category="Service Security",
                severity=SeverityLevel.INFO,
                title="Systemd not available",
                description="Systemd service manager not available or accessible",
                recommendation="Service security checks skipped",
                details={"status": "not_available"}
            ))
            return
        
        self.check_service_security()
        self.check_failed_services()


class ProcessServiceSecurityChecker(SecurityChecker):
    """Main process and service security checker"""
    
    def __init__(self):
        super().__init__()
        self.process_checker = ProcessSecurityChecker()
        self.service_checker = SystemdServiceChecker()
    
    def check_privilege_escalation_vectors(self):
        """Check for potential privilege escalation vectors"""
        escalation_vectors = []
        
        # Check /etc/sudoers permissions
        sudoers_files = ['/etc/sudoers', '/etc/sudoers.d/*']
        for sudoers_pattern in sudoers_files:
            if sudoers_pattern.endswith('*'):
                sudoers_dir = sudoers_pattern[:-1]
                if os.path.exists(sudoers_dir):
                    try:
                        for file in os.listdir(sudoers_dir):
                            file_path = os.path.join(sudoers_dir, file)
                            if os.path.isfile(file_path):
                                stat_info = os.stat(file_path)
                                if stat_info.st_mode & 0o022:  # Group or other writable
                                    escalation_vectors.append(f"Sudoers file {file_path} is writable by group/others")
                    except OSError:
                        pass
            else:
                if os.path.exists(sudoers_pattern):
                    stat_info = os.stat(sudoers_pattern)
                    if stat_info.st_mode & 0o022:  # Group or other writable
                        escalation_vectors.append(f"Sudoers file {sudoers_pattern} is writable by group/others")
        
        # Check for writable PATH directories
        path_env = os.environ.get('PATH', '')
        for path_dir in path_env.split(':'):
            if path_dir and os.path.exists(path_dir):
                try:
                    stat_info = os.stat(path_dir)
                    if stat_info.st_mode & 0o002:  # World writable
                        escalation_vectors.append(f"PATH directory {path_dir} is world-writable")
                except OSError:
                    pass
        
        # Check for world-writable directories in common locations
        dangerous_locations = ['/usr/bin', '/usr/sbin', '/bin', '/sbin', '/usr/local/bin']
        for location in dangerous_locations:
            if os.path.exists(location):
                try:
                    stat_info = os.stat(location)
                    if stat_info.st_mode & 0o002:  # World writable
                        escalation_vectors.append(f"System directory {location} is world-writable")
                except OSError:
                    pass
        
        if escalation_vectors:
            self.findings.append(Finding(
                category="Privilege Escalation",
                severity=SeverityLevel.CRITICAL,
                title="Privilege escalation vectors detected",
                description=f"Found {len(escalation_vectors)} potential privilege escalation vectors",
                recommendation="Fix file permissions and restrict access to sensitive directories",
                details={"escalation_vectors": escalation_vectors}
            ))
    
    def run(self):
        """Run all process and service security checks"""
        # Run process checks
        self.process_checker.run()
        self.findings.extend(self.process_checker.findings)
        
        # Run service checks
        self.service_checker.run()
        self.findings.extend(self.service_checker.findings)
        
        # Check privilege escalation vectors
        self.check_privilege_escalation_vectors()
    
    def check(self):
        """Compatibility method for VigileGuard integration"""
        self.run()
        return self.findings


def main():
    """Main function for standalone testing"""
    checker = ProcessServiceSecurityChecker()
    checker.run()
    
    print(f"⚙️ Process & Service Security Analysis Results:")
    print(f"Found {len(checker.findings)} findings")
    
    for finding in checker.findings:
        print(f"\n[{finding.severity.value}] {finding.title}")
        print(f"Description: {finding.description}")
        print(f"Recommendation: {finding.recommendation}")


if __name__ == "__main__":
    main()