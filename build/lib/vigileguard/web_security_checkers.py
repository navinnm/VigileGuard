#!/usr/bin/env python3
"""
VigileGuard Phase 2: Web Server & Network Security
Web Server and Network Security Audit Components
"""

import os
import re
import ssl
import socket
import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

# Import base classes - handle both relative and absolute imports
try:
    from .vigileguard import SecurityChecker, SeverityLevel, Finding
except ImportError:
    try:
        from vigileguard import SecurityChecker, SeverityLevel, Finding
    except ImportError:
        # Fallback - redefine classes if import fails
        class SeverityLevel(Enum):
            CRITICAL = "CRITICAL"
            HIGH = "HIGH"
            MEDIUM = "MEDIUM"
            LOW = "LOW"
            INFO = "INFO"

        @dataclass
        class Finding:
            category: str
            severity: SeverityLevel
            title: str
            description: str
            recommendation: str
            details: Optional[Dict[str, Any]] = None

            def to_dict(self) -> Dict[str, Any]:
                from dataclasses import asdict
                result = asdict(self)
                result["severity"] = self.severity.value
                return result

        class SecurityChecker:
            def __init__(self):
                self.findings: List[Finding] = []

            def check(self) -> List[Finding]:
                raise NotImplementedError

            def add_finding(self, category: str, severity: SeverityLevel, title: str,
                        description: str, recommendation: str, 
                        details: Optional[Dict[str, Any]] = None):
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
                try:
                    result = subprocess.run(
                        command, shell=True, capture_output=True, text=True, timeout=30
                    )
                    return result.returncode, result.stdout, result.stderr
                except subprocess.TimeoutExpired:
                    return -1, "", "Command timed out"
                except Exception as e:
                    return -1, "", str(e)

# Handle rich console gracefully
try:
    from rich.console import Console
    console = Console()
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    class Console:
        def print(self, *args, **kwargs):
            print(*args)
    console = Console()


class WebServerSecurityChecker(SecurityChecker):
    """Check web server security configurations"""
    
    def check(self) -> List[Finding]:
        """Run web server security checks"""
        if RICH_AVAILABLE:
            console.print("🌐 Checking web server security...", style="yellow")
        else:
            print("🌐 Checking web server security...")
        
        # Detect installed web servers
        self._detect_web_servers()
        
        # Check Apache if installed
        if self._is_apache_installed():
            self._check_apache_security()
        
        # Check Nginx if installed  
        if self._is_nginx_installed():
            self._check_nginx_security()
        
        # Check SSL/TLS configuration
        self._check_ssl_tls_config()
        
        # Check for common web vulnerabilities
        self._check_common_web_vulns()
        
        return self.findings
    
    def _detect_web_servers(self):
        """Detect installed web servers"""
        servers_found = []
        
        # Check for Apache
        if self._is_apache_installed():
            servers_found.append("Apache")
        
        # Check for Nginx
        if self._is_nginx_installed():
            servers_found.append("Nginx")
        
        if servers_found:
            self.add_finding(
                category="Web Server",
                severity=SeverityLevel.INFO,
                title="Web servers detected",
                description=f"Found installed web servers: {', '.join(servers_found)}",
                recommendation="Ensure all web servers are properly configured and secured",
                details={"servers": servers_found}
            )
        else:
            self.add_finding(
                category="Web Server",
                severity=SeverityLevel.INFO,
                title="No web servers detected",
                description="No Apache or Nginx installations found",
                recommendation="Consider this informational if web services are not needed",
                details={}
            )
    
    def _is_apache_installed(self) -> bool:
        """Check if Apache is installed"""
        apache_paths = [
            "/usr/sbin/apache2",
            "/usr/sbin/httpd",
            "/etc/apache2",
            "/etc/httpd"
        ]
        return any(os.path.exists(path) for path in apache_paths)
    
    def _is_nginx_installed(self) -> bool:
        """Check if Nginx is installed"""
        nginx_paths = [
            "/usr/sbin/nginx",
            "/etc/nginx"
        ]
        return any(os.path.exists(path) for path in nginx_paths)
    
    def _check_apache_security(self):
        """Check Apache security configuration"""
        if RICH_AVAILABLE:
            console.print("🔍 Checking Apache configuration...", style="blue")
        else:
            print("🔍 Checking Apache configuration...")
        
        # Check Apache configuration files
        config_paths = [
            "/etc/apache2/apache2.conf",
            "/etc/httpd/conf/httpd.conf",
            "/etc/apache2/sites-enabled/000-default.conf"
        ]
        
        for config_path in config_paths:
            if os.path.exists(config_path):
                self._analyze_apache_config(config_path)
        
        # Check Apache modules
        self._check_apache_modules()
        
        # Check Apache version
        self._check_apache_version()
    
    def _analyze_apache_config(self, config_path: str):
        """Analyze Apache configuration file"""
        try:
            with open(config_path, 'r') as f:
                config_content = f.read()
            
            # Check for server tokens
            if "ServerTokens" not in config_content:
                self.add_finding(
                    category="Web Server",
                    severity=SeverityLevel.MEDIUM,
                    title="Apache ServerTokens not configured",
                    description="ServerTokens directive not found in Apache configuration",
                    recommendation="Add 'ServerTokens Prod' to hide server version information",
                    details={"config_file": config_path}
                )
            elif "ServerTokens Full" in config_content:
                self.add_finding(
                    category="Web Server",
                    severity=SeverityLevel.MEDIUM,
                    title="Apache ServerTokens set to Full",
                    description="ServerTokens reveals full server information",
                    recommendation="Change ServerTokens to 'Prod' to minimize information disclosure",
                    details={"config_file": config_path}
                )
            
            # Check for server signature
            if "ServerSignature Off" not in config_content:
                self.add_finding(
                    category="Web Server",
                    severity=SeverityLevel.LOW,
                    title="Apache ServerSignature not disabled",
                    description="ServerSignature may reveal server information in error pages",
                    recommendation="Add 'ServerSignature Off' to Apache configuration",
                    details={"config_file": config_path}
                )
            
            # Check for directory browsing
            if "Options Indexes" in config_content:
                self.add_finding(
                    category="Web Server",
                    severity=SeverityLevel.HIGH,
                    title="Directory browsing enabled",
                    description="Apache directory browsing is enabled, which can expose sensitive files",
                    recommendation="Remove 'Indexes' from Options directive or use 'Options -Indexes'",
                    details={"config_file": config_path}
                )
            
            # Check for security headers
            security_headers = [
                "X-Content-Type-Options",
                "X-Frame-Options", 
                "X-XSS-Protection"
            ]
            
            missing_headers = []
            for header in security_headers:
                if header not in config_content:
                    missing_headers.append(header)
            
            if missing_headers:
                self.add_finding(
                    category="Web Server", 
                    severity=SeverityLevel.MEDIUM,
                    title="Missing security headers in Apache",
                    description=f"Security headers not configured: {', '.join(missing_headers)}",
                    recommendation="Configure security headers using mod_headers module",
                    details={"missing_headers": missing_headers, "config_file": config_path}
                )
                
        except (OSError, PermissionError):
            self.add_finding(
                category="Web Server",
                severity=SeverityLevel.INFO,
                title="Cannot read Apache configuration",
                description=f"Insufficient permissions to read {config_path}",
                recommendation="Run VigileGuard with appropriate privileges to audit web server configuration"
            )
    
    def _check_apache_modules(self):
        """Check for dangerous Apache modules"""
        dangerous_modules = [
            "mod_info",
            "mod_status", 
            "mod_userdir"
        ]
        
        cmd = "apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null || echo 'apache not running'"
        returncode, stdout, stderr = self.run_command(cmd)
        
        if returncode == 0 and stdout and "apache not running" not in stdout:
            loaded_modules = stdout.lower()
            found_dangerous = []
            
            for module in dangerous_modules:
                if module.replace("mod_", "") in loaded_modules:
                    found_dangerous.append(module)
            
            if found_dangerous:
                self.add_finding(
                    category="Web Server",
                    severity=SeverityLevel.MEDIUM,
                    title="Potentially dangerous Apache modules enabled",
                    description=f"Found enabled modules that may expose sensitive information: {', '.join(found_dangerous)}",
                    recommendation="Disable unnecessary modules or restrict access to their endpoints",
                    details={"dangerous_modules": found_dangerous}
                )
    
    def _check_apache_version(self):
        """Check Apache version for known vulnerabilities"""
        cmd = "apache2 -v 2>/dev/null || httpd -v 2>/dev/null || echo 'version not found'"
        returncode, stdout, stderr = self.run_command(cmd)
        
        if returncode == 0 and stdout and "version not found" not in stdout:
            version_match = re.search(r'Apache/(\d+\.\d+\.\d+)', stdout)
            if version_match:
                version = version_match.group(1)
                
                self.add_finding(
                    category="Web Server",
                    severity=SeverityLevel.INFO,
                    title="Apache version detected",
                    description=f"Apache version {version} detected",
                    recommendation="Keep Apache updated to the latest stable version",
                    details={"version": version}
                )
                
                # Check for known vulnerable versions (simplified check)
                vulnerable_versions = ["2.4.41", "2.4.29", "2.4.28"]
                if version in vulnerable_versions:
                    self.add_finding(
                        category="Web Server",
                        severity=SeverityLevel.HIGH,
                        title="Apache version has known vulnerabilities",
                        description=f"Apache version {version} has known security vulnerabilities",
                        recommendation="Update Apache to the latest stable version",
                        details={"version": version}
                    )
    
    def _check_nginx_security(self):
        """Check Nginx security configuration"""
        if RICH_AVAILABLE:
            console.print("🔍 Checking Nginx configuration...", style="blue")
        else:
            print("🔍 Checking Nginx configuration...")
        
        # Check Nginx configuration files
        config_paths = [
            "/etc/nginx/nginx.conf",
            "/etc/nginx/sites-enabled/default",
            "/etc/nginx/conf.d/default.conf"
        ]
        
        for config_path in config_paths:
            if os.path.exists(config_path):
                self._analyze_nginx_config(config_path)
        
        # Check Nginx version
        self._check_nginx_version()
    
    def _analyze_nginx_config(self, config_path: str):
        """Analyze Nginx configuration file"""
        try:
            with open(config_path, 'r') as f:
                config_content = f.read()
            
            # Check for server tokens
            if "server_tokens off" not in config_content:
                self.add_finding(
                    category="Web Server",
                    severity=SeverityLevel.MEDIUM,
                    title="Nginx server_tokens not disabled",
                    description="Nginx server version is exposed in headers and error pages",
                    recommendation="Add 'server_tokens off;' to nginx configuration",
                    details={"config_file": config_path}
                )
            
            # Check for security headers
            security_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block"
            }
            
            missing_headers = []
            for header, value in security_headers.items():
                if f"add_header {header}" not in config_content:
                    missing_headers.append(header)
            
            if missing_headers:
                self.add_finding(
                    category="Web Server",
                    severity=SeverityLevel.MEDIUM,
                    title="Missing security headers in Nginx",
                    description=f"Security headers not configured: {', '.join(missing_headers)}",
                    recommendation="Add security headers using add_header directive",
                    details={"missing_headers": missing_headers, "config_file": config_path}
                )
            
            # Check for directory listing
            if "autoindex on" in config_content:
                self.add_finding(
                    category="Web Server",
                    severity=SeverityLevel.HIGH,
                    title="Nginx directory listing enabled",
                    description="Nginx autoindex is enabled, which can expose directory contents",
                    recommendation="Set 'autoindex off;' in nginx configuration",
                    details={"config_file": config_path}
                )
                
        except (OSError, PermissionError):
            self.add_finding(
                category="Web Server",
                severity=SeverityLevel.INFO,
                title="Cannot read Nginx configuration",
                description=f"Insufficient permissions to read {config_path}",
                recommendation="Run VigileGuard with appropriate privileges to audit web server configuration"
            )
    
    def _check_nginx_version(self):
        """Check Nginx version for known vulnerabilities"""
        cmd = "nginx -v 2>&1 || echo 'nginx not found'"
        returncode, stdout, stderr = self.run_command(cmd)
        
        if returncode == 0:
            output = stdout + stderr
            if "nginx not found" not in output:
                version_match = re.search(r'nginx/(\d+\.\d+\.\d+)', output)
                if version_match:
                    version = version_match.group(1)
                    
                    self.add_finding(
                        category="Web Server",
                        severity=SeverityLevel.INFO,
                        title="Nginx version detected",
                        description=f"Nginx version {version} detected",
                        recommendation="Keep Nginx updated to the latest stable version",
                        details={"version": version}
                    )
                    
                    # Check for known vulnerable versions (simplified check)
                    vulnerable_versions = ["1.18.0", "1.16.1", "1.14.2"]
                    if version in vulnerable_versions:
                        self.add_finding(
                            category="Web Server",
                            severity=SeverityLevel.HIGH,
                            title="Nginx version has known vulnerabilities",
                            description=f"Nginx version {version} has known security vulnerabilities",
                            recommendation="Update Nginx to the latest stable version",
                            details={"version": version}
                        )
    
    def _check_ssl_tls_config(self):
        """Check SSL/TLS configuration"""
        # Check for SSL certificate files
        ssl_paths = [
            "/etc/ssl/certs",
            "/etc/pki/tls/certs",
            "/etc/nginx/ssl",
            "/etc/apache2/ssl"
        ]
        
        cert_files = []
        for ssl_path in ssl_paths:
            if os.path.exists(ssl_path):
                try:
                    for file in os.listdir(ssl_path):
                        if file.endswith(('.crt', '.pem', '.cert')):
                            cert_files.append(os.path.join(ssl_path, file))
                except PermissionError:
                    pass
        
        if cert_files:
            self.add_finding(
                category="SSL/TLS",
                severity=SeverityLevel.INFO,
                title="SSL certificates found",
                description=f"Found {len(cert_files)} SSL certificate files",
                recommendation="Ensure SSL certificates are properly configured and up to date",
                details={"certificate_count": len(cert_files)}
            )
            self._analyze_ssl_certificates(cert_files)
        
        # Check for weak SSL ciphers in configuration
        self._check_ssl_ciphers()
    
    def _analyze_ssl_certificates(self, cert_files: List[str]):
        """Analyze SSL certificates"""
        for cert_file in cert_files[:5]:  # Limit to first 5 certificates
            try:
                cmd = f"openssl x509 -in {cert_file} -text -noout 2>/dev/null"
                returncode, stdout, stderr = self.run_command(cmd)
                
                if returncode == 0 and stdout:
                    # Check for weak signature algorithms
                    if "sha1WithRSAEncryption" in stdout:
                        self.add_finding(
                            category="SSL/TLS",
                            severity=SeverityLevel.MEDIUM,
                            title="Weak SSL certificate signature algorithm",
                            description=f"Certificate uses weak SHA-1 signature: {cert_file}",
                            recommendation="Replace certificate with SHA-256 or stronger signature algorithm",
                            details={"certificate": cert_file}
                        )
                    
                    # Check for short key length
                    rsa_match = re.search(r'Public-Key: \((\d+) bit\)', stdout)
                    if rsa_match and int(rsa_match.group(1)) < 2048:
                        self.add_finding(
                            category="SSL/TLS",
                            severity=SeverityLevel.HIGH,
                            title="Weak SSL certificate key length",
                            description=f"Certificate uses weak key length: {rsa_match.group(1)} bits",
                            recommendation="Use at least 2048-bit RSA keys or equivalent strength",
                            details={"certificate": cert_file, "key_length": rsa_match.group(1)}
                        )
                        
            except Exception:
                pass
    
    def _check_ssl_ciphers(self):
        """Check for weak SSL cipher configurations"""
        config_files = [
            "/etc/nginx/nginx.conf",
            "/etc/apache2/apache2.conf",
            "/etc/httpd/conf/httpd.conf"
        ]
        
        weak_ciphers = ["RC4", "DES", "3DES", "MD5"]
        
        for config_file in config_files:
            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    found_weak = []
                    for cipher in weak_ciphers:
                        if cipher in content.upper():
                            found_weak.append(cipher)
                    
                    if found_weak:
                        self.add_finding(
                            category="SSL/TLS",
                            severity=SeverityLevel.HIGH,
                            title="Weak SSL ciphers configured",
                            description=f"Weak ciphers found in configuration: {', '.join(found_weak)}",
                            recommendation="Use strong cipher suites and disable weak ciphers",
                            details={"weak_ciphers": found_weak, "config_file": config_file}
                        )
                        
                except (OSError, PermissionError):
                    pass
    
    def _check_common_web_vulns(self):
        """Check for common web application vulnerabilities"""
        # Check for exposed sensitive files
        sensitive_files = [
            "/.env",
            "/.git/config", 
            "/config.php",
            "/wp-config.php",
            "/database.yml",
            "/.htaccess",
            "/web.config"
        ]
        
        document_roots = self._get_document_roots()
        
        exposed_files = []
        for doc_root in document_roots:
            for sensitive_file in sensitive_files:
                full_path = doc_root + sensitive_file
                if os.path.exists(full_path):
                    exposed_files.append(full_path)
        
        if exposed_files:
            self.add_finding(
                category="Web Application",
                severity=SeverityLevel.HIGH,
                title="Sensitive files exposed in web directory",
                description=f"Found {len(exposed_files)} sensitive files in web-accessible directories",
                recommendation="Move sensitive files outside web root or block access via web server configuration",
                details={"exposed_files": exposed_files[:10]}  # Limit to first 10
            )
    
    def _get_document_roots(self) -> List[str]:
        """Get document root directories from web server configurations"""
        document_roots = []
        
        # Common default document roots
        default_roots = [
            "/var/www/html",
            "/var/www",
            "/usr/share/nginx/html",
            "/srv/http"
        ]
        
        for root in default_roots:
            if os.path.exists(root):
                document_roots.append(root)
        
        return document_roots


class NetworkSecurityChecker(SecurityChecker):
    """Check network security configuration"""
    
    def check(self) -> List[Finding]:
        """Run network security checks"""
        if RICH_AVAILABLE:
            console.print("🌐 Checking network security...", style="yellow")
        else:
            print("🌐 Checking network security...")
        
        # Check firewall configuration
        self._check_firewall_config()
        
        # Check open ports
        self._check_open_ports()
        
        # Check network services
        self._check_network_services()
        
        # Check DNS configuration
        self._check_dns_config()
        
        return self.findings
    
    def _check_firewall_config(self):
        """Check firewall configuration"""
        # Check UFW status
        cmd = "ufw status 2>/dev/null || echo 'ufw not found'"
        returncode, stdout, stderr = self.run_command(cmd)
        
        if returncode == 0 and "ufw not found" not in stdout:
            if "Status: inactive" in stdout:
                self.add_finding(
                    category="Network Security",
                    severity=SeverityLevel.HIGH,
                    title="UFW firewall is inactive",
                    description="Ubuntu Uncomplicated Firewall (UFW) is not enabled",
                    recommendation="Enable UFW with 'sudo ufw enable' and configure appropriate rules",
                    details={}
                )
            else:
                self._analyze_ufw_rules(stdout)
        
        # Check iptables if UFW not available
        cmd = "iptables -L 2>/dev/null || echo 'iptables not accessible'"
        returncode, stdout, stderr = self.run_command(cmd)
        
        if returncode == 0 and "iptables not accessible" not in stdout:
            self._analyze_iptables_rules(stdout)
    
    def _analyze_ufw_rules(self, ufw_output: str):
        """Analyze UFW firewall rules"""
        lines = ufw_output.split('\n')
        
        # Check for overly permissive rules
        for line in lines:
            if "ALLOW" in line and "Anywhere" in line:
                if any(port in line for port in ["22/tcp", "ssh"]):
                    # SSH from anywhere - warn but not critical
                    self.add_finding(
                        category="Network Security",
                        severity=SeverityLevel.MEDIUM,
                        title="SSH accessible from anywhere",
                        description="SSH port is open to all IP addresses",
                        recommendation="Consider restricting SSH access to specific IP ranges",
                        details={"rule": line.strip()}
                    )
                elif any(service in line for service in ["80/tcp", "443/tcp", "http", "https"]):
                    # Web services from anywhere - usually acceptable
                    pass
                else:
                    # Other services from anywhere - potential issue
                    self.add_finding(
                        category="Network Security",
                        severity=SeverityLevel.MEDIUM,
                        title="Service accessible from anywhere",
                        description=f"Network service is open to all IP addresses: {line.strip()}",
                        recommendation="Review if this service needs to be publicly accessible",
                        details={"rule": line.strip()}
                    )
    
    def _analyze_iptables_rules(self, iptables_output: str):
        """Analyze iptables firewall rules"""
        # Check if iptables is effectively empty (allowing everything)
        if "ACCEPT     all" in iptables_output and "DROP" not in iptables_output:
            self.add_finding(
                category="Network Security",
                severity=SeverityLevel.HIGH,
                title="Permissive iptables configuration",
                description="iptables appears to allow all traffic with no restrictions",
                recommendation="Configure iptables rules to restrict unnecessary network access",
                details={}
            )
    
    def _check_open_ports(self):
        """Check for unnecessary open ports"""
        # Use netstat to check listening ports
        cmd = "netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null || echo 'no network tools found'"
        returncode, stdout, stderr = self.run_command(cmd)
        
        if returncode == 0 and "no network tools found" not in stdout:
            self._analyze_listening_ports(stdout)
        else:
            self.add_finding(
                category="Network Security",
                severity=SeverityLevel.INFO,
                title="Cannot check open ports",
                description="Network monitoring tools (netstat/ss) not available or accessible",
                recommendation="Install net-tools package or run with appropriate privileges",
                details={}
            )
    
    def _analyze_listening_ports(self, port_output: str):
        """Analyze listening ports for security issues"""
        lines = port_output.split('\n')
        
        # Common risky ports and services
        risky_ports = {
            "21": "FTP",
            "23": "Telnet", 
            "25": "SMTP",
            "53": "DNS",
            "69": "TFTP",
            "135": "RPC",
            "139": "NetBIOS",
            "445": "SMB",
            "513": "rlogin",
            "514": "rsh",
            "1433": "SQL Server",
            "3306": "MySQL",
            "5432": "PostgreSQL",
            "6379": "Redis",
            "27017": "MongoDB"
        }
        
        found_risky = []
        all_ports = []
        
        for line in lines:
            if "LISTEN" in line or "State" in line:
                # Extract port number
                port_match = re.search(r':(\d+)\s', line)
                if port_match:
                    port = port_match.group(1)
                    all_ports.append(port)
                    
                    if port in risky_ports:
                        # Check if bound to all interfaces (0.0.0.0)
                        if "0.0.0.0:" + port in line or "*:" + port in line:
                            found_risky.append({
                                "port": port,
                                "service": risky_ports[port],
                                "line": line.strip()
                            })
        
        # Report risky ports
        for risky in found_risky:
            severity = SeverityLevel.CRITICAL if risky["service"] in ["Telnet", "FTP", "rsh"] else SeverityLevel.HIGH
            
            self.add_finding(
                category="Network Security",
                severity=severity,
                title=f"Risky service exposed: {risky['service']}",
                description=f"{risky['service']} service (port {risky['port']}) is listening on all interfaces",
                recommendation=f"Secure or disable {risky['service']} service, or bind to localhost only",
                details={"port": risky["port"], "service": risky["service"]}
            )
        
        # Report if too many ports are open
        if len(all_ports) > 20:
            self.add_finding(
                category="Network Security",
                severity=SeverityLevel.MEDIUM,
                title="Many network ports open",
                description=f"Found {len(all_ports)} listening ports, which may increase attack surface",
                recommendation="Review and close unnecessary network services",
                details={"port_count": len(all_ports)}
            )
        
        # Add informational finding about detected ports
        if all_ports:
            self.add_finding(
                category="Network Security",
                severity=SeverityLevel.INFO,
                title="Network ports detected",
                description=f"Found {len(all_ports)} listening network ports",
                recommendation="Review that all listening services are necessary and properly secured",
                details={"listening_ports": all_ports[:20]}  # Limit to first 20
            )
    
    def _check_network_services(self):
        """Check for risky network services"""
        risky_services = [
            "telnet",
            "rsh",
            "rlogin",
            "tftp",
            "finger"
        ]
        
        active_risky = []
        
        for service in risky_services:
            cmd = f"systemctl is-active {service} 2>/dev/null || echo 'inactive'"
            returncode, stdout, stderr = self.run_command(cmd)
            
            if returncode == 0 and "active" in stdout and "inactive" not in stdout:
                active_risky.append(service)
        
        if active_risky:
            self.add_finding(
                category="Network Security",
                severity=SeverityLevel.CRITICAL,
                title="Insecure network services running",
                description=f"Found active insecure services: {', '.join(active_risky)}",
                recommendation="Disable insecure services and use secure alternatives (SSH instead of telnet/rsh)",
                details={"services": active_risky}
            )
    
    def _check_dns_config(self):
        """Check DNS configuration security"""
        # Check /etc/resolv.conf
        resolv_conf = "/etc/resolv.conf"
        if os.path.exists(resolv_conf):
            try:
                with open(resolv_conf, 'r') as f:
                    content = f.read()
                
                # Check for DNS servers
                dns_servers = re.findall(r'nameserver\s+(\S+)', content)
                
                if dns_servers:
                    self.add_finding(
                        category="Network Security",
                        severity=SeverityLevel.INFO,
                        title="DNS configuration detected",
                        description=f"Found {len(dns_servers)} DNS servers configured",
                        recommendation="Ensure DNS servers are trustworthy and properly secured",
                        details={"dns_servers": dns_servers}
                    )
                
                # Check if using localhost DNS (potential DNS spoofing)
                if any(dns in ["127.0.0.1", "::1"] for dns in dns_servers):
                    self.add_finding(
                        category="Network Security",
                        severity=SeverityLevel.LOW,
                        title="Localhost DNS server configured",
                        description="DNS resolution is configured to use localhost",
                        recommendation="Verify localhost DNS server is secure and properly configured",
                        details={"dns_servers": dns_servers}
                    )
                        
            except (OSError, PermissionError):
                self.add_finding(
                    category="Network Security",
                    severity=SeverityLevel.INFO,
                    title="Cannot read DNS configuration",
                    description="Insufficient permissions to read /etc/resolv.conf",
                    recommendation="Run VigileGuard with appropriate privileges to check DNS configuration"
                )