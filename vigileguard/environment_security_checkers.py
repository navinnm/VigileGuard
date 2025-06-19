#!/usr/bin/env python3
"""
Environment Variables Security Checkers for VigileGuard
=======================================================

This module provides security checkers for environment variables,
looking for exposed secrets, API keys, and sensitive data.

Author: VigileGuard Development Team
License: MIT
"""

import os
import re
import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum

try:
    from .vigileguard import Finding, SeverityLevel, SecurityChecker
except ImportError:
    # Fallback for standalone usage
    import sys
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from vigileguard import Finding, SeverityLevel, SecurityChecker


class SecretType(Enum):
    """Types of secrets that can be detected"""
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    DATABASE_URL = "database_url"
    PRIVATE_KEY = "private_key"
    AWS_SECRET = "aws_secret"
    GITHUB_TOKEN = "github_token"
    JWT_SECRET = "jwt_secret"
    ENCRYPTION_KEY = "encryption_key"


@dataclass
class SecretPattern:
    """Pattern for detecting secrets"""
    name: str
    pattern: str
    secret_type: SecretType
    severity: SeverityLevel
    description: str


class EnvironmentSecurityChecker(SecurityChecker):
    """Environment variables security checker"""
    
    def __init__(self):
        super().__init__()
        self.secret_patterns = self._initialize_secret_patterns()
        self.sensitive_var_names = self._initialize_sensitive_var_names()
    
    def _initialize_secret_patterns(self) -> List[SecretPattern]:
        """Initialize patterns for detecting secrets"""
        return [
            # API Keys
            SecretPattern(
                name="Generic API Key",
                pattern=r"(?i)(api[_-]?key|apikey)['\"\s]*[:=]['\"\s]*([a-zA-Z0-9_\-]{20,})",
                secret_type=SecretType.API_KEY,
                severity=SeverityLevel.HIGH,
                description="Generic API key pattern detected"
            ),
            
            # AWS Secrets
            SecretPattern(
                name="AWS Access Key",
                pattern=r"AKIA[0-9A-Z]{16}",
                secret_type=SecretType.AWS_SECRET,
                severity=SeverityLevel.CRITICAL,
                description="AWS Access Key ID detected"
            ),
            SecretPattern(
                name="AWS Secret Key",
                pattern=r"(?i)(aws[_-]?secret[_-]?access[_-]?key)['\"\s]*[:=]['\"\s]*([a-zA-Z0-9/+]{40})",
                secret_type=SecretType.AWS_SECRET,
                severity=SeverityLevel.CRITICAL,
                description="AWS Secret Access Key detected"
            ),
            
            # GitHub Tokens
            SecretPattern(
                name="GitHub Personal Access Token",
                pattern=r"ghp_[a-zA-Z0-9]{36}",
                secret_type=SecretType.GITHUB_TOKEN,
                severity=SeverityLevel.HIGH,
                description="GitHub Personal Access Token detected"
            ),
            SecretPattern(
                name="GitHub OAuth Token",
                pattern=r"gho_[a-zA-Z0-9]{36}",
                secret_type=SecretType.GITHUB_TOKEN,
                severity=SeverityLevel.HIGH,
                description="GitHub OAuth Token detected"
            ),
            
            # Database URLs
            SecretPattern(
                name="Database URL with credentials",
                pattern=r"(?i)(postgresql|mysql|mongodb|redis)://[^:]+:[^@]+@[^/]+",
                secret_type=SecretType.DATABASE_URL,
                severity=SeverityLevel.HIGH,
                description="Database URL with embedded credentials detected"
            ),
            
            # JWT Secrets
            SecretPattern(
                name="JWT Secret",
                pattern=r"(?i)(jwt[_-]?secret|jwt[_-]?key)['\"\s]*[:=]['\"\s]*([a-zA-Z0-9_\-]{20,})",
                secret_type=SecretType.JWT_SECRET,
                severity=SeverityLevel.HIGH,
                description="JWT secret key detected"
            ),
            
            # Generic passwords
            SecretPattern(
                name="Password",
                pattern=r"(?i)(password|passwd|pwd)['\"\s]*[:=]['\"\s]*([a-zA-Z0-9_\-@#$%^&*!]{8,})",
                secret_type=SecretType.PASSWORD,
                severity=SeverityLevel.MEDIUM,
                description="Password in environment variable detected"
            ),
            
            # Private keys
            SecretPattern(
                name="Private Key",
                pattern=r"-----BEGIN[A-Z\s]*PRIVATE KEY-----",
                secret_type=SecretType.PRIVATE_KEY,
                severity=SeverityLevel.CRITICAL,
                description="Private key detected in environment variable"
            ),
            
            # Generic tokens
            SecretPattern(
                name="Generic Token",
                pattern=r"(?i)(token|auth[_-]?token|access[_-]?token)['\"\s]*[:=]['\"\s]*([a-zA-Z0-9_\-\.]{20,})",
                secret_type=SecretType.TOKEN,
                severity=SeverityLevel.HIGH,
                description="Generic authentication token detected"
            ),
        ]
    
    def _initialize_sensitive_var_names(self) -> Set[str]:
        """Initialize list of sensitive environment variable names"""
        return {
            # Generic secrets
            'PASSWORD', 'PASSWD', 'PWD', 'SECRET', 'KEY', 'TOKEN', 'API_KEY', 'APIKEY',
            
            # Database
            'DB_PASSWORD', 'DATABASE_PASSWORD', 'MYSQL_PASSWORD', 'POSTGRES_PASSWORD',
            'MONGODB_PASSWORD', 'REDIS_PASSWORD', 'DB_URL', 'DATABASE_URL',
            
            # AWS
            'AWS_SECRET_ACCESS_KEY', 'AWS_ACCESS_KEY_ID', 'AWS_SESSION_TOKEN',
            
            # GitHub
            'GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_API_TOKEN',
            
            # Other cloud providers
            'GOOGLE_APPLICATION_CREDENTIALS', 'AZURE_CLIENT_SECRET',
            
            # Application secrets
            'JWT_SECRET', 'SESSION_SECRET', 'ENCRYPTION_KEY', 'PRIVATE_KEY',
            'SLACK_TOKEN', 'DISCORD_TOKEN', 'STRIPE_SECRET_KEY',
            
            # Common application variables
            'SECRET_KEY', 'SECRET_KEY_BASE', 'APP_SECRET', 'AUTH_SECRET'
        }
    
    def _get_environment_variables(self) -> Dict[str, str]:
        """Get all environment variables"""
        return dict(os.environ)
    
    def _get_process_environments(self) -> List[Dict[str, Any]]:
        """Get environment variables from running processes"""
        process_envs = []
        
        try:
            # Get list of process PIDs
            result = subprocess.run(['ps', 'axo', 'pid,comm'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return []
            
            pids = []
            for line in result.stdout.strip().split('\n')[1:]:  # Skip header
                parts = line.strip().split(None, 1)
                if len(parts) >= 1:
                    try:
                        pid = int(parts[0])
                        pids.append(pid)
                    except ValueError:
                        continue
            
            # Check environment for first 50 processes (to avoid performance issues)
            for pid in pids[:50]:
                env_file = f"/proc/{pid}/environ"
                try:
                    with open(env_file, 'rb') as f:
                        env_data = f.read().decode('utf-8', errors='ignore')
                    
                    # Parse environment variables (null-separated)
                    env_vars = {}
                    for var in env_data.split('\x00'):
                        if '=' in var:
                            key, value = var.split('=', 1)
                            env_vars[key] = value
                    
                    if env_vars:
                        process_envs.append({
                            'pid': pid,
                            'environment': env_vars
                        })
                        
                except (IOError, OSError, PermissionError):
                    # Process may have terminated or no permission
                    continue
                    
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        
        return process_envs
    
    def _analyze_variable_for_secrets(self, var_name: str, var_value: str) -> List[Dict[str, Any]]:
        """Analyze a single environment variable for secrets"""
        secrets_found = []
        
        # Check against secret patterns
        for pattern in self.secret_patterns:
            matches = re.findall(pattern.pattern, var_value)
            if matches:
                for match in matches:
                    secret_value = match if isinstance(match, str) else match[-1]  # Get the actual secret part
                    secrets_found.append({
                        'pattern_name': pattern.name,
                        'secret_type': pattern.secret_type.value,
                        'severity': pattern.severity,
                        'description': pattern.description,
                        'variable_name': var_name,
                        'secret_preview': secret_value[:10] + '...' if len(secret_value) > 10 else secret_value
                    })
        
        # Check if variable name itself is sensitive
        if var_name.upper() in self.sensitive_var_names:
            if var_value and len(var_value) > 5:  # Only if there's a substantial value
                secrets_found.append({
                    'pattern_name': 'Sensitive Variable Name',
                    'secret_type': 'sensitive_variable',
                    'severity': SeverityLevel.MEDIUM,
                    'description': f'Variable name "{var_name}" suggests sensitive content',
                    'variable_name': var_name,
                    'secret_preview': var_value[:10] + '...' if len(var_value) > 10 else var_value
                })
        
        return secrets_found
    
    def check_current_environment(self):
        """Check current process environment variables"""
        env_vars = self._get_environment_variables()
        
        all_secrets = []
        critical_secrets = []
        high_secrets = []
        
        for var_name, var_value in env_vars.items():
            secrets = self._analyze_variable_for_secrets(var_name, var_value)
            all_secrets.extend(secrets)
            
            for secret in secrets:
                if secret['severity'] == SeverityLevel.CRITICAL:
                    critical_secrets.append(secret)
                elif secret['severity'] == SeverityLevel.HIGH:
                    high_secrets.append(secret)
        
        # Report critical secrets
        if critical_secrets:
            self.findings.append(Finding(
                category="Environment Security",
                severity=SeverityLevel.CRITICAL,
                title="Critical secrets in environment variables",
                description=f"Found {len(critical_secrets)} critical secrets in environment variables",
                recommendation="Remove secrets from environment variables and use secure credential management",
                details={
                    "critical_secrets": [
                        {
                            'variable': s['variable_name'],
                            'type': s['secret_type'],
                            'description': s['description']
                        } for s in critical_secrets
                    ],
                    "total_secrets": len(all_secrets)
                }
            ))
        
        # Report high-severity secrets
        if high_secrets:
            self.findings.append(Finding(
                category="Environment Security",
                severity=SeverityLevel.HIGH,
                title="High-risk secrets in environment variables",
                description=f"Found {len(high_secrets)} high-risk secrets in environment variables",
                recommendation="Use environment variable encryption or dedicated secret management service",
                details={
                    "high_risk_secrets": [
                        {
                            'variable': s['variable_name'],
                            'type': s['secret_type'],
                            'description': s['description']
                        } for s in high_secrets[:10]  # Limit output
                    ],
                    "total_secrets": len(all_secrets)
                }
            ))
        
        # Report general finding if any secrets found
        if all_secrets and not critical_secrets and not high_secrets:
            self.findings.append(Finding(
                category="Environment Security",
                severity=SeverityLevel.MEDIUM,
                title="Potential secrets in environment variables",
                description=f"Found {len(all_secrets)} potential secrets in environment variables",
                recommendation="Review environment variables and implement proper secret management",
                details={
                    "potential_secrets": [
                        {
                            'variable': s['variable_name'],
                            'type': s['secret_type']
                        } for s in all_secrets[:15]
                    ]
                }
            ))
    
    def check_process_environments(self):
        """Check environment variables from running processes"""
        process_envs = self._get_process_environments()
        
        if not process_envs:
            return
        
        processes_with_secrets = []
        total_secrets = 0
        
        for proc_env in process_envs:
            pid = proc_env['pid']
            env_vars = proc_env['environment']
            
            proc_secrets = []
            for var_name, var_value in env_vars.items():
                secrets = self._analyze_variable_for_secrets(var_name, var_value)
                proc_secrets.extend(secrets)
            
            if proc_secrets:
                total_secrets += len(proc_secrets)
                processes_with_secrets.append({
                    'pid': pid,
                    'secret_count': len(proc_secrets),
                    'secret_types': list(set(s['secret_type'] for s in proc_secrets))
                })
        
        if processes_with_secrets:
            self.findings.append(Finding(
                category="Environment Security",
                severity=SeverityLevel.HIGH,
                title="Secrets in process environments",
                description=f"Found secrets in {len(processes_with_secrets)} process environments",
                recommendation="Audit running processes and implement secure credential management",
                details={
                    "affected_processes": processes_with_secrets[:10],
                    "total_processes_checked": len(process_envs),
                    "total_secrets_found": total_secrets
                }
            ))
    
    def check_environment_files(self):
        """Check common environment files for secrets"""
        env_files = [
            '.env', '.env.local', '.env.production', '.env.development',
            '.env.staging', '.env.test', 'environment', '.environment',
            'config.env', 'app.env'
        ]
        
        # Search in current directory and common locations
        search_paths = [
            '.',
            '/opt',
            '/var/www',
            '/home'
        ]
        
        found_files = []
        files_with_secrets = []
        
        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue
                
            try:
                for root, dirs, files in os.walk(search_path):
                    # Limit depth to avoid performance issues
                    depth = root.replace(search_path, '').count(os.sep)
                    if depth > 2:
                        dirs[:] = []  # Don't go deeper
                        continue
                    
                    for file in files:
                        if file in env_files:
                            file_path = os.path.join(root, file)
                            found_files.append(file_path)
                            
                            # Check file for secrets
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read()
                                
                                file_secrets = []
                                for line in content.split('\n'):
                                    if '=' in line and not line.strip().startswith('#'):
                                        try:
                                            var_name, var_value = line.split('=', 1)
                                            var_name = var_name.strip()
                                            var_value = var_value.strip().strip('\'"')
                                            
                                            secrets = self._analyze_variable_for_secrets(var_name, var_value)
                                            file_secrets.extend(secrets)
                                        except:
                                            continue
                                
                                if file_secrets:
                                    files_with_secrets.append({
                                        'file_path': file_path,
                                        'secret_count': len(file_secrets),
                                        'secret_types': list(set(s['secret_type'] for s in file_secrets))
                                    })
                                    
                            except (IOError, PermissionError):
                                continue
                                
            except (OSError, PermissionError):
                continue
        
        # Report findings
        if found_files:
            self.findings.append(Finding(
                category="Environment Security",
                severity=SeverityLevel.MEDIUM,
                title="Environment files detected",
                description=f"Found {len(found_files)} environment files on the system",
                recommendation="Ensure environment files are not exposed and contain no secrets",
                details={
                    "environment_files": found_files[:20],
                    "total_count": len(found_files)
                }
            ))
        
        if files_with_secrets:
            self.findings.append(Finding(
                category="Environment Security",
                severity=SeverityLevel.HIGH,
                title="Secrets in environment files",
                description=f"Found secrets in {len(files_with_secrets)} environment files",
                recommendation="Remove secrets from environment files and use proper secret management",
                details={
                    "files_with_secrets": files_with_secrets,
                    "total_files_checked": len(found_files)
                }
            ))
    
    def run(self):
        """Run all environment security checks"""
        self.check_current_environment()
        self.check_process_environments()
        self.check_environment_files()
    
    def check(self):
        """Compatibility method for VigileGuard integration"""
        self.run()
        return self.findings


def main():
    """Main function for standalone testing"""
    checker = EnvironmentSecurityChecker()
    checker.run()
    
    print(f"🔐 Environment Security Analysis Results:")
    print(f"Found {len(checker.findings)} findings")
    
    for finding in checker.findings:
        print(f"\n[{finding.severity.value}] {finding.title}")
        print(f"Description: {finding.description}")
        print(f"Recommendation: {finding.recommendation}")


if __name__ == "__main__":
    main()