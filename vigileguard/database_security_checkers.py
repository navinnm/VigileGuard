#!/usr/bin/env python3
"""
Database Security Checkers for VigileGuard
===========================================

This module provides security checkers for database systems including
MySQL, PostgreSQL, MongoDB, and other common database platforms.

Author: VigileGuard Development Team
License: MIT
"""

import os
import re
import json
import subprocess
import configparser
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

try:
    from .vigileguard import Finding, SeverityLevel, SecurityChecker
except ImportError:
    # Fallback for standalone usage
    import sys
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from vigileguard import Finding, SeverityLevel, SecurityChecker


class DatabaseType(Enum):
    """Database types"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MONGODB = "mongodb"
    REDIS = "redis"
    SQLITE = "sqlite"


@dataclass
class DatabaseInfo:
    """Database information"""
    type: DatabaseType
    version: str
    running: bool
    config_files: List[str]
    data_directory: str
    port: int
    users: List[str]


class MySQLSecurityChecker(SecurityChecker):
    """MySQL/MariaDB security checker"""
    
    def __init__(self):
        super().__init__()
        self.mysql_available = self._check_mysql_available()
        self.config_files = [
            "/etc/mysql/mysql.conf.d/mysqld.cnf",
            "/etc/mysql/my.cnf",
            "/etc/my.cnf",
            "/usr/etc/my.cnf",
            "~/.my.cnf"
        ]
    
    def _check_mysql_available(self) -> bool:
        """Check if MySQL is available"""
        try:
            # Check if MySQL service is running
            result = subprocess.run(['systemctl', 'is-active', 'mysql'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return True
            
            # Check MariaDB
            result = subprocess.run(['systemctl', 'is-active', 'mariadb'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _find_mysql_config(self) -> List[str]:
        """Find MySQL configuration files"""
        found_configs = []
        for config_path in self.config_files:
            expanded_path = os.path.expanduser(config_path)
            if os.path.exists(expanded_path):
                found_configs.append(expanded_path)
        return found_configs
    
    def _parse_mysql_config(self, config_path: str) -> Dict[str, Any]:
        """Parse MySQL configuration file"""
        config = configparser.ConfigParser(allow_no_value=True)
        config.read(config_path)
        return {section: dict(config.items(section)) for section in config.sections()}
    
    def check_mysql_configuration(self):
        """Check MySQL configuration for security issues"""
        if not self.mysql_available:
            return
        
        config_files = self._find_mysql_config()
        if not config_files:
            self.findings.append(Finding(
                category="Database Security",
                severity=SeverityLevel.MEDIUM,
                title="MySQL configuration files not found",
                description="No MySQL configuration files found in standard locations",
                recommendation="Ensure MySQL is properly configured with security settings",
                details={"searched_paths": self.config_files}
            ))
            return
        
        security_issues = []
        
        for config_file in config_files:
            try:
                config = self._parse_mysql_config(config_file)
                
                # Check mysqld section
                mysqld_config = config.get('mysqld', {})
                
                # Check for SSL/TLS configuration
                if not mysqld_config.get('ssl'):
                    security_issues.append("SSL/TLS not enabled")
                
                # Check bind-address
                bind_address = mysqld_config.get('bind-address', '0.0.0.0')
                if bind_address == '0.0.0.0':
                    security_issues.append("MySQL bound to all interfaces (0.0.0.0)")
                
                # Check for log configuration
                if not mysqld_config.get('log-error'):
                    security_issues.append("Error logging not configured")
                
                # Check for general log
                if mysqld_config.get('general_log') == 'ON':
                    security_issues.append("General query log enabled (potential sensitive data exposure)")
                
                # Check for local-infile
                if mysqld_config.get('local-infile', '1') == '1':
                    security_issues.append("LOCAL INFILE enabled (potential security risk)")
                
                # Check skip-networking
                if not mysqld_config.get('skip-networking'):
                    security_issues.append("Network access enabled (consider skip-networking for local-only)")
                
                # Check validate_password plugin
                if not any(key.startswith('validate_password') for key in mysqld_config.keys()):
                    security_issues.append("Password validation plugin not configured")
                
            except Exception as e:
                security_issues.append(f"Failed to parse config {config_file}: {e}")
        
        if security_issues:
            self.findings.append(Finding(
                category="Database Security",
                severity=SeverityLevel.HIGH,
                title="MySQL configuration security issues",
                description=f"Found {len(security_issues)} MySQL configuration security issues",
                recommendation="Review and harden MySQL configuration settings",
                details={
                    "config_files": config_files,
                    "issues": security_issues
                }
            ))
    
    def check_mysql_users(self):
        """Check MySQL users for security issues"""
        if not self.mysql_available:
            return
        
        try:
            # Try to connect and check users (requires mysql client)
            result = subprocess.run(['mysql', '-e', "SELECT User, Host FROM mysql.user;"], 
                                  capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                users_output = result.stdout
                security_issues = []
                
                # Check for anonymous users
                if "''" in users_output or "anonymous" in users_output.lower():
                    security_issues.append("Anonymous users detected")
                
                # Check for users with % host (any host)
                if "%" in users_output:
                    security_issues.append("Users with wildcard host (%) detected")
                
                # Check for root users with remote access
                if "root" in users_output and "%" in users_output:
                    security_issues.append("Root user with remote access detected")
                
                if security_issues:
                    self.findings.append(Finding(
                        category="Database Security",
                        severity=SeverityLevel.CRITICAL,
                        title="MySQL user security issues",
                        description=f"Found {len(security_issues)} MySQL user security issues",
                        recommendation="Remove anonymous users, restrict root access, limit host permissions",
                        details={"issues": security_issues}
                    ))
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # MySQL client not available or access denied
            self.findings.append(Finding(
                category="Database Security",
                severity=SeverityLevel.INFO,
                title="MySQL user check skipped",
                description="Could not check MySQL users (mysql client not available or access denied)",
                recommendation="Manually review MySQL users for security issues",
                details={"reason": "client_unavailable"}
            ))
    
    def run(self):
        """Run all MySQL security checks"""
        if not self.mysql_available:
            return
        
        self.check_mysql_configuration()
        self.check_mysql_users()


class PostgreSQLSecurityChecker(SecurityChecker):
    """PostgreSQL security checker"""
    
    def __init__(self):
        super().__init__()
        self.postgresql_available = self._check_postgresql_available()
        self.config_files = [
            "/etc/postgresql/*/main/postgresql.conf",
            "/var/lib/pgsql/data/postgresql.conf",
            "/usr/local/pgsql/data/postgresql.conf"
        ]
        self.hba_files = [
            "/etc/postgresql/*/main/pg_hba.conf",
            "/var/lib/pgsql/data/pg_hba.conf",
            "/usr/local/pgsql/data/pg_hba.conf"
        ]
    
    def _check_postgresql_available(self) -> bool:
        """Check if PostgreSQL is available"""
        try:
            result = subprocess.run(['systemctl', 'is-active', 'postgresql'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _find_postgresql_configs(self) -> Tuple[List[str], List[str]]:
        """Find PostgreSQL configuration files"""
        import glob
        
        config_files = []
        hba_files = []
        
        for pattern in self.config_files:
            config_files.extend(glob.glob(pattern))
        
        for pattern in self.hba_files:
            hba_files.extend(glob.glob(pattern))
        
        return config_files, hba_files
    
    def check_postgresql_configuration(self):
        """Check PostgreSQL configuration for security issues"""
        if not self.postgresql_available:
            return
        
        config_files, hba_files = self._find_postgresql_configs()
        
        security_issues = []
        
        # Check main configuration files
        for config_file in config_files:
            try:
                with open(config_file, 'r') as f:
                    content = f.read()
                
                # Check SSL configuration
                if "ssl = off" in content or "ssl=off" in content:
                    security_issues.append("SSL disabled in PostgreSQL")
                
                # Check listening addresses
                if re.search(r"listen_addresses\s*=\s*['\"]?\*['\"]?", content):
                    security_issues.append("PostgreSQL listening on all interfaces (*)")
                
                # Check logging
                if "log_statement = 'none'" in content:
                    security_issues.append("Statement logging disabled")
                
                # Check password encryption
                if "password_encryption = off" in content:
                    security_issues.append("Password encryption disabled")
                
            except IOError as e:
                security_issues.append(f"Cannot read PostgreSQL config {config_file}: {e}")
        
        # Check pg_hba.conf files
        for hba_file in hba_files:
            try:
                with open(hba_file, 'r') as f:
                    content = f.read()
                
                # Check for trust authentication
                if re.search(r'\btrust\b', content):
                    security_issues.append("Trust authentication found in pg_hba.conf")
                
                # Check for password authentication (should use md5 or scram-sha-256)
                if re.search(r'\bpassword\b', content):
                    security_issues.append("Plain password authentication found")
                
                # Check for wide host ranges
                if re.search(r'0\.0\.0\.0/0', content):
                    security_issues.append("Wide host range (0.0.0.0/0) in pg_hba.conf")
                
            except IOError as e:
                security_issues.append(f"Cannot read pg_hba.conf {hba_file}: {e}")
        
        if security_issues:
            self.findings.append(Finding(
                category="Database Security",
                severity=SeverityLevel.HIGH,
                title="PostgreSQL configuration security issues",
                description=f"Found {len(security_issues)} PostgreSQL configuration security issues",
                recommendation="Review and harden PostgreSQL configuration and authentication",
                details={
                    "config_files": config_files,
                    "hba_files": hba_files,
                    "issues": security_issues
                }
            ))
    
    def run(self):
        """Run all PostgreSQL security checks"""
        if not self.postgresql_available:
            return
        
        self.check_postgresql_configuration()


class MongoDBSecurityChecker(SecurityChecker):
    """MongoDB security checker"""
    
    def __init__(self):
        super().__init__()
        self.mongodb_available = self._check_mongodb_available()
        self.config_files = [
            "/etc/mongod.conf",
            "/etc/mongodb.conf",
            "/usr/local/etc/mongod.conf"
        ]
    
    def _check_mongodb_available(self) -> bool:
        """Check if MongoDB is available"""
        try:
            result = subprocess.run(['systemctl', 'is-active', 'mongod'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def check_mongodb_configuration(self):
        """Check MongoDB configuration for security issues"""
        if not self.mongodb_available:
            return
        
        security_issues = []
        found_configs = []
        
        for config_file in self.config_files:
            if os.path.exists(config_file):
                found_configs.append(config_file)
                try:
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    # Check bind IP
                    if re.search(r'bindIp.*0\.0\.0\.0', content):
                        security_issues.append("MongoDB bound to all interfaces (0.0.0.0)")
                    
                    # Check authentication
                    if "authorization: enabled" not in content and "auth = true" not in content:
                        security_issues.append("Authentication not enabled")
                    
                    # Check SSL/TLS
                    if "ssl:" not in content and "sslMode:" not in content:
                        security_issues.append("SSL/TLS not configured")
                    
                    # Check JavaScript execution
                    if "javascriptEnabled: true" in content:
                        security_issues.append("Server-side JavaScript enabled (security risk)")
                    
                except IOError as e:
                    security_issues.append(f"Cannot read MongoDB config {config_file}: {e}")
        
        if not found_configs:
            security_issues.append("No MongoDB configuration files found")
        
        if security_issues:
            self.findings.append(Finding(
                category="Database Security",
                severity=SeverityLevel.HIGH,
                title="MongoDB configuration security issues",
                description=f"Found {len(security_issues)} MongoDB configuration security issues",
                recommendation="Enable authentication, configure SSL/TLS, restrict bind IP",
                details={
                    "config_files": found_configs,
                    "issues": security_issues
                }
            ))
    
    def run(self):
        """Run all MongoDB security checks"""
        if not self.mongodb_available:
            return
        
        self.check_mongodb_configuration()


class RedisSecurityChecker(SecurityChecker):
    """Redis security checker"""
    
    def __init__(self):
        super().__init__()
        self.redis_available = self._check_redis_available()
        self.config_files = [
            "/etc/redis/redis.conf",
            "/etc/redis.conf",
            "/usr/local/etc/redis.conf"
        ]
    
    def _check_redis_available(self) -> bool:
        """Check if Redis is available"""
        try:
            result = subprocess.run(['systemctl', 'is-active', 'redis'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return True
            
            result = subprocess.run(['systemctl', 'is-active', 'redis-server'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def check_redis_configuration(self):
        """Check Redis configuration for security issues"""
        if not self.redis_available:
            return
        
        security_issues = []
        found_configs = []
        
        for config_file in self.config_files:
            if os.path.exists(config_file):
                found_configs.append(config_file)
                try:
                    with open(config_file, 'r') as f:
                        content = f.read()
                    
                    # Check bind configuration
                    if re.search(r'^bind 0\.0\.0\.0', content, re.MULTILINE):
                        security_issues.append("Redis bound to all interfaces (0.0.0.0)")
                    
                    # Check authentication
                    if not re.search(r'^requirepass', content, re.MULTILINE):
                        security_issues.append("No password authentication configured")
                    
                    # Check dangerous commands
                    if not re.search(r'rename-command.*FLUSHDB', content):
                        security_issues.append("FLUSHDB command not disabled/renamed")
                    
                    if not re.search(r'rename-command.*FLUSHALL', content):
                        security_issues.append("FLUSHALL command not disabled/renamed")
                    
                    if not re.search(r'rename-command.*CONFIG', content):
                        security_issues.append("CONFIG command not disabled/renamed")
                    
                    # Check protected mode
                    if "protected-mode no" in content:
                        security_issues.append("Protected mode disabled")
                    
                except IOError as e:
                    security_issues.append(f"Cannot read Redis config {config_file}: {e}")
        
        if not found_configs:
            security_issues.append("No Redis configuration files found")
        
        if security_issues:
            self.findings.append(Finding(
                category="Database Security",
                severity=SeverityLevel.HIGH,
                title="Redis configuration security issues",
                description=f"Found {len(security_issues)} Redis configuration security issues",
                recommendation="Configure authentication, disable dangerous commands, restrict bind IP",
                details={
                    "config_files": found_configs,
                    "issues": security_issues
                }
            ))
    
    def run(self):
        """Run all Redis security checks"""
        if not self.redis_available:
            return
        
        self.check_redis_configuration()


class DatabaseSecurityChecker(SecurityChecker):
    """Main database security checker that orchestrates all database checks"""
    
    def __init__(self):
        super().__init__()
        self.mysql_checker = MySQLSecurityChecker()
        self.postgresql_checker = PostgreSQLSecurityChecker()
        self.mongodb_checker = MongoDBSecurityChecker()
        self.redis_checker = RedisSecurityChecker()
    
    def check_database_services(self):
        """Check which database services are running"""
        databases = []
        
        if self.mysql_checker.mysql_available:
            databases.append("MySQL/MariaDB")
        
        if self.postgresql_checker.postgresql_available:
            databases.append("PostgreSQL")
        
        if self.mongodb_checker.mongodb_available:
            databases.append("MongoDB")
        
        if self.redis_checker.redis_available:
            databases.append("Redis")
        
        if databases:
            self.findings.append(Finding(
                category="Database Security",
                severity=SeverityLevel.INFO,
                title="Database services detected",
                description=f"Found database services: {', '.join(databases)}",
                recommendation="Ensure all database services are properly secured",
                details={"databases": databases}
            ))
        else:
            self.findings.append(Finding(
                category="Database Security",
                severity=SeverityLevel.INFO,
                title="No database services detected",
                description="No database services found running on this system",
                recommendation="Database security checks skipped",
                details={"databases": []}
            ))
    
    def run(self):
        """Run all database security checks"""
        self.check_database_services()
        
        # Run individual database checks
        checkers = [
            self.mysql_checker,
            self.postgresql_checker,
            self.mongodb_checker,
            self.redis_checker
        ]
        
        for checker in checkers:
            checker.run()
            self.findings.extend(checker.findings)
    
    def check(self):
        """Compatibility method for VigileGuard integration"""
        self.run()
        return self.findings


def main():
    """Main function for standalone testing"""
    checker = DatabaseSecurityChecker()
    checker.run()
    
    print(f"🗄️ Database Security Analysis Results:")
    print(f"Found {len(checker.findings)} findings")
    
    for finding in checker.findings:
        print(f"\n[{finding.severity.value}] {finding.title}")
        print(f"Description: {finding.description}")
        print(f"Recommendation: {finding.recommendation}")


if __name__ == "__main__":
    main()