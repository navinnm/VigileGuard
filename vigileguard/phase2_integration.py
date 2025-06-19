#!/usr/bin/env python3
"""
VigileGuard Phase 2: Integration and Configuration Management
Enhanced configuration, webhook integration, and environment-specific rules
"""

import os
import json
import yaml
import requests
import smtplib
import subprocess
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
import logging

# Handle imports gracefully - support both relative and absolute imports
try:
    from .vigileguard import SeverityLevel, Finding, SecurityChecker, AuditEngine
except ImportError:
    try:
        from vigileguard import SeverityLevel, Finding, SecurityChecker, AuditEngine
    except ImportError:
        # Fallback - redefine classes if import fails
        from enum import Enum
        from dataclasses import dataclass, asdict
        
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
                result = asdict(self)
                result["severity"] = self.severity.value
                return result
        
        class SecurityChecker:
            def __init__(self):
                self.findings: List[Finding] = []

        class AuditEngine:
            def __init__(self, config_path=None):
                self.config_path = config_path
                self.all_findings = []

# Handle rich console gracefully
try:
    from rich.console import Console
    from rich.panel import Panel
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    class Console:
        def print(self, *args, **kwargs):
            print(*args)
    
    class Panel:
        @staticmethod
        def fit(text, **kwargs):
            return text
    
    console = Console()


class ConfigurationManager:
    """Advanced configuration management for Phase 2"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_config_file()
        self.config = self._load_enhanced_config()
        self._setup_logging()
    
    def _find_config_file(self) -> str:
        """Find configuration file in standard locations"""
        search_paths = [
            os.environ.get('VIGILEGUARD_CONFIG'),
            './config.yaml',
            './vigileguard.yaml',
            os.path.expanduser('~/.config/vigileguard/config.yaml'),
            '/etc/vigileguard/config.yaml'
        ]
        
        for path in search_paths:
            if path and os.path.exists(path):
                return path
        
        # Return default path for creation
        return './config.yaml'
    
    def _load_enhanced_config(self) -> Dict[str, Any]:
        """Load enhanced configuration with Phase 2 features"""
        default_config = {
            # Basic settings from Phase 1
            "output_format": "console",
            "severity_filter": "INFO",
            "excluded_checks": [],
            
            # Reporting configuration
            "reporting": {
                "formats": ["console", "json", "html"],
                "output_directory": "./reports",
                "include_trends": True,
                "executive_summary": True,
                "auto_archive": True,
                "retention_days": 90
            },
            
            # Notification configuration (disabled by default)
            "notifications": {
                "enabled": False,
                "channels": [],
                "severity_threshold": "HIGH",
                "email": {
                    "enabled": False,
                    "smtp_server": "",
                    "smtp_port": 587,
                    "username": "",
                    "password": "",
                    "from_address": "",
                    "to_addresses": [],
                    "use_tls": True
                },
                "slack": {
                    "enabled": False,
                    "webhook_url": "",
                    "channel": "#security",
                    "username": "VigileGuard"
                },
                "webhook": {
                    "enabled": False,
                    "url": "",
                    "method": "POST",
                    "headers": {"Content-Type": "application/json"},
                    "timeout": 30
                }
            },
            
            # Environment-specific settings
            "environments": {
                "development": {
                    "severity_filter": "MEDIUM",
                    "notifications": {"enabled": False}
                },
                "staging": {
                    "severity_filter": "HIGH",
                    "notifications": {"enabled": True}
                },
                "production": {
                    "severity_filter": "INFO",
                    "notifications": {"enabled": True}
                }
            },
            
            # Scheduling configuration
            "scheduling": {
                "daily_scan": {
                    "enabled": False,
                    "time": "02:00"
                },
                "weekly_scan": {
                    "enabled": False,
                    "day": 0,
                    "time": "03:00"
                }
            }
        }
        
        # Load existing config if it exists
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    content = f.read().strip()
                    if content:
                        custom_config = yaml.safe_load(content)
                        if custom_config and isinstance(custom_config, dict):
                            # Deep merge with defaults
                            default_config = self._deep_merge(default_config, custom_config)
            except Exception as e:
                if RICH_AVAILABLE:
                    console.print(f"Warning: Error loading config: {e}", style="yellow")
                else:
                    print(f"Warning: Error loading config: {e}")
        
        return default_config
    
    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """Deep merge two dictionaries"""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
    
    def _setup_logging(self):
        """Setup logging based on configuration"""
        log_config = self.config.get('logging', {})
        log_level = log_config.get('level', 'INFO')
        log_file = log_config.get('file', 'vigileguard.log')
        
        # Configure logging
        logging.basicConfig(
            level=getattr(logging, log_level.upper(), logging.INFO),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    
    def get_environment_config(self, environment: str = None) -> Dict[str, Any]:
        """Get configuration for specific environment"""
        if not environment:
            environment = os.environ.get('VIGILEGUARD_ENV', 'production')
        
        base_config = self.config.copy()
        env_config = self.config.get('environments', {}).get(environment, {})
        
        # Merge environment-specific settings
        if env_config:
            base_config = self._deep_merge(base_config, env_config)
        
        return base_config
    
    def validate_config(self) -> List[str]:
        """Validate configuration and return any issues"""
        issues = []
        
        # Check notification configuration
        notifications = self.config.get('notifications', {})
        if notifications.get('enabled', False):
            channels = notifications.get('channels', [])
            
            if 'email' in channels:
                email_config = notifications.get('email', {})
                if not email_config.get('to_addresses'):
                    issues.append("Email notifications enabled but no recipients configured")
                if not email_config.get('smtp_server'):
                    issues.append("Email notifications enabled but no SMTP server configured")
            
            if 'webhook' in channels:
                webhook_config = notifications.get('webhook', {})
                webhook_url = webhook_config.get('url', '')
                if not webhook_url or not webhook_url.startswith(('http://', 'https://')):
                    issues.append("Webhook notifications enabled but no valid URL configured")
            
            if 'slack' in channels:
                slack_config = notifications.get('slack', {})
                slack_url = slack_config.get('webhook_url', '')
                if not slack_url or not slack_url.startswith(('http://', 'https://')):
                    issues.append("Slack notifications enabled but no valid webhook URL configured")
        
        return issues
    
    def create_sample_config(self, output_path: str = None):
        """Create a sample configuration file"""
        if not output_path:
            output_path = './sample-config.yaml'
        
        with open(output_path, 'w') as f:
            yaml.dump(self.config, f, default_flow_style=False, indent=2)
        
        if RICH_AVAILABLE:
            console.print(f"Sample configuration created: {output_path}", style="green")
        else:
            print(f"Sample configuration created: {output_path}")


class NotificationManager:
    """Manage notifications for security findings"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.notification_config = config.get('notifications', {})
        self.logger = logging.getLogger(__name__)
    
    def should_notify(self, findings: List[Finding]) -> bool:
        """Determine if notifications should be sent"""
        if not self.notification_config.get('enabled', False):
            return False
        
        threshold = self.notification_config.get('severity_threshold', 'HIGH')
        threshold_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        threshold_index = threshold_levels.index(threshold)
        
        # Check if any finding meets the threshold
        for finding in findings:
            finding_index = threshold_levels.index(finding.severity.value)
            if finding_index <= threshold_index:
                return True
        
        return False
    
    def send_notifications(self, findings: List[Finding], scan_info: Dict[str, Any]):
        """Send notifications through configured channels"""
        if not self.should_notify(findings):
            return
        
        channels = self.notification_config.get('channels', [])
        
        for channel in channels:
            try:
                if channel == 'email':
                    email_config = self.notification_config.get('email', {})
                    if self._is_email_configured(email_config):
                        self._send_email_notification(findings, scan_info)
                    else:
                        self.logger.debug("Email notification skipped - not properly configured")
                        
                elif channel == 'webhook':
                    webhook_config = self.notification_config.get('webhook', {})
                    if self._is_webhook_configured(webhook_config):
                        self._send_webhook_notification(findings, scan_info)
                    else:
                        self.logger.debug("Webhook notification skipped - not properly configured")
                        
                elif channel == 'slack':
                    slack_config = self.notification_config.get('slack', {})
                    if self._is_slack_configured(slack_config):
                        self._send_slack_notification(findings, scan_info)
                    else:
                        self.logger.debug("Slack notification skipped - not properly configured")
                        
                else:
                    self.logger.warning(f"Unknown notification channel: {channel}")
            except Exception as e:
                self.logger.error(f"Failed to send {channel} notification: {e}")
    
    def _is_email_configured(self, email_config: Dict[str, Any]) -> bool:
        """Check if email is properly configured"""
        return (email_config.get('smtp_server') and 
                email_config.get('to_addresses') and 
                email_config.get('from_address'))
    
    def _is_webhook_configured(self, webhook_config: Dict[str, Any]) -> bool:
        """Check if webhook is properly configured"""
        url = webhook_config.get('url', '')
        return url and url.startswith(('http://', 'https://'))
    
    def _is_slack_configured(self, slack_config: Dict[str, Any]) -> bool:
        """Check if Slack is properly configured"""
        url = slack_config.get('webhook_url', '')
        return url and url.startswith(('http://', 'https://'))
    
    def _send_email_notification(self, findings: List[Finding], scan_info: Dict[str, Any]):
        """Send email notification"""
        email_config = self.notification_config['email']
        
        # Create email content
        subject = f"VigileGuard Security Alert - {scan_info.get('hostname', 'Unknown Host')}"
        body = self._create_email_body(findings, scan_info)
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = email_config['from_address']
        msg['To'] = ', '.join(email_config['to_addresses'])
        msg['Subject'] = subject
        
        msg.attach(MIMEText(body, 'html'))
        
        # Send email
        with smtplib.SMTP(email_config['smtp_server'], email_config.get('smtp_port', 587)) as server:
            if email_config.get('use_tls', True):
                server.starttls()
            
            if email_config.get('username') and email_config.get('password'):
                server.login(email_config['username'], email_config['password'])
            
            server.sendmail(
                email_config['from_address'],
                email_config['to_addresses'],
                msg.as_string()
            )
        
        self.logger.info(f"Email notification sent to {len(email_config['to_addresses'])} recipients")
    
    def _create_email_body(self, findings: List[Finding], scan_info: Dict[str, Any]) -> str:
        """Create HTML email body"""
        critical_high = sum(1 for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH])
        
        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: #dc3545; color: white; padding: 20px; text-align: center; }}
                .summary {{ padding: 20px; background-color: #f8f9fa; }}
                .finding {{ margin: 10px 0; padding: 10px; border-left: 4px solid #ddd; }}
                .critical {{ border-left-color: #dc3545; }}
                .high {{ border-left-color: #fd7e14; }}
                .medium {{ border-left-color: #ffc107; }}
                .low {{ border-left-color: #28a745; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ VigileGuard Security Alert</h1>
                <p>Security scan completed for {scan_info.get('hostname', 'Unknown Host')}</p>
            </div>
            
            <div class="summary">
                <h2>Scan Summary</h2>
                <ul>
                    <li><strong>Scan Time:</strong> {scan_info.get('timestamp', 'Unknown')}</li>
                    <li><strong>Total Findings:</strong> {len(findings)}</li>
                    <li><strong>Critical/High Issues:</strong> {critical_high}</li>
                </ul>
            </div>
            
            <div>
                <h2>Critical and High Priority Issues</h2>
        """
        
        priority_findings = [f for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
        
        for finding in priority_findings[:10]:  # Limit to top 10
            severity_class = finding.severity.value.lower()
            html_body += f"""
                <div class="finding {severity_class}">
                    <h3>{finding.title}</h3>
                    <p><strong>Severity:</strong> {finding.severity.value}</p>
                    <p><strong>Category:</strong> {finding.category}</p>
                    <p><strong>Description:</strong> {finding.description}</p>
                    <p><strong>Recommendation:</strong> {finding.recommendation}</p>
                </div>
            """
        
        html_body += """
            </div>
            
            <div style="margin-top: 20px; padding: 20px; background-color: #e9ecef;">
                <p><strong>Next Steps:</strong></p>
                <ol>
                    <li>Review all critical and high severity issues immediately</li>
                    <li>Implement recommended security fixes</li>
                    <li>Run VigileGuard again to verify remediation</li>
                </ol>
                
                <p><em>This is an automated message from VigileGuard Security Audit Tool</em></p>
            </div>
        </body>
        </html>
        """
        
        return html_body
    
    def _send_webhook_notification(self, findings: List[Finding], scan_info: Dict[str, Any]):
        """Send webhook notification"""
        webhook_config = self.notification_config['webhook']
        
        # Prepare payload
        payload = {
            'scan_info': scan_info,
            'summary': {
                'total_findings': len(findings),
                'by_severity': self._count_by_severity(findings),
                'timestamp': datetime.now().isoformat()
            },
            'critical_high_findings': [
                f.to_dict() for f in findings 
                if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
            ][:10]  # Limit to first 10
        }
        
        # Send webhook
        response = requests.post(
            webhook_config['url'],
            json=payload,
            headers=webhook_config.get('headers', {}),
            timeout=webhook_config.get('timeout', 30)
        )
        
        response.raise_for_status()
        self.logger.info(f"Webhook notification sent successfully to {webhook_config['url']}")
    
    def _send_slack_notification(self, findings: List[Finding], scan_info: Dict[str, Any]):
        """Send Slack notification"""
        slack_config = self.notification_config['slack']
        
        critical_high = sum(1 for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH])
        
        # Determine alert color based on severity
        if critical_high > 5:
            color = 'danger'  # Red
        elif critical_high > 0:
            color = 'warning'  # Yellow
        else:
            color = 'good'  # Green
        
        # Create Slack message
        slack_payload = {
            'channel': slack_config.get('channel', '#security'),
            'username': slack_config.get('username', 'VigileGuard'),
            'icon_emoji': ':shield:',
            'attachments': [
                {
                    'color': color,
                    'title': f"🛡️ VigileGuard Security Scan - {scan_info.get('hostname', 'Unknown Host')}",
                    'fields': [
                        {
                            'title': 'Total Findings',
                            'value': str(len(findings)),
                            'short': True
                        },
                        {
                            'title': 'Critical/High Issues',
                            'value': str(critical_high),
                            'short': True
                        },
                        {
                            'title': 'Scan Time',
                            'value': scan_info.get('timestamp', 'Unknown'),
                            'short': False
                        }
                    ],
                    'footer': 'VigileGuard Security Audit',
                    'ts': int(datetime.now().timestamp())
                }
            ]
        }
        
        # Add top findings to message
        priority_findings = [f for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]][:5]
        if priority_findings:
            findings_text = "\n".join([
                f"• *{f.severity.value}*: {f.title}" 
                for f in priority_findings
            ])
            slack_payload['attachments'][0]['text'] = f"Top Priority Issues:\n{findings_text}"
        
        # Send to Slack
        response = requests.post(
            slack_config['webhook_url'],
            json=slack_payload,
            timeout=30
        )
        
        response.raise_for_status()
        self.logger.info("Slack notification sent successfully")
    
    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {}
        for finding in findings:
            severity = finding.severity.value
            counts[severity] = counts.get(severity, 0) + 1
        return counts


class WebhookIntegration:
    """Handle webhook integrations for real-time notifications"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def send_scan_started(self, scan_info: Dict[str, Any]):
        """Send notification when scan starts"""
        payload = {
            'event': 'scan_started',
            'timestamp': datetime.now().isoformat(),
            'scan_info': scan_info
        }
        self._send_webhook(payload)
    
    def send_scan_completed(self, findings: List[Finding], scan_info: Dict[str, Any]):
        """Send notification when scan completes"""
        payload = {
            'event': 'scan_completed',
            'timestamp': datetime.now().isoformat(),
            'scan_info': scan_info,
            'summary': {
                'total_findings': len(findings),
                'by_severity': self._count_by_severity(findings),
                'categories': list(set(f.category for f in findings))
            }
        }
        self._send_webhook(payload)
    
    def send_critical_finding(self, finding: Finding, scan_info: Dict[str, Any]):
        """Send immediate notification for critical findings"""
        if finding.severity == SeverityLevel.CRITICAL:
            payload = {
                'event': 'critical_finding',
                'timestamp': datetime.now().isoformat(),
                'scan_info': scan_info,
                'finding': finding.to_dict()
            }
            self._send_webhook(payload)
    
    def _send_webhook(self, payload: Dict[str, Any]):
        """Send webhook with payload"""
        webhook_config = self.config.get('notifications', {}).get('webhook', {})
        
        webhook_url = webhook_config.get('url', '')
        if not webhook_url or not webhook_url.startswith(('http://', 'https://')):
            self.logger.debug("Webhook skipped - no valid URL configured")
            return
        
        try:
            response = requests.post(
                webhook_url,
                json=payload,
                headers=webhook_config.get('headers', {}),
                timeout=webhook_config.get('timeout', 30)
            )
            response.raise_for_status()
            self.logger.debug(f"Webhook sent successfully: {payload['event']}")
        except Exception as e:
            self.logger.error(f"Failed to send webhook: {e}")
    
    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {}
        for finding in findings:
            severity = finding.severity.value
            counts[severity] = counts.get(severity, 0) + 1
        return counts


class SchedulingManager:
    """Handle scheduled scans and recurring audits"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.schedule_config = config.get('scheduling', {})
    
    def create_cron_job(self, schedule: str, command: str) -> bool:
        """Create a cron job for scheduled scans"""
        try:
            # Read current crontab
            result = subprocess.run(['crontab', '-l'], capture_output=True, text=True)
            current_crontab = result.stdout if result.returncode == 0 else ""
            
            # Add new job if not already present
            cron_entry = f"{schedule} {command}"
            if cron_entry not in current_crontab:
                new_crontab = current_crontab + f"\n{cron_entry}\n"
                
                # Write updated crontab
                process = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
                process.communicate(input=new_crontab)
                
                if process.returncode == 0:
                    self.logger.info(f"Cron job created: {cron_entry}")
                    return True
                else:
                    self.logger.error("Failed to create cron job")
                    return False
            else:
                self.logger.info("Cron job already exists")
                return True
                
        except Exception as e:
            self.logger.error(f"Error creating cron job: {e}")
            return False
    
    def setup_daily_scan(self, time: str = "02:00") -> bool:
        """Setup daily security scan"""
        # Get the current script path
        script_path = os.path.abspath(__file__)
        command = f"python3 {script_path} --format json --output /var/log/vigileguard/daily-$(date +\\%Y\\%m\\%d).json"
        
        hour, minute = time.split(':')
        schedule = f"{minute} {hour} * * *"
        
        return self.create_cron_job(schedule, command)
    
    def setup_weekly_scan(self, day: int = 0, time: str = "03:00") -> bool:
        """Setup weekly security scan (0=Sunday, 6=Saturday)"""
        script_path = os.path.abspath(__file__)
        command = f"python3 {script_path} --format json --output /var/log/vigileguard/weekly-$(date +\\%Y\\%m\\%d).json"
        
        hour, minute = time.split(':')
        schedule = f"{minute} {hour} * * {day}"
        
        return self.create_cron_job(schedule, command)


class Phase2AuditEngine:
    """Enhanced audit engine for Phase 2 with web server and network security"""
    
    def __init__(self, config_path: Optional[str] = None, environment: str = None):
        # Initialize logger first
        self.logger = logging.getLogger(__name__)
        
        self.config_manager = ConfigurationManager(config_path)
        self.config = self.config_manager.get_environment_config(environment)
        
        # Initialize notification manager
        self.notification_manager = NotificationManager(self.config)
        self.webhook_integration = WebhookIntegration(self.config)
        self.scheduling_manager = SchedulingManager(self.config)
        
        # Initialize checkers (Phase 1 + Phase 2)
        self.checkers = self._initialize_checkers()
        self.all_findings: List[Finding] = []
    
    def _initialize_checkers(self) -> List[SecurityChecker]:
        """Initialize all security checkers"""
        checkers = []
        
        # Phase 1 checkers
        try:
            from vigileguard import FilePermissionChecker, UserAccountChecker, SSHConfigChecker, SystemInfoChecker
            checkers.extend([
                FilePermissionChecker(),
                UserAccountChecker(),
                SSHConfigChecker(),
                SystemInfoChecker()
            ])
            self.logger.info("Phase 1 checkers loaded successfully")
        except ImportError as e:
            self.logger.warning(f"Could not import Phase 1 checkers: {e}")
        
        # Phase 2 checkers
        try:
            from web_security_checkers import WebServerSecurityChecker, NetworkSecurityChecker
            checkers.extend([
                WebServerSecurityChecker(),
                NetworkSecurityChecker()
            ])
            self.logger.info("Phase 2 checkers loaded successfully")
        except ImportError as e:
            self.logger.warning(f"Could not import Phase 2 checkers: {e}")
        
        # Phase 3 enhanced checkers (new security domains)
        try:
            from container_security_checkers import ContainerSecurityChecker
            checkers.append(ContainerSecurityChecker())
            self.logger.info("Container security checker loaded successfully")
        except ImportError as e:
            self.logger.warning(f"Could not import container security checker: {e}")
        
        try:
            from database_security_checkers import DatabaseSecurityChecker
            checkers.append(DatabaseSecurityChecker())
            self.logger.info("Database security checker loaded successfully")
        except ImportError as e:
            self.logger.warning(f"Could not import database security checker: {e}")
        
        try:
            from process_security_checkers import ProcessServiceSecurityChecker
            checkers.append(ProcessServiceSecurityChecker())
            self.logger.info("Process & service security checker loaded successfully")
        except ImportError as e:
            self.logger.warning(f"Could not import process security checker: {e}")
        
        try:
            from environment_security_checkers import EnvironmentSecurityChecker
            checkers.append(EnvironmentSecurityChecker())
            self.logger.info("Environment security checker loaded successfully")
        except ImportError as e:
            self.logger.warning(f"Could not import environment security checker: {e}")
        
        return checkers
    
    def run_audit(self) -> List[Finding]:
        """Run comprehensive security audit with Phase 2 enhancements"""
        scan_info = {
            'timestamp': datetime.now().isoformat(),
            'tool': 'VigileGuard',
            'version': '3.0.6',
            'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
            'environment': os.environ.get('VIGILEGUARD_ENV', 'production'),
            'repository': 'https://github.com/navinnm/VigileGuard'
        }
        
        if RICH_AVAILABLE:
            console.print(Panel.fit("🛡️ VigileGuard Security Audit", style="bold blue"))
            console.print(f"Environment: {scan_info['environment']}")
            console.print(f"Starting audit at {scan_info['timestamp']}")
            console.print()
        else:
            print("🛡️ VigileGuard Security Audit")
            print(f"Environment: {scan_info['environment']}")
            print(f"Starting audit at {scan_info['timestamp']}")
        
        # Send scan started notification
        self.webhook_integration.send_scan_started(scan_info)
        
        # Run all security checks
        for checker in self.checkers:
            task_name = checker.__class__.__name__
            try:
                if RICH_AVAILABLE:
                    console.print(f"Running {task_name}...", style="blue")
                else:
                    print(f"Running {task_name}...")
                    
                findings = checker.check()
                self.all_findings.extend(findings)
                
                # Send immediate notifications for critical findings
                for finding in findings:
                    if finding.severity == SeverityLevel.CRITICAL:
                        self.webhook_integration.send_critical_finding(finding, scan_info)
                
                if RICH_AVAILABLE:
                    console.print(f"✅ {task_name} completed - {len(findings)} findings", style="green")
                else:
                    print(f"✅ {task_name} completed - {len(findings)} findings")
                
            except Exception as e:
                if RICH_AVAILABLE:
                    console.print(f"❌ Error in {task_name}: {e}", style="red")
                else:
                    print(f"❌ Error in {task_name}: {e}")
                self.logger.error(f"Error in {task_name}: {e}")
        
        # Generate enhanced reports
        try:
            from enhanced_reporting import ReportManager
            report_manager = ReportManager(self.all_findings, scan_info)
            
            # Save reports in configured formats
            output_dir = self.config.get('reporting', {}).get('output_directory', './reports')
            generated_files = report_manager.generate_all_formats(output_dir)
            
            if RICH_AVAILABLE:
                console.print(f"\n📊 Reports generated:", style="bold green")
                for format_type, file_path in generated_files.items():
                    console.print(f"  {format_type.upper()}: {file_path}")
            else:
                print(f"\n📊 Reports generated:")
                for format_type, file_path in generated_files.items():
                    print(f"  {format_type.upper()}: {file_path}")
        except ImportError:
            if RICH_AVAILABLE:
                console.print("⚠️ Enhanced reporting not available", style="yellow")
            else:
                print("⚠️ Enhanced reporting not available")
        
        # Send notifications
        try:
            self.notification_manager.send_notifications(self.all_findings, scan_info)
        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"Warning: Failed to send notifications: {e}", style="yellow")
            else:
                print(f"Warning: Failed to send notifications: {e}")
        
        # Send scan completed notification
        self.webhook_integration.send_scan_completed(self.all_findings, scan_info)
        
        return self.all_findings
    
    def setup_scheduled_scans(self):
        """Setup scheduled scans based on configuration"""
        schedule_config = self.config.get('scheduling', {})
        
        if schedule_config.get('daily_scan', {}).get('enabled', False):
            time = schedule_config['daily_scan'].get('time', '02:00')
            if self.scheduling_manager.setup_daily_scan(time):
                if RICH_AVAILABLE:
                    console.print(f"✅ Daily scan scheduled for {time}", style="green")
                else:
                    print(f"✅ Daily scan scheduled for {time}")
            else:
                if RICH_AVAILABLE:
                    console.print("❌ Failed to setup daily scan", style="red")
                else:
                    print("❌ Failed to setup daily scan")
        
        if schedule_config.get('weekly_scan', {}).get('enabled', False):
            day = schedule_config['weekly_scan'].get('day', 0)
            time = schedule_config['weekly_scan'].get('time', '03:00')
            if self.scheduling_manager.setup_weekly_scan(day, time):
                if RICH_AVAILABLE:
                    console.print(f"✅ Weekly scan scheduled for day {day} at {time}", style="green")
                else:
                    print(f"✅ Weekly scan scheduled for day {day} at {time}")
            else:
                if RICH_AVAILABLE:
                    console.print("❌ Failed to setup weekly scan", style="red")
                else:
                    print("❌ Failed to setup weekly scan")
    
    def validate_configuration(self):
        """Validate current configuration"""
        issues = self.config_manager.validate_config()
        
        if issues:
            if RICH_AVAILABLE:
                console.print("⚠️  Configuration Issues Found:", style="yellow")
                for issue in issues:
                    console.print(f"  • {issue}", style="yellow")
            else:
                print("⚠️  Configuration Issues Found:")
                for issue in issues:
                    print(f"  • {issue}")
            return False
        else:
            if RICH_AVAILABLE:
                console.print("✅ Configuration validation passed", style="green")
            else:
                print("✅ Configuration validation passed")
            return True


# CLI Integration for Phase 2
def main_phase2():
    """Main function for Phase 2 VigileGuard with enhanced features"""
    import click
    
    @click.command()
    @click.option('--config', '-c', help='Configuration file path')
    @click.option('--environment', '-e', help='Environment (development/staging/production)')
    @click.option('--output', '-o', help='Output file path')
    @click.option('--format', '-f', 'output_format', default='console',
                  type=click.Choice(['console', 'json', 'html', 'all']), help='Output format')
    @click.option('--setup-schedule', is_flag=True, help='Setup scheduled scans')
    @click.option('--validate-config', is_flag=True, help='Validate configuration')
    @click.option('--create-sample-config', help='Create sample configuration file')
    @click.option('--debug', is_flag=True, help='Enable debug output')
    def cli(config, environment, output, output_format, setup_schedule, validate_config, create_sample_config, debug):
        """
        VigileGuard Phase 2 - Enhanced Linux Security Audit Tool
        
        Features:
        - Web server security auditing (Apache, Nginx)
        - Network security analysis
        - Enhanced reporting (HTML, compliance mapping)
        - Notification integrations (Email, Slack, Webhooks)
        - Environment-specific configurations
        - Scheduled scanning capabilities
        """
        
        if create_sample_config:
            config_manager = ConfigurationManager()
            config_manager.create_sample_config(create_sample_config)
            return
        
        # Initialize Phase 2 audit engine
        try:
            engine = Phase2AuditEngine(config, environment)
            
            if validate_config:
                engine.validate_configuration()
                return
            
            if setup_schedule:
                engine.setup_scheduled_scans()
                return
            
            # Run the enhanced audit
            findings = engine.run_audit()
            
            # Handle specific output format requests
            if output and output_format != 'all':
                try:
                    from enhanced_reporting import ReportManager
                    report_manager = ReportManager(findings, {
                        'timestamp': datetime.now().isoformat(),
                        'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown',
                        'version': '3.0.6'
                    })
                    
                    if output_format == 'html':
                        report_manager.html_reporter.generate_report(output)
                    elif output_format == 'json':
                        technical_report = report_manager.generate_technical_report()
                        with open(output, 'w') as f:
                            json.dump(technical_report, f, indent=2, default=str)
                    
                    if RICH_AVAILABLE:
                        console.print(f"Report saved to {output}", style="green")
                    else:
                        print(f"Report saved to {output}")
                except ImportError:
                    if RICH_AVAILABLE:
                        console.print("❌ Enhanced reporting not available for specific output formats", style="red")
                    else:
                        print("❌ Enhanced reporting not available for specific output formats")
            
            # Exit with appropriate code
            critical_high_count = sum(1 for f in findings 
                                    if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH])
            
            if critical_high_count > 0:
                if RICH_AVAILABLE:
                    console.print(f"\n⚠️  Found {critical_high_count} critical/high severity issues", style="red")
                else:
                    print(f"\n⚠️  Found {critical_high_count} critical/high severity issues")
                return 1
            else:
                if RICH_AVAILABLE:
                    console.print(f"\n✅ Audit completed successfully", style="green")
                else:
                    print(f"\n✅ Audit completed successfully")
                return 0
                
        except KeyboardInterrupt:
            if RICH_AVAILABLE:
                console.print("\n❌ Audit interrupted by user", style="red")
            else:
                print("\n❌ Audit interrupted by user")
            return 130
        except Exception as e:
            if RICH_AVAILABLE:
                console.print(f"\n❌ Error during audit: {e}", style="red")
            else:
                print(f"\n❌ Error during audit: {e}")
            if debug:
                import traceback
                traceback.print_exc()
            return 1
    
    return cli()


if __name__ == "__main__":
    exit(main_phase2())