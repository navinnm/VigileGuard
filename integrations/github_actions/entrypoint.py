#!/usr/bin/env python3
"""
VigileGuard GitHub Actions Entrypoint

Runs security audits in GitHub Actions workflow with full integration support.
"""

import os
import sys
import json
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import requests
import uuid


class GitHubActionsIntegration:
    """GitHub Actions integration for VigileGuard"""
    
    def __init__(self):
        self.workspace = os.environ.get('GITHUB_WORKSPACE', '/github/workspace')
        self.repository = os.environ.get('GITHUB_REPOSITORY', '')
        self.sha = os.environ.get('GITHUB_SHA', '')
        self.ref = os.environ.get('GITHUB_REF', '')
        self.event_name = os.environ.get('GITHUB_EVENT_NAME', '')
        self.pr_number = os.environ.get('GITHUB_PR_NUMBER', '')
        self.github_token = os.environ.get('GITHUB_TOKEN', '')
        
        # VigileGuard configuration
        self.target = os.environ.get('VIGILEGUARD_TARGET', '')
        self.config_file = os.environ.get('VIGILEGUARD_CONFIG', '.vigileguard.yml')
        self.checkers = os.environ.get('VIGILEGUARD_CHECKERS', 'all')
        self.fail_critical = os.environ.get('VIGILEGUARD_FAIL_CRITICAL', 'true').lower() == 'true'
        self.fail_high = os.environ.get('VIGILEGUARD_FAIL_HIGH', 'false').lower() == 'true'
        self.output_format = os.environ.get('VIGILEGUARD_FORMAT', 'json')
        self.upload_results = os.environ.get('VIGILEGUARD_UPLOAD', 'true').lower() == 'true'
        self.comment_pr = os.environ.get('VIGILEGUARD_PR_COMMENT', 'false').lower() == 'true'
        self.api_endpoint = os.environ.get('VIGILEGUARD_API_ENDPOINT', '')
        self.api_key = os.environ.get('VIGILEGUARD_API_KEY', '')
        self.webhook_url = os.environ.get('VIGILEGUARD_WEBHOOK_URL', '')
        self.severity_threshold = os.environ.get('VIGILEGUARD_SEVERITY_THRESHOLD', 'medium')
        self.timeout = int(os.environ.get('VIGILEGUARD_TIMEOUT', '300'))
        
        # Generate unique scan ID
        self.scan_id = f"gh_{self.repository.replace('/', '_')}_{self.sha[:8]}_{uuid.uuid4().hex[:8]}"
        self.report_path = f"/app/reports/vigileguard_report_{self.scan_id}"
    
    def log(self, message: str, level: str = "INFO"):
        """Log message with GitHub Actions formatting"""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {level}: {message}")
    
    def error(self, message: str):
        """Log error message"""
        self.log(message, "ERROR")
        print(f"::error::{message}")
    
    def warning(self, message: str):
        """Log warning message"""
        self.log(message, "WARNING")
        print(f"::warning::{message}")
    
    def set_output(self, name: str, value: str):
        """Set GitHub Actions output"""
        # Write to GITHUB_OUTPUT file if available (new format)
        github_output = os.environ.get('GITHUB_OUTPUT')
        if github_output:
            with open(github_output, 'a') as f:
                f.write(f"{name}={value}\n")
        else:
            # Fallback to old format
            print(f"::set-output name={name}::{value}")
    
    def mask_secret(self, secret: str):
        """Mask secret in logs"""
        if secret:
            print(f"::add-mask::{secret}")
    
    def group(self, name: str):
        """Start a collapsible group in logs"""
        print(f"::group::{name}")
    
    def endgroup(self):
        """End a collapsible group in logs"""
        print("::endgroup::")
    
    def validate_inputs(self) -> bool:
        """Validate required inputs"""
        if not self.target:
            self.error("Target is required. Please specify the target to scan.")
            return False
        
        # Check if config file exists
        config_path = os.path.join(self.workspace, self.config_file)
        if not os.path.exists(config_path) and self.config_file != '.vigileguard.yml':
            self.warning(f"Config file not found: {config_path}. Using default configuration.")
        
        # Mask sensitive inputs
        if self.api_key:
            self.mask_secret(self.api_key)
        if self.webhook_url:
            self.mask_secret(self.webhook_url)
        
        return True
    
    def run_scan(self) -> Dict[str, Any]:
        """Run VigileGuard security scan"""
        self.group("Running VigileGuard Security Scan")
        
        try:
            # Build command
            cmd = [
                'python', '-m', 'vigileguard.vigileguard',
                '--target', self.target,
                '--format', self.output_format,
                '--output', self.report_path
            ]
            
            # Add checkers
            if self.checkers and self.checkers != 'all':
                for checker in self.checkers.split(','):
                    cmd.extend(['--checker', checker.strip()])
            
            # Add config file
            config_path = os.path.join(self.workspace, self.config_file)
            if os.path.exists(config_path):
                cmd.extend(['--config', config_path])
            
            # Add timeout
            cmd.extend(['--timeout', str(self.timeout)])
            
            self.log(f"Running command: {' '.join(cmd[:-2])} [config-file] [timeout]")
            
            # Run scan
            result = subprocess.run(
                cmd,
                cwd=self.workspace,
                capture_output=True,
                text=True,
                timeout=self.timeout + 30  # Add buffer to command timeout
            )
            
            # Log output
            if result.stdout:
                self.log("Scan output:")
                print(result.stdout)
            
            if result.stderr:
                self.log("Scan errors:")
                print(result.stderr)
            
            # Parse results
            scan_results = self.parse_scan_results()
            
            self.endgroup()
            return scan_results
            
        except subprocess.TimeoutExpired:
            self.error(f"Scan timed out after {self.timeout} seconds")
            self.endgroup()
            return {"error": "timeout", "status": "failed"}
        
        except Exception as e:
            self.error(f"Failed to run scan: {str(e)}")
            self.endgroup()
            return {"error": str(e), "status": "failed"}
    
    def parse_scan_results(self) -> Dict[str, Any]:
        """Parse scan results from report file"""
        try:
            # Try to read JSON report
            json_report_path = f"{self.report_path}.json"
            if os.path.exists(json_report_path):
                with open(json_report_path, 'r') as f:
                    results = json.load(f)
                    return self.extract_metrics(results)
            
            # Try to read other formats
            html_report_path = f"{self.report_path}.html"
            if os.path.exists(html_report_path):
                self.log("HTML report generated successfully")
                return {"status": "completed", "format": "html"}
            
            # Default response
            return {"status": "completed", "format": "unknown"}
            
        except Exception as e:
            self.error(f"Failed to parse scan results: {str(e)}")
            return {"error": str(e), "status": "failed"}
    
    def extract_metrics(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key metrics from scan results"""
        summary = results.get('summary', {})
        
        return {
            "status": "completed",
            "critical_count": summary.get('critical', 0),
            "high_count": summary.get('high', 0),
            "medium_count": summary.get('medium', 0),
            "low_count": summary.get('low', 0),
            "total_issues": summary.get('failed', 0),
            "compliance_score": results.get('compliance_score', 0),
            "scan_duration": results.get('scan_duration', 0),
            "target": results.get('target', self.target),
            "timestamp": results.get('timestamp', datetime.utcnow().isoformat())
        }
    
    def determine_build_status(self, results: Dict[str, Any]) -> str:
        """Determine if build should pass or fail"""
        if results.get("error"):
            return "failed"
        
        critical_count = results.get("critical_count", 0)
        high_count = results.get("high_count", 0)
        
        if self.fail_critical and critical_count > 0:
            return "failed"
        
        if self.fail_high and high_count > 0:
            return "failed"
        
        if critical_count > 0 or high_count > 0:
            return "warning"
        
        return "passed"
    
    def upload_artifacts(self, results: Dict[str, Any]):
        """Upload scan results as GitHub Actions artifacts"""
        if not self.upload_results:
            return
        
        self.group("Uploading Artifacts")
        
        try:
            # Create artifacts directory
            artifacts_dir = "/tmp/vigileguard-artifacts"
            os.makedirs(artifacts_dir, exist_ok=True)
            
            # Copy report files
            for ext in ['.json', '.html', '.pdf']:
                report_file = f"{self.report_path}{ext}"
                if os.path.exists(report_file):
                    artifact_file = f"{artifacts_dir}/vigileguard-report{ext}"
                    subprocess.run(['cp', report_file, artifact_file], check=True)
                    self.log(f"Prepared artifact: vigileguard-report{ext}")
            
            # Create summary file
            summary_file = f"{artifacts_dir}/scan-summary.json"
            with open(summary_file, 'w') as f:
                json.dump({
                    "scan_id": self.scan_id,
                    "repository": self.repository,
                    "commit": self.sha,
                    "timestamp": datetime.utcnow().isoformat(),
                    "results": results
                }, f, indent=2)
            
            self.log("Artifacts prepared for upload")
            
        except Exception as e:
            self.warning(f"Failed to prepare artifacts: {str(e)}")
        
        self.endgroup()
    
    def comment_on_pr(self, results: Dict[str, Any]):
        """Comment scan results on pull request"""
        if not self.comment_pr or not self.pr_number or not self.github_token:
            return
        
        self.group("Commenting on Pull Request")
        
        try:
            # Generate comment content
            comment = self.generate_pr_comment(results)
            
            # Post comment using GitHub CLI
            cmd = [
                'gh', 'pr', 'comment', self.pr_number,
                '--repo', self.repository,
                '--body', comment
            ]
            
            env = os.environ.copy()
            env['GITHUB_TOKEN'] = self.github_token
            
            result = subprocess.run(cmd, env=env, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.log("Successfully commented on pull request")
            else:
                self.warning(f"Failed to comment on PR: {result.stderr}")
        
        except Exception as e:
            self.warning(f"Failed to comment on pull request: {str(e)}")
        
        self.endgroup()
    
    def generate_pr_comment(self, results: Dict[str, Any]) -> str:
        """Generate pull request comment content"""
        status = self.determine_build_status(results)
        status_emoji = {
            "passed": "✅",
            "warning": "⚠️",
            "failed": "❌"
        }
        
        comment = f"""## {status_emoji.get(status, '🔍')} VigileGuard Security Scan Results

**Scan ID:** `{self.scan_id}`
**Target:** `{self.target}`
**Status:** {status.upper()}
**Commit:** {self.sha[:8]}

### 📊 Summary
- **Critical Issues:** {results.get('critical_count', 0)}
- **High Issues:** {results.get('high_count', 0)}
- **Medium Issues:** {results.get('medium_count', 0)}
- **Low Issues:** {results.get('low_count', 0)}
- **Total Issues:** {results.get('total_issues', 0)}
- **Compliance Score:** {results.get('compliance_score', 0):.1f}%

"""
        
        if status == "failed":
            comment += "### ❌ Build Failed\n"
            if results.get('critical_count', 0) > 0 and self.fail_critical:
                comment += "- Critical security issues found (fail-on-critical enabled)\n"
            if results.get('high_count', 0) > 0 and self.fail_high:
                comment += "- High severity issues found (fail-on-high enabled)\n"
        elif status == "warning":
            comment += "### ⚠️ Security Issues Found\n"
            comment += "- Review and address the identified security issues\n"
        else:
            comment += "### ✅ Security Scan Passed\n"
            comment += "- No critical security issues detected\n"
        
        comment += f"\n📋 **Detailed Report:** Check the GitHub Actions artifacts for complete results.\n"
        comment += f"🕐 **Scanned at:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
        
        return comment
    
    def send_webhook_notification(self, results: Dict[str, Any]):
        """Send webhook notification"""
        if not self.webhook_url:
            return
        
        self.group("Sending Webhook Notification")
        
        try:
            status = self.determine_build_status(results)
            
            payload = {
                "scan_id": self.scan_id,
                "repository": self.repository,
                "commit": self.sha,
                "branch": self.ref,
                "target": self.target,
                "status": status,
                "results": results,
                "timestamp": datetime.utcnow().isoformat(),
                "github_actions_url": f"https://github.com/{self.repository}/actions"
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=30,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                self.log("Webhook notification sent successfully")
            else:
                self.warning(f"Webhook notification failed: {response.status_code}")
        
        except Exception as e:
            self.warning(f"Failed to send webhook notification: {str(e)}")
        
        self.endgroup()
    
    def set_action_outputs(self, results: Dict[str, Any]):
        """Set GitHub Actions outputs"""
        status = self.determine_build_status(results)
        
        self.set_output("scan-id", self.scan_id)
        self.set_output("report-path", self.report_path)
        self.set_output("critical-count", str(results.get("critical_count", 0)))
        self.set_output("high-count", str(results.get("high_count", 0)))
        self.set_output("medium-count", str(results.get("medium_count", 0)))
        self.set_output("low-count", str(results.get("low_count", 0)))
        self.set_output("total-issues", str(results.get("total_issues", 0)))
        self.set_output("compliance-score", str(results.get("compliance_score", 0)))
        self.set_output("scan-status", status)
        
        # Set artifacts URL if uploaded
        if self.upload_results:
            artifacts_url = f"https://github.com/{self.repository}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}"
            self.set_output("artifacts-url", artifacts_url)
    
    def run(self):
        """Main execution function"""
        self.log("🛡️  VigileGuard Security Audit - GitHub Actions Integration")
        self.log(f"Repository: {self.repository}")
        self.log(f"Commit: {self.sha}")
        self.log(f"Target: {self.target}")
        
        # Validate inputs
        if not self.validate_inputs():
            sys.exit(1)
        
        # Run security scan
        results = self.run_scan()
        
        # Determine status
        status = self.determine_build_status(results)
        
        # Upload artifacts
        self.upload_artifacts(results)
        
        # Comment on PR
        self.comment_on_pr(results)
        
        # Send webhook notification
        self.send_webhook_notification(results)
        
        # Set outputs
        self.set_action_outputs(results)
        
        # Final status
        self.log(f"Scan completed with status: {status.upper()}")
        
        if results.get("critical_count", 0) > 0:
            self.log(f"⚠️  {results['critical_count']} critical security issues found!")
        if results.get("high_count", 0) > 0:
            self.log(f"⚠️  {results['high_count']} high severity issues found!")
        
        # Exit with appropriate code
        if status == "failed":
            self.error("Security scan failed - critical issues found")
            sys.exit(1)
        elif status == "warning":
            self.warning("Security scan completed with warnings")
            sys.exit(0)
        else:
            self.log("✅ Security scan passed successfully")
            sys.exit(0)


if __name__ == "__main__":
    integration = GitHubActionsIntegration()
    integration.run()