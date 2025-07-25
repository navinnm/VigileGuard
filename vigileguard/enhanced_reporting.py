#!/usr/bin/env python3
"""
VigileGuard Phase 2: Enhanced Reporting System
HTML reports, compliance mapping, and trend tracking
"""

import json
import os
import subprocess
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
import tempfile
import hashlib



# Handle imports gracefully - support both relative and absolute imports
try:
    from .vigileguard import SeverityLevel, Finding
except ImportError:
    try:
        from vigileguard import SeverityLevel, Finding
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

class PDFReporter:
    """PDF report generator using HTML to PDF conversion"""
    
    def __init__(self, findings: List[Finding], scan_info: Dict[str, Any], server_summary: Optional[Dict[str, Any]] = None):
        self.findings = findings
        self.scan_info = scan_info
        self.server_summary = server_summary or {}
        self.html_reporter = HTMLReporter(findings, scan_info, server_summary)
    
    def generate_report(self, output_path: str) -> str:
        """Generate PDF report from HTML using wkhtmltopdf or alternative methods"""
        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        # Try multiple PDF generation methods
        methods = [
            self._generate_with_wkhtmltopdf,
            self._generate_with_weasyprint,
            self._generate_with_simple_pdf,
            self._generate_fallback_html
        ]
        
        for method in methods:
            try:
                result = method(output_path)
                if result:
                    return result
            except Exception as e:
                print(f"PDF generation method failed: {e}")
                continue
        
        # If all methods fail, return the HTML file path as fallback
        html_path = output_path.replace('.pdf', '.html')
        return self.html_reporter.generate_report(html_path)
    
    def _generate_with_wkhtmltopdf(self, output_path: str) -> Optional[str]:
        """Generate PDF using wkhtmltopdf"""
        # Check if wkhtmltopdf is available
        try:
            subprocess.run(['wkhtmltopdf', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return None
        
        # Create temporary HTML file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as temp_html:
            html_content = self._create_pdf_optimized_html()
            temp_html.write(html_content)
            temp_html_path = temp_html.name
        
        try:
            # Generate PDF using wkhtmltopdf with optimized settings
            cmd = [
                'wkhtmltopdf',
                '--page-size', 'A4',
                '--orientation', 'Portrait',
                '--margin-top', '0.75in',
                '--margin-right', '0.75in',
                '--margin-bottom', '0.75in',
                '--margin-left', '0.75in',
                '--encoding', 'UTF-8',
                '--enable-local-file-access',
                '--disable-javascript',  # Disable JS for PDF generation
                temp_html_path,
                output_path
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0 and os.path.exists(output_path):
                return output_path
            else:
                print(f"wkhtmltopdf error: {result.stderr}")
                return None
                
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_html_path)
            except:
                pass
    
    def _generate_with_weasyprint(self, output_path: str) -> Optional[str]:
        """Generate PDF using WeasyPrint (Python library)"""
        try:
            import weasyprint
            
            html_content = self._create_pdf_optimized_html()
            
            # Generate PDF
            html_doc = weasyprint.HTML(string=html_content)
            html_doc.write_pdf(output_path)
            
            if os.path.exists(output_path):
                return output_path
            else:
                return None
                
        except ImportError:
            return None
        except Exception as e:
            print(f"WeasyPrint error: {e}")
            return None
    
    def _generate_with_simple_pdf(self, output_path: str) -> Optional[str]:
        """Generate PDF using simple HTML to PDF conversion"""
        try:
            # Try using browser-based conversion if available
            html_content = self._create_pdf_optimized_html()
            
            # Save as temporary HTML file
            temp_html = output_path.replace('.pdf', '_temp.html')
            with open(temp_html, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            # Try chromium/chrome headless
            chrome_commands = [
                'google-chrome',
                'chromium-browser', 
                'chromium',
                'chrome'
            ]
            
            for cmd in chrome_commands:
                try:
                    result = subprocess.run([
                        cmd, '--headless', '--disable-gpu', '--no-sandbox',
                        '--print-to-pdf=' + output_path,
                        'file://' + os.path.abspath(temp_html)
                    ], capture_output=True, timeout=30)
                    
                    if result.returncode == 0 and os.path.exists(output_path):
                        os.unlink(temp_html)  # Clean up
                        return output_path
                except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                    continue
            
            # Clean up temp file if PDF generation failed
            try:
                os.unlink(temp_html)
            except:
                pass
                
            return None
            
        except Exception as e:
            print(f"Simple PDF generation error: {e}")
            return None
    
    def _generate_fallback_html(self, output_path: str) -> str:
        """Fallback: Generate HTML file when PDF generation fails"""
        html_path = output_path.replace('.pdf', '_fallback.html')
        return self.html_reporter.generate_report(html_path)
    
    def _create_pdf_optimized_html(self) -> str:
        """Create HTML optimized for PDF generation (no JavaScript, embedded CSS)"""
        server_header = self.html_reporter._generate_server_header()
        summary = self.html_reporter._generate_summary()
        findings_html = self._generate_pdf_findings_html()
        server_details = self.html_reporter._generate_server_details_section()
        
        # Create PDF-optimized template without JavaScript and with print-friendly styles
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VigileGuard Security Report - {self.server_summary.get('hostname', 'Security Audit')}</title>
    <style>
        {self._get_pdf_css_styles()}
    </style>
</head>
<body>
    <div class="container">
        <!-- Enhanced Server Information Header -->
        {server_header}
        
        <!-- Main Header -->
        <header class="main-header">
            <h1>🛡️ VigileGuard Security Report</h1>
            <small>Powered by Fulgid v{self.scan_info.get('version', '3.0.7')}</small>
            <div class="scan-info">
                <p><strong>Scan Date:</strong> {self.scan_info.get('timestamp', 'Unknown')}</p>
                <p><strong>Tool Version:</strong> {self.scan_info.get('version', '3.0.7')}</p>
                <p><strong>Repository:</strong> {self.scan_info.get('repository', '#')}</p>
            </div>
        </header>
        
        <!-- Summary Section -->
        <section class="summary">
            {summary}
        </section>
        
        <!-- Security Findings -->
        <section class="findings">
            <h2>Security Findings</h2>
            {findings_html}
        </section>
        
        <!-- Detailed Server Information -->
        {server_details}
        
        <footer class="footer">
            <p>Generated by VigileGuard v{self.scan_info.get('version', '3.0.7')} | 
            <a href="{self.scan_info.get('repository', '#')}">GitHub Repository</a></p>
        </footer>
    </div>
</body>
</html>
        """
        return html_template
    
    def _generate_pdf_findings_html(self) -> str:
        """Generate findings HTML optimized for PDF (no collapsible sections)"""
        if not self.findings:
            return """
            <div class="no-findings">
                <h3>✅ No Security Issues Found</h3>
                <p>Congratulations! VigileGuard did not detect any security issues during this scan.</p>
            </div>
            """
        
        # Generate affected files section (expanded for PDF)
        findings_html = self._generate_pdf_affected_files_section()
        
        # Separate security findings from informational findings
        security_findings = [f for f in self.findings if f.severity != SeverityLevel.INFO]
        info_findings = [f for f in self.findings if f.severity == SeverityLevel.INFO]
        
        if security_findings:
            # Group security findings by severity
            findings_by_severity = {}
            for finding in security_findings:
                severity = finding.severity.value
                if severity not in findings_by_severity:
                    findings_by_severity[severity] = []
                findings_by_severity[severity].append(finding)
            
            # Order by severity
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            
            for severity in severity_order:
                if severity in findings_by_severity:
                    findings_html += f"""
                    <div class="severity-section">
                        <h3 class="severity-header severity-{severity.lower()}">{severity} Issues ({len(findings_by_severity[severity])})</h3>
                    """
                    
                    for finding in findings_by_severity[severity]:
                        findings_html += self.html_reporter._generate_finding_card(finding)
                    
                    findings_html += "</div>"
        
        # Add informational findings (expanded for PDF)
        if info_findings:
            findings_html += f"""
            <div class="info-section">
                <h3 class="info-header">📋 System Information ({len(info_findings)} items)</h3>
                <div class="info-content expanded">
            """
            
            for finding in info_findings:
                findings_html += self.html_reporter._generate_finding_card(finding)
            
            findings_html += """
                </div>
            </div>
            """
        
        return findings_html
    
    def _generate_pdf_affected_files_section(self) -> str:
        """Generate expanded affected files section for PDF"""
        file_issues = {}
        folder_issues = {}
        
        # Extract file and folder information from findings
        for finding in self.findings:
            if finding.details and isinstance(finding.details, dict):
                files_found = self._extract_file_paths_pdf(finding.details)
                
                for file_path in files_found:
                    if file_path not in file_issues:
                        file_issues[file_path] = []
                    file_issues[file_path].append({
                        'title': finding.title,
                        'severity': finding.severity.value,
                        'category': finding.category
                    })
                    
                    folder = os.path.dirname(file_path) if file_path != '/' else '/'
                    if folder and folder not in folder_issues:
                        folder_issues[folder] = set()
                    if folder:
                        folder_issues[folder].add(finding.category)
        
        if not file_issues and not folder_issues:
            return ""
        
        section_html = """
        <section class="affected-files-section">
            <h3>📁 Affected Files and Folders</h3>
            <div class="affected-files-content expanded">
        """
        
        # Generate folder summary (always expanded for PDF)
        if folder_issues:
            section_html += """
            <div class="folder-summary">
                <h4>📂 Folders with Issues</h4>
                <div class="folder-grid">
            """
            
            for folder, categories in sorted(folder_issues.items()):
                issue_count = sum(len(issues) for path, issues in file_issues.items() 
                                if path.startswith(folder + '/') or path == folder)
                section_html += f"""
                <div class="folder-item">
                    <div class="folder-path">{folder or '/'}</div>
                    <div class="folder-stats">
                        <span class="issue-count">{issue_count} issues</span>
                        <span class="category-list">{', '.join(sorted(categories))}</span>
                    </div>
                </div>
                """
            
            section_html += "</div></div>"
        
        # Generate file details (always expanded for PDF)
        if file_issues:
            section_html += """
            <div class="file-details">
                <h4>📄 Files with Specific Issues</h4>
                <div class="file-list">
            """
            
            for file_path, issues in sorted(file_issues.items()):
                highest_severity = self._get_highest_severity_pdf(issues)
                section_html += f"""
                <div class="file-item severity-{highest_severity.lower()}">
                    <div class="file-header">
                        <span class="file-icon">📄</span>
                        <div class="file-path">{file_path}</div>
                        <span class="severity-badge severity-{highest_severity.lower()}">{highest_severity}</span>
                    </div>
                    <div class="file-issues">
                """
                
                for issue in issues:
                    section_html += f"""
                    <div class="issue-item">
                        <span class="issue-title">{issue['title']}</span>
                        <span class="issue-category">{issue['category']}</span>
                    </div>
                    """
                
                section_html += "</div></div>"
            
            section_html += "</div></div>"
        
        section_html += "</div></section>"
        return section_html
    
    def _extract_file_paths_pdf(self, details: Dict[str, Any]) -> List[str]:
        """Extract file paths from finding details for PDF reporter"""
        file_paths = []
        
        # Common keys that might contain file paths
        path_keys = ['file', 'path', 'config_file', 'files', 'affected_files', 'file_path', 'location']
        
        for key, value in details.items():
            if any(path_key in key.lower() for path_key in path_keys):
                if isinstance(value, str) and (value.startswith('/') or value.startswith('./')):
                    file_paths.append(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and (item.startswith('/') or item.startswith('./')):
                            file_paths.append(item)
                        elif isinstance(item, dict) and 'path' in item:
                            file_paths.append(item['path'])
        
        return file_paths
    
    def _get_highest_severity_pdf(self, issues: List[Dict[str, str]]) -> str:
        """Get the highest severity from a list of issues for PDF reporter"""
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        
        highest = 'INFO'
        for issue in issues:
            severity = issue.get('severity', 'INFO')
            if severity_order.index(severity) < severity_order.index(highest):
                highest = severity
        
        return highest
    
    def _get_pdf_css_styles(self) -> str:
        """Get CSS styles optimized for PDF generation"""
        base_css = self.html_reporter._get_css_styles()
        
        # Add PDF-specific styles
        pdf_css = """
        /* PDF-specific styles */
        @media print {
            body {
                font-size: 11pt;
                line-height: 1.4;
            }
            
            .container {
                max-width: none;
                margin: 0;
                padding: 10pt;
            }
            
            .main-header {
                page-break-inside: avoid;
                margin-bottom: 20pt;
            }
            
            .severity-section {
                page-break-inside: avoid;
                margin-bottom: 15pt;
            }
            
            .finding-card {
                page-break-inside: avoid;
                margin-bottom: 10pt;
            }
            
            .server-info-header {
                page-break-inside: avoid;
            }
            
            .summary {
                page-break-inside: avoid;
            }
            
            .charts {
                display: none; /* Hide charts in PDF */
            }
            
            /* Ensure sections don't break across pages */
            h2, h3, h4 {
                page-break-after: avoid;
            }
            
            /* Make sure collapsible content is visible */
            .info-content, .affected-files-content {
                display: block !important;
            }
            
            /* Hide toggle controls */
            .info-header, .section-header {
                cursor: default;
            }
            
            /* Adjust spacing for print */
            .detail-item {
                margin-bottom: 8pt;
            }
            
            .file-item, .folder-item {
                margin-bottom: 8pt;
            }
        }
        
        /* Always show content in PDF mode */
        .info-content.expanded,
        .affected-files-content.expanded {
            display: block !important;
        }
        """
        
        return base_css + pdf_css


class HTMLReporter:
    """Enhanced HTML reporter with comprehensive server information display"""
    
    def __init__(self, findings: List[Finding], scan_info: Dict[str, Any], server_summary: Optional[Dict[str, Any]] = None):
        self.findings = findings
        self.scan_info = scan_info
        self.server_summary = server_summary or {}
    
    def generate_report(self, output_path: str) -> str:
        """Generate comprehensive HTML report with server information"""
        html_content = self._create_html_template()
        
        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
    
    def _create_html_template(self) -> str:
        """Create comprehensive HTML report template"""
        server_header = self._generate_server_header()
        summary = self._generate_summary()
        findings_html = self._generate_findings_html()
        charts_data = self._generate_charts_data()
        server_details = self._generate_server_details_section()
        
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VigileGuard Security Report - {self.server_summary.get('hostname', 'Security Audit')}</title>
    <style>
        {self._get_css_styles()}
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
</head>
<body>
    <div class="container">
        <!-- Enhanced Server Information Header -->
        {server_header}
        
        <!-- Main Header -->
        <header class="main-header">
            <h1>🛡️ VigileGuard Security Report</h1>
            <small>Powered by Fulgid v{self.scan_info.get('version', '3.0.7')}</small>
            <div class="scan-info">
                <p><strong>Scan Date:</strong> {self.scan_info.get('timestamp', 'Unknown')}</p>
                <p><strong>Tool Version:</strong> {self.scan_info.get('version', '3.0.7')}</p>
                <p><strong>Repository:</strong> <a href="{self.scan_info.get('repository', '#')}">GitHub</a></p>
            </div>
        </header>
        
        <!-- Summary Section -->
        <section class="summary">
            {summary}
        </section>
        
        <!-- Charts Section -->
        <section class="charts">
            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="categoryChart"></canvas>
            </div>
        </section>
        
        <!-- Security Findings -->
        <section class="findings">
            <h2>Security Findings</h2>
            {findings_html}
        </section>
        
        <!-- Detailed Server Information -->
        {server_details}
        
        <footer class="footer">
            <p>Generated by VigileGuard v{self.scan_info.get('version', '3.0.7')} | 
            <a href="{self.scan_info.get('repository', '#')}">GitHub Repository</a></p>
        </footer>
    </div>
    
    <script>
        {self._get_javascript_code(charts_data)}
    </script>
</body>
</html>
        """
        return html_template
    
    def _generate_server_header(self) -> str:
        """Generate enhanced server information header"""
        if not self.server_summary:
            return ""
        
        return f"""
        <div class="server-info-header">
            <div class="server-card">
                <h2>🖥️ Server Information</h2>
                <div class="server-details">
                    <div class="detail-item">
                        <span class="detail-icon">🌐</span>
                        <div class="detail-content">
                            <strong>Primary IP:</strong>
                            <span class="detail-value">{self.server_summary.get('primary_ip', 'Unknown')}</span>
                        </div>
                    </div>
                    <div class="detail-item">
                        <span class="detail-icon">🏷️</span>
                        <div class="detail-content">
                            <strong>Domain:</strong>
                            <span class="detail-value">{self.server_summary.get('primary_domain', 'No domain configured')}</span>
                        </div>
                    </div>
                    <div class="detail-item">
                        <span class="detail-icon">🖥️</span>
                        <div class="detail-content">
                            <strong>Web Server:</strong>
                            <span class="detail-value">{self.server_summary.get('primary_web_server', 'None detected')}</span>
                        </div>
                    </div>
                    <div class="detail-item">
                        <span class="detail-icon">💻</span>
                        <div class="detail-content">
                            <strong>Languages:</strong>
                            <span class="detail-value">{', '.join(self.server_summary.get('primary_languages', ['None detected']))}</span>
                        </div>
                    </div>
                    <div class="detail-item">
                        <span class="detail-icon">🐧</span>
                        <div class="detail-content">
                            <strong>Operating System:</strong>
                            <span class="detail-value">{self.server_summary.get('os_info', 'Unknown')}</span>
                        </div>
                    </div>
                    <div class="detail-item">
                        <span class="detail-icon">🏠</span>
                        <div class="detail-content">
                            <strong>Hostname:</strong>
                            <span class="detail-value">{self.server_summary.get('hostname', 'Unknown')}</span>
                        </div>
                    </div>
                    <div class="detail-item">
                        <span class="detail-icon">🔌</span>
                        <div class="detail-content">
                            <strong>Network Services:</strong>
                            <span class="detail-value">{self.server_summary.get('total_services', 0)}</span>
                        </div>
                    </div>
                    <div class="detail-item">
                        <span class="detail-icon">📡</span>
                        <div class="detail-content">
                            <strong>IP Addresses:</strong>
                            <span class="detail-value">{self._count_total_ips()}</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        """
    
    def _count_total_ips(self) -> int:
        """Count total IP addresses from server info"""
        server_info = self.server_summary.get('server_info', {})
        ip_addresses = server_info.get('ip_addresses', {})
        total = 0
        for interface_info in ip_addresses.values():
            total += len(interface_info.get('ips', []))
        return total
    
    def _generate_summary(self) -> str:
        """Generate enhanced summary section"""
        severity_counts = {}
        category_counts = {}
        
        for finding in self.findings:
            # Count by severity
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by category
            category = finding.category
            category_counts[category] = category_counts.get(category, 0) + 1
        
        total_findings = len(self.findings)
        critical_high = severity_counts.get('CRITICAL', 0) + severity_counts.get('HIGH', 0)
        
        # Determine overall risk level
        if critical_high > 5:
            risk_level = "HIGH RISK"
            risk_class = "risk-high"
        elif critical_high > 0:
            risk_level = "MEDIUM RISK"
            risk_class = "risk-medium"
        else:
            risk_level = "LOW RISK"
            risk_class = "risk-low"
        
        # Server metrics
        server_metrics = ""
        if self.server_summary:
            server_info = self.server_summary.get('server_info', {})
            server_metrics = f"""
            <div class="server-metrics">
                <h3>📊 Server Metrics</h3>
                <div class="metrics-grid">
                    <div class="metric-item">
                        <span class="metric-icon">🌐</span>
                        <div class="metric-content">
                            <span class="metric-label">Network Interfaces</span>
                            <span class="metric-value">{len(server_info.get('ip_addresses', {}))}</span>
                        </div>
                    </div>
                    <div class="metric-item">
                        <span class="metric-icon">🏷️</span>
                        <div class="metric-content">
                            <span class="metric-label">Domain Names</span>
                            <span class="metric-value">{len(server_info.get('domain_names', []))}</span>
                        </div>
                    </div>
                    <div class="metric-item">
                        <span class="metric-icon">🖥️</span>
                        <div class="metric-content">
                            <span class="metric-label">Web Servers</span>
                            <span class="metric-value">{len(server_info.get('web_servers', []))}</span>
                        </div>
                    </div>
                    <div class="metric-item">
                        <span class="metric-icon">💻</span>
                        <div class="metric-content">
                            <span class="metric-label">Programming Languages</span>
                            <span class="metric-value">{len(server_info.get('installed_languages', {}))}</span>
                        </div>
                    </div>
                </div>
            </div>
            """
        
        summary_html = f"""
        <div class="summary-cards">
            <div class="summary-card total">
                <h3>Total Findings</h3>
                <div class="number">{total_findings}</div>
            </div>
            <div class="summary-card {risk_class}">
                <h3>Risk Level</h3>
                <div class="risk-level">{risk_level}</div>
            </div>
            <div class="summary-card critical">
                <h3>Critical/High</h3>
                <div class="number">{critical_high}</div>
            </div>
        </div>
        
        {server_metrics}
        
        <div class="severity-breakdown">
            <h3>Severity Breakdown</h3>
            <div class="severity-grid">
        """
        
        severity_colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14', 
            'MEDIUM': '#ffc107',
            'LOW': '#20c997',
            'INFO': '#6c757d'
        }
        
        for severity, color in severity_colors.items():
            count = severity_counts.get(severity, 0)
            summary_html += f"""
                <div class="severity-item">
                    <span class="severity-badge" style="background-color: {color};">{severity}</span>
                    <span class="severity-count">{count}</span>
                </div>
            """
        
        summary_html += """
            </div>
        </div>
        """
        
        return summary_html
    
    def _generate_findings_html(self) -> str:
        """Generate findings section HTML"""
        if not self.findings:
            return """
            <div class="no-findings">
                <h3>✅ No Security Issues Found</h3>
                <p>Congratulations! VigileGuard did not detect any security issues during this scan.</p>
            </div>
            """
        
        # Separate security findings from informational findings
        security_findings = [f for f in self.findings if f.severity != SeverityLevel.INFO]
        info_findings = [f for f in self.findings if f.severity == SeverityLevel.INFO]
        
        findings_html = ""
        
        if security_findings:
            # Group security findings by severity
            findings_by_severity = {}
            for finding in security_findings:
                severity = finding.severity.value
                if severity not in findings_by_severity:
                    findings_by_severity[severity] = []
                findings_by_severity[severity].append(finding)
            
            # Order by severity
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            
            for severity in severity_order:
                if severity in findings_by_severity:
                    findings_html += f"""
                    <div class="severity-section">
                        <h3 class="severity-header severity-{severity.lower()}">{severity} Issues ({len(findings_by_severity[severity])})</h3>
                    """
                    
                    for finding in findings_by_severity[severity]:
                        findings_html += self._generate_finding_card(finding)
                    
                    findings_html += "</div>"
        
        # Add informational findings in a collapsible section
        if info_findings:
            findings_html += f"""
            <div class="info-section">
                <h3 class="info-header" onclick="toggleInfoSection()">
                    📋 System Information ({len(info_findings)} items) <span id="info-toggle">▼</span>
                </h3>
                <div id="info-content" class="info-content">
            """
            
            for finding in info_findings:
                findings_html += self._generate_finding_card(finding)
            
            findings_html += """
                </div>
            </div>
            """
        
        return findings_html
    
    def _generate_finding_card(self, finding: Finding) -> str:
        """Generate individual finding card"""
        details_html = ""
        if finding.details:
            # Format details nicely
            if isinstance(finding.details, dict):
                details_items = []
                for key, value in finding.details.items():
                    if isinstance(value, (list, dict)):
                        details_items.append(f"<strong>{key}:</strong> {len(value) if isinstance(value, list) else len(value)} items")
                    else:
                        details_items.append(f"<strong>{key}:</strong> {value}")
                
                if details_items:
                    details_html = f"""
                    <div class="finding-details">
                        <strong>Details:</strong>
                        <ul>{''.join(f'<li>{item}</li>' for item in details_items[:5])}</ul>
                        {f'<p><em>... and {len(details_items) - 5} more items</em></p>' if len(details_items) > 5 else ''}
                    </div>
                    """
        
        severity_class = finding.severity.value.lower()
        
        return f"""
        <div class="finding-card severity-{severity_class}">
            <div class="finding-header">
                <h4>{finding.title}</h4>
                <span class="severity-badge severity-{severity_class}">{finding.severity.value}</span>
            </div>
            <div class="finding-category">Category: {finding.category}</div>
            <div class="finding-description">{finding.description}</div>
            <div class="finding-recommendation">
                <strong>Recommendation:</strong> {finding.recommendation}
            </div>
            {details_html}
        </div>
        """
    
    def _generate_server_details_section(self) -> str:
        """Generate detailed server information section"""
        if not self.server_summary or not self.server_summary.get('server_info'):
            return ""
        
        server_info = self.server_summary['server_info']
        
        return f"""
        <section class="server-details">
            <h2>📋 Detailed Server Information</h2>
            
            <div class="details-grid">
                <div class="detail-section">
                    <h3>🌐 Network Configuration</h3>
                    <div class="detail-content">
                        {self._format_network_details(server_info.get('ip_addresses', {}))}
                    </div>
                </div>
                
                <div class="detail-section">
                    <h3>🌍 Domain Configuration</h3>
                    <div class="detail-content">
                        {self._format_domain_details(server_info.get('domain_names', []))}
                    </div>
                </div>
                
                <div class="detail-section">
                    <h3>🖥️ Web Servers</h3>
                    <div class="detail-content">
                        {self._format_web_server_details(server_info.get('web_servers', []))}
                    </div>
                </div>
                
                <div class="detail-section">
                    <h3>💻 Programming Languages</h3>
                    <div class="detail-content">
                        {self._format_language_details(server_info.get('installed_languages', {}))}
                    </div>
                </div>
                
                <div class="detail-section">
                    <h3>🔌 Network Services</h3>
                    <div class="detail-content">
                        {self._format_network_services(server_info.get('network_services', []))}
                    </div>
                </div>
                
                <div class="detail-section">
                    <h3>⚙️ System Information</h3>
                    <div class="detail-content">
                        {self._format_system_details(server_info.get('system_info', {}))}
                    </div>
                </div>
            </div>
        </section>
        """
    
    def _format_network_details(self, ip_addresses: Dict) -> str:
        """Format network interface details"""
        if not ip_addresses:
            return "<p>No network information available</p>"
        
        details = ""
        for interface, info in ip_addresses.items():
            status_class = "status-up" if info.get('status') == 'UP' else "status-down"
            details += f"""
            <div class='interface-item'>
                <div class="interface-header">
                    <strong>{interface}</strong>
                    <span class="status-badge {status_class}">{info.get('status', 'unknown')}</span>
                </div>
            """
            if info.get('ips'):
                details += "<ul>"
                for ip in info['ips']:
                    ip_type_class = f"ip-{ip.get('type', 'unknown')}"
                    details += f"<li class='{ip_type_class}'>{ip['ip']} ({ip.get('type', 'unknown')})</li>"
                details += "</ul>"
            details += "</div>"
        
        return details
    
    def _format_domain_details(self, domains: List) -> str:
        """Format domain details"""
        if not domains:
            return "<p>No domains configured</p>"
        
        details = "<ul>"
        for domain in domains:
            type_class = f"domain-{domain.get('type', 'unknown').replace('_', '-')}"
            details += f"<li class='{type_class}'><strong>{domain['domain']}</strong> <span class='domain-type'>({domain.get('type', 'unknown')})</span></li>"
        details += "</ul>"
        
        return details
    
    def _format_web_server_details(self, web_servers: List) -> str:
        """Format web server details"""
        if not web_servers:
            return "<p>No web servers detected</p>"
        
        details = ""
        for server in web_servers:
            status_class = "status-running" if server.get('status') == 'running' else "status-installed"
            version = server.get('version', 'unknown version')
            status = server.get('status', 'unknown')
            
            details += f"""
            <div class='server-item'>
                <div class="server-header">
                    <strong>{server['name']}</strong>
                    <span class="status-badge {status_class}">{status}</span>
                </div>
                <div class="server-version">Version: {version}</div>
            </div>
            """
        
        return details
    
    def _format_language_details(self, languages: Dict) -> str:
        """Format programming language details"""
        if not languages:
            return "<p>No programming languages detected</p>"
        
        details = ""
        for lang, info in languages.items():
            version = info.get('version', 'unknown version')
            package_managers = info.get('package_managers', [])
            
            details += f"""
            <div class='language-item'>
                <div class="language-header">
                    <strong>{lang}</strong>
                    <span class="version-badge">{version}</span>
                </div>
            """
            if package_managers:
                details += f"<div class='package-managers'>Package Managers: {', '.join(package_managers)}</div>"
            details += "</div>"
        
        return details
    
    def _format_network_services(self, services: List) -> str:
        """Format network services details"""
        if not services:
            return "<p>No network services detected</p>"
        
        # Group services by type
        service_groups = {}
        for service in services[:20]:  # Limit to first 20 services
            service_name = service.get('service_name', 'Unknown')
            if service_name not in service_groups:
                service_groups[service_name] = []
            service_groups[service_name].append(service)
        
        details = ""
        for service_name, service_list in service_groups.items():
            details += f"""
            <div class='service-group'>
                <strong>{service_name}</strong>
                <ul>
            """
            for service in service_list:
                port = service.get('port', 'unknown')
                ip = service.get('ip', 'unknown')
                process = service.get('process', 'unknown')
                details += f"<li>Port {port} on {ip} ({process})</li>"
            details += "</ul></div>"
        
        if len(services) > 20:
            details += f"<p><em>... and {len(services) - 20} more services</em></p>"
        
        return details
    
    def _format_system_details(self, system_info: Dict) -> str:
        """Format system information details"""
        if not system_info:
            return "<p>No system information available</p>"
        
        details = "<div class='system-info'>"
        
        # Key system information
        key_info = {
            'pretty_name': 'Operating System',
            'kernel': 'Kernel',
            'memory_total': 'Total Memory',
            'cpu_cores': 'CPU Cores',
            'cpu_model': 'CPU Model',
            'disk_total': 'Disk Space',
            'uptime': 'System Uptime'
        }
        
        for key, label in key_info.items():
            if key in system_info:
                value = system_info[key]
                details += f"<div class='system-item'><strong>{label}:</strong> {value}</div>"
        
        details += "</div>"
        return details
    
    def _generate_charts_data(self) -> Dict[str, Any]:
        """Generate data for charts"""
        severity_counts = {}
        category_counts = {}
        
        for finding in self.findings:
            # Count by severity
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by category
            category = finding.category
            category_counts[category] = category_counts.get(category, 0) + 1
        
        return {
            'severity': severity_counts,
            'category': category_counts
        }
    
    def _get_css_styles(self) -> str:
        """Get comprehensive CSS styles for the report"""
        return """
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f8f9fa;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Server Information Header */
        .server-info-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        
        .server-card h2 {
            text-align: center;
            margin-bottom: 25px;
            font-size: 2.2rem;
        }
        
        .server-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 15px;
        }
        
        .detail-item {
            background: rgba(255, 255, 255, 0.1);
            padding: 15px;
            border-radius: 10px;
            backdrop-filter: blur(10px);
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .detail-icon {
            font-size: 1.5rem;
            width: 30px;
            text-align: center;
        }
        
        .detail-content {
            flex: 1;
        }
        
        .detail-content strong {
            display: block;
            color: #fff;
            margin-bottom: 2px;
        }
        
        .detail-value {
            color: #e0e0e0;
            font-size: 0.9rem;
        }
        
        /* Main Header */
        .main-header {
            background: #fff;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .main-header h1 {
            color: #333;
            margin-bottom: 15px;
            font-size: 2.5rem;
        }
        
        .scan-info {
            display: flex;
            justify-content: center;
            gap: 30px;
            flex-wrap: wrap;
        }
        
        /* Summary Section */
        .summary {
            margin-bottom: 30px;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .summary-card h3 {
            color: #666;
            margin-bottom: 10px;
        }
        
        .summary-card .number {
            font-size: 2rem;
            font-weight: bold;
            color: #333;
        }
        
        .summary-card .risk-level {
            font-size: 1.5rem;
            font-weight: bold;
        }
        
        .risk-high .risk-level { color: #dc3545; }
        .risk-medium .risk-level { color: #fd7e14; }
        .risk-low .risk-level { color: #28a745; }
        
        /* Server Metrics */
        .server-metrics {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        
        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .metric-item {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        
        .metric-icon {
            font-size: 1.2rem;
        }
        
        .metric-content {
            flex: 1;
        }
        
        .metric-label {
            display: block;
            font-size: 0.8rem;
            color: #666;
        }
        
        .metric-value {
            font-weight: bold;
            font-size: 1.1rem;
            color: #333;
        }
        
        /* Severity Breakdown */
        .severity-breakdown {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .severity-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        
        .severity-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        
        .severity-badge {
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }
        
        .severity-count {
            font-weight: bold;
            font-size: 1.2rem;
        }
        
        /* Charts */
        .charts {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-bottom: 30px;
        }
        
        .chart-container {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        /* Findings */
        .findings {
            margin-bottom: 30px;
        }
        
        .findings h2 {
            margin-bottom: 20px;
            color: #333;
        }
        
        .no-findings {
            background: white;
            padding: 40px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .no-findings h3 {
            color: #28a745;
            margin-bottom: 15px;
        }
        
        .severity-section {
            margin-bottom: 30px;
        }
        
        .severity-header {
            padding: 15px;
            border-radius: 10px 10px 0 0;
            color: white;
            font-size: 1.3rem;
            margin-bottom: 0;
        }
        
        .severity-critical { background-color: #dc3545; }
        .severity-high { background-color: #fd7e14; }
        .severity-medium { background-color: #ffc107; color: #333; }
        .severity-low { background-color: #28a745; }
        .severity-info { background-color: #6c757d; }
        
        /* Info Section */
        .info-section {
            margin-top: 30px;
        }
        
        .info-header {
            background-color: #6c757d;
            color: white;
            padding: 15px;
            border-radius: 10px;
            cursor: pointer;
            user-select: none;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .info-header:hover {
            background-color: #5a6268;
        }
        
        .info-content {
            display: none;
            background: white;
            border-radius: 0 0 10px 10px;
        }
        
        .info-content.show {
            display: block;
        }
        
        /* Finding Cards */
        .finding-card {
            background: white;
            border-left: 5px solid #ddd;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 0 10px 10px 0;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .finding-card.severity-critical { border-left-color: #dc3545; }
        .finding-card.severity-high { border-left-color: #fd7e14; }
        .finding-card.severity-medium { border-left-color: #ffc107; }
        .finding-card.severity-low { border-left-color: #28a745; }
        .finding-card.severity-info { border-left-color: #6c757d; }
        
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .finding-header h4 {
            color: #333;
            margin: 0;
        }
        
        .severity-badge.severity-critical { background-color: #dc3545; }
        .severity-badge.severity-high { background-color: #fd7e14; }
        .severity-badge.severity-medium { background-color: #ffc107; color: #333; }
        .severity-badge.severity-low { background-color: #28a745; }
        .severity-badge.severity-info { background-color: #6c757d; }
        
        .finding-category {
            color: #666;
            font-size: 0.9rem;
            margin-bottom: 10px;
        }
        
        .finding-description {
            margin-bottom: 15px;
            line-height: 1.6;
        }
        
        .finding-recommendation {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        
        .finding-details {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
        }
        
        .finding-details ul {
            margin-left: 20px;
        }
        
        /* Server Details Section */
        .server-details {
            margin-bottom: 30px;
        }
        
        .server-details h2 {
            margin-bottom: 20px;
            color: #333;
        }
        
        .details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
        }
        
        .detail-section {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .detail-section h3 {
            color: #333;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 2px solid #e9ecef;
        }
        
        /* Network Details */
        .interface-item {
            margin-bottom: 15px;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        
        .interface-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 5px;
        }
        
        .status-badge {
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .status-up { background-color: #28a745; color: white; }
        .status-down { background-color: #dc3545; color: white; }
        
        .interface-item ul {
            margin-left: 20px;
            margin-top: 5px;
        }
        
        .ip-public { color: #dc3545; font-weight: bold; }
        .ip-private { color: #28a745; }
        .ip-loopback { color: #6c757d; }
        
        /* Domain Details */
        .domain-type {
            font-size: 0.8rem;
            color: #666;
        }
        
        /* Server Details */
        .server-item {
            margin-bottom: 10px;
            padding: 8px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        
        .server-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .status-running { background-color: #28a745; color: white; }
        .status-installed { background-color: #6c757d; color: white; }
        
        .server-version {
            font-size: 0.8rem;
            color: #666;
            margin-top: 2px;
        }
        
        /* Language Details */
        .language-item {
            margin-bottom: 10px;
            padding: 8px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        
        .language-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .version-badge {
            background-color: #007bff;
            color: white;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.7rem;
        }
        
        .package-managers {
            font-size: 0.8rem;
            color: #666;
            margin-top: 2px;
        }
        
        /* Service Details */
        .service-group {
            margin-bottom: 10px;
            padding: 8px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        
        .service-group ul {
            margin-left: 20px;
            margin-top: 5px;
        }
        
        /* System Info */
        .system-info {
            display: grid;
            gap: 8px;
        }
        
        .system-item {
            padding: 8px;
            background: #f8f9fa;
            border-radius: 5px;
        }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            border-top: 1px solid #ddd;
        }
        
        .footer a {
            color: #667eea;
            text-decoration: none;
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            .server-details {
                grid-template-columns: 1fr;
            }
            
            .scan-info {
                flex-direction: column;
                gap: 10px;
            }
            
            .finding-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }
            
            .charts {
                grid-template-columns: 1fr;
            }
            
            .details-grid {
                grid-template-columns: 1fr;
            }
        }
        """
    
    def _get_javascript_code(self, charts_data: Dict[str, Any]) -> str:
        """Get JavaScript code for charts and interactions"""
        return f"""
        // Chart.js configuration
        const severityData = {json.dumps(charts_data['severity'])};
        const categoryData = {json.dumps(charts_data['category'])};
        
        // Only create charts if there's data
        if (Object.keys(severityData).length > 0) {{
            // Severity Chart
            const severityCtx = document.getElementById('severityChart').getContext('2d');
            new Chart(severityCtx, {{
                type: 'doughnut',
                data: {{
                    labels: Object.keys(severityData),
                    datasets: [{{
                        data: Object.values(severityData),
                        backgroundColor: [
                            '#dc3545',  // CRITICAL
                            '#fd7e14',  // HIGH
                            '#ffc107',  // MEDIUM
                            '#28a745',  // LOW
                            '#6c757d'   // INFO
                        ]
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        title: {{
                            display: true,
                            text: 'Findings by Severity'
                        }},
                        legend: {{
                            position: 'bottom'
                        }}
                    }}
                }}
            }});
        }} else {{
            document.getElementById('severityChart').style.display = 'none';
        }}
        
        // Category Chart
        if (Object.keys(categoryData).length > 0) {{
            const categoryCtx = document.getElementById('categoryChart').getContext('2d');
            new Chart(categoryCtx, {{
                type: 'bar',
                data: {{
                    labels: Object.keys(categoryData),
                    datasets: [{{
                        label: 'Findings',
                        data: Object.values(categoryData),
                        backgroundColor: 'rgba(102, 126, 234, 0.8)',
                        borderColor: 'rgba(102, 126, 234, 1)',
                        borderWidth: 1
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        title: {{
                            display: true,
                            text: 'Findings by Category'
                        }}
                    }},
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            ticks: {{
                                stepSize: 1
                            }}
                        }}
                    }}
                }}
            }});
        }} else {{
            document.getElementById('categoryChart').style.display = 'none';
        }}
        
        // Toggle info section
        function toggleInfoSection() {{
            const content = document.getElementById('info-content');
            const toggle = document.getElementById('info-toggle');
            
            if (content.classList.contains('show')) {{
                content.classList.remove('show');
                toggle.textContent = '▼';
            }} else {{
                content.classList.add('show');
                toggle.textContent = '▲';
            }}
        }}
        
        // Toggle affected files section
        function toggleAffectedFiles() {{
            const content = document.getElementById('affected-files-content');
            const toggle = document.getElementById('files-toggle');
            
            if (content.classList.contains('show')) {{
                content.classList.remove('show');
                toggle.textContent = '▼';
            }} else {{
                content.classList.add('show');
                toggle.textContent = '▲';
            }}
        }}
        """

class ComplianceMapper:
    """Map security findings to compliance frameworks"""
    
    def __init__(self):
        self.framework_mappings = {
            'PCI_DSS': {
                'description': 'Payment Card Industry Data Security Standard',
                'mappings': {
                    'File Permissions': ['2.2.4', '7.1.1'],
                    'User Accounts': ['7.1.2', '8.1.1', '8.2.3'],
                    'SSH': ['2.3', '8.2.1'],
                    'Web Server': ['2.2.3', '6.5.10'],
                    'Network Security': ['1.3.1', '2.2.2'],
                    'SSL/TLS': ['4.1.1', '8.2.1'],
                    'Web Application': ['6.5.1', '6.5.7']
                }
            },
            'SOC_2': {
                'description': 'Service Organization Control 2',
                'mappings': {
                    'File Permissions': ['CC6.1', 'CC6.3'],
                    'User Accounts': ['CC6.1', 'CC6.2'],
                    'SSH': ['CC6.1', 'CC6.7'],
                    'Web Server': ['CC6.1', 'CC6.8'],
                    'Network Security': ['CC6.1', 'CC6.6'],
                    'SSL/TLS': ['CC6.1', 'CC6.7'],
                    'Web Application': ['CC6.1', 'CC6.8']
                }
            },
            'NIST_CSF': {
                'description': 'NIST Cybersecurity Framework',
                'mappings': {
                    'File Permissions': ['PR.AC-1', 'PR.AC-4'],
                    'User Accounts': ['PR.AC-1', 'PR.AC-7'],
                    'SSH': ['PR.AC-3', 'PR.AC-7'],
                    'Web Server': ['PR.AC-3', 'PR.PT-3'],
                    'Network Security': ['PR.AC-3', 'PR.AC-5'],
                    'SSL/TLS': ['PR.DS-2', 'PR.DS-6'],
                    'Web Application': ['PR.AC-3', 'PR.DS-1']
                }
            },
            'ISO_27001': {
                'description': 'ISO/IEC 27001:2013',
                'mappings': {
                    'File Permissions': ['A.9.1.1', 'A.9.2.3'],
                    'User Accounts': ['A.9.2.1', 'A.9.2.2'],
                    'SSH': ['A.9.4.2', 'A.13.1.1'],
                    'Web Server': ['A.13.1.1', 'A.14.1.3'],
                    'Network Security': ['A.13.1.1', 'A.13.1.3'],
                    'SSL/TLS': ['A.13.1.1', 'A.13.2.3'],
                    'Web Application': ['A.14.1.3', 'A.14.2.1']
                }
            }
        }
    
    def generate_compliance_report(self, findings: List[Finding], frameworks: List[str] = None) -> Dict[str, Any]:
        """Generate compliance mapping report"""
        if frameworks is None:
            frameworks = list(self.framework_mappings.keys())
        
        compliance_report = {
            'scan_timestamp': datetime.now().isoformat(),
            'frameworks': {},
            'coverage_summary': {},
            'recommendations': []
        }
        
        for framework in frameworks:
            if framework in self.framework_mappings:
                compliance_report['frameworks'][framework] = self._map_findings_to_framework(
                    findings, framework
                )
        
        compliance_report['coverage_summary'] = self._calculate_coverage_summary(findings, frameworks)
        compliance_report['recommendations'] = self._generate_compliance_recommendations(findings, frameworks)
        
        return compliance_report
    
    def _map_findings_to_framework(self, findings: List[Finding], framework: str) -> Dict[str, Any]:
        """Map findings to specific compliance framework"""
        framework_data = self.framework_mappings[framework]
        mapped_findings = {}
        
        for finding in findings:
            category = finding.category
            if category in framework_data['mappings']:
                controls = framework_data['mappings'][category]
                for control in controls:
                    if control not in mapped_findings:
                        mapped_findings[control] = []
                    mapped_findings[control].append({
                        'title': finding.title,
                        'severity': finding.severity.value,
                        'category': finding.category,
                        'description': finding.description
                    })
        
        return {
            'description': framework_data['description'],
            'mapped_controls': mapped_findings,
            'total_controls_affected': len(mapped_findings),
            'total_findings_mapped': sum(len(findings) for findings in mapped_findings.values())
        }
    
    def _calculate_coverage_summary(self, findings: List[Finding], frameworks: List[str]) -> Dict[str, Any]:
        """Calculate compliance coverage summary"""
        summary = {}
        
        for framework in frameworks:
            if framework in self.framework_mappings:
                framework_data = self.framework_mappings[framework]
                total_controls = sum(len(controls) for controls in framework_data['mappings'].values())
                
                mapped_findings = self._map_findings_to_framework(findings, framework)
                affected_controls = mapped_findings['total_controls_affected']
                
                coverage_percentage = (affected_controls / total_controls * 100) if total_controls > 0 else 0
                
                summary[framework] = {
                    'total_controls': total_controls,
                    'affected_controls': affected_controls,
                    'coverage_percentage': round(coverage_percentage, 2),
                    'compliance_level': self._determine_compliance_level(coverage_percentage)
                }
        
        return summary
    
    def _determine_compliance_level(self, coverage_percentage: float) -> str:
        """Determine compliance level based on coverage"""
        if coverage_percentage < 20:
            return "Good"
        elif coverage_percentage < 50:
            return "Needs Attention"
        else:
            return "Requires Immediate Action"
    
    def _generate_compliance_recommendations(self, findings: List[Finding], frameworks: List[str]) -> List[Dict[str, Any]]:
        """Generate compliance-specific recommendations"""
        recommendations = []
        
        # Group findings by severity
        critical_high_findings = [f for f in findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
        
        if critical_high_findings:
            recommendations.append({
                'priority': 'High',
                'title': 'Address Critical and High Severity Issues',
                'description': f'Found {len(critical_high_findings)} critical/high severity issues that impact compliance',
                'frameworks_affected': frameworks,
                'estimated_effort': 'High'
            })
        
        # Category-specific recommendations
        category_counts = {}
        for finding in findings:
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
        
        if category_counts.get('User Accounts', 0) > 3:
            recommendations.append({
                'priority': 'Medium',
                'title': 'Implement Comprehensive Identity and Access Management',
                'description': 'Multiple user account issues detected affecting compliance frameworks',
                'frameworks_affected': ['PCI_DSS', 'SOC_2', 'ISO_27001'],
                'estimated_effort': 'Medium'
            })
        
        if category_counts.get('Network Security', 0) > 2:
            recommendations.append({
                'priority': 'Medium',
                'title': 'Strengthen Network Security Controls',
                'description': 'Network security gaps detected that impact multiple compliance requirements',
                'frameworks_affected': ['PCI_DSS', 'NIST_CSF'],
                'estimated_effort': 'Medium'
            })
        
        return recommendations


class TrendTracker:
    """Track security trends over time"""
    
    def __init__(self, storage_path: str = "./vigileguard_trends"):
        self.storage_path = Path(storage_path)
        try:
            self.storage_path.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # Fallback to current directory if we can't create the preferred path
            self.storage_path = Path("./trends")
            self.storage_path.mkdir(parents=True, exist_ok=True)
    
    def record_scan(self, findings: List[Finding], scan_info: Dict[str, Any]) -> str:
        """Record scan results for trend analysis"""
        scan_id = self._generate_scan_id(scan_info)
        
        trend_data = {
            'scan_id': scan_id,
            'timestamp': scan_info.get('timestamp', datetime.now().isoformat()),
            'hostname': scan_info.get('hostname', 'unknown'),
            'summary': self._generate_scan_summary(findings),
            'findings_count': len(findings),
            'categories': self._count_by_category(findings),
            'severities': self._count_by_severity(findings)
        }
        
        # Save to file
        trend_file = self.storage_path / f"scan_{scan_id}.json"
        with open(trend_file, 'w') as f:
            json.dump(trend_data, f, indent=2, default=str)
        
        return scan_id
    
    def generate_trend_report(self, hostname: str = None, days: int = 30) -> Dict[str, Any]:
        """Generate trend analysis report"""
        scans = self._load_recent_scans(hostname, days)
        
        if len(scans) < 2:
            return {
                'error': 'Insufficient data for trend analysis',
                'scans_found': len(scans),
                'minimum_required': 2
            }
        
        trend_report = {
            'analysis_period': f"{days} days",
            'total_scans': len(scans),
            'hostname_filter': hostname,
            'trends': {
                'overall': self._analyze_overall_trend(scans),
                'by_category': self._analyze_category_trends(scans),
                'by_severity': self._analyze_severity_trends(scans)
            },
            'recommendations': self._generate_trend_recommendations(scans)
        }
        
        return trend_report
    
    def _generate_scan_id(self, scan_info: Dict[str, Any]) -> str:
        """Generate unique scan ID"""
        hostname = scan_info.get('hostname', 'unknown')
        timestamp = scan_info.get('timestamp', datetime.now().isoformat())
        
        # Create hash from hostname and timestamp
        hash_input = f"{hostname}_{timestamp}".encode()
        return hashlib.md5(hash_input).hexdigest()[:12]
    
    def _generate_scan_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate summary of scan results"""
        return {
            'total_findings': len(findings),
            'risk_score': self._calculate_risk_score(findings),
            'categories_affected': len(set(f.category for f in findings)),
            'highest_severity': max([f.severity.value for f in findings], default='INFO')
        }
    
    def _calculate_risk_score(self, findings: List[Finding]) -> int:
        """Calculate numerical risk score"""
        severity_weights = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 2,
            'INFO': 1
        }
        
        score = sum(severity_weights.get(f.severity.value, 1) for f in findings)
        return min(score, 100)  # Cap at 100
    
    def _count_by_category(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by category"""
        counts = {}
        for finding in findings:
            counts[finding.category] = counts.get(finding.category, 0) + 1
        return counts
    
    def _count_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {}
        for finding in findings:
            severity = finding.severity.value
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def _load_recent_scans(self, hostname: str = None, days: int = 30) -> List[Dict[str, Any]]:
        """Load recent scan data"""
        cutoff_date = datetime.now() - timedelta(days=days)
        scans = []
        
        for scan_file in self.storage_path.glob("scan_*.json"):
            try:
                with open(scan_file, 'r') as f:
                    scan_data = json.load(f)
                
                # Parse timestamp
                timestamp_str = scan_data['timestamp']
                if timestamp_str.endswith('Z'):
                    timestamp_str = timestamp_str[:-1] + '+00:00'
                scan_timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                
                # Filter by date and hostname
                if scan_timestamp >= cutoff_date:
                    if hostname is None or scan_data.get('hostname') == hostname:
                        scans.append(scan_data)
                        
            except (json.JSONDecodeError, KeyError, ValueError):
                continue
        
        # Sort by timestamp
        scans.sort(key=lambda x: x['timestamp'])
        return scans
    
    def _analyze_overall_trend(self, scans: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze overall security trend"""
        if len(scans) < 2:
            return {'trend': 'insufficient_data'}
        
        first_scan = scans[0]
        last_scan = scans[-1]
        
        findings_change = last_scan['findings_count'] - first_scan['findings_count']
        risk_change = last_scan['summary']['risk_score'] - first_scan['summary']['risk_score']
        
        if findings_change < 0 and risk_change < 0:
            trend = 'improving'
        elif findings_change > 0 or risk_change > 0:
            trend = 'deteriorating'
        else:
            trend = 'stable'
        
        return {
            'trend': trend,
            'findings_change': findings_change,
            'risk_score_change': risk_change,
            'period_start': first_scan['timestamp'],
            'period_end': last_scan['timestamp'],
            'total_scans_analyzed': len(scans)
        }
    
    def _analyze_category_trends(self, scans: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Analyze trends by category"""
        category_trends = {}
        
        # Get all categories
        all_categories = set()
        for scan in scans:
            all_categories.update(scan['categories'].keys())
        
        for category in all_categories:
            category_data = []
            for scan in scans:
                count = scan['categories'].get(category, 0)
                category_data.append(count)
            
            if len(category_data) >= 2:
                change = category_data[-1] - category_data[0]
                avg_count = sum(category_data) / len(category_data)
                
                category_trends[category] = {
                    'change': change,
                    'average_count': round(avg_count, 2),
                    'trend': 'improving' if change < 0 else 'deteriorating' if change > 0 else 'stable'
                }
        
        return category_trends
    
    def _analyze_severity_trends(self, scans: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Analyze trends by severity"""
        severity_trends = {}
        severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        
        for severity in severities:
            severity_data = []
            for scan in scans:
                count = scan['severities'].get(severity, 0)
                severity_data.append(count)
            
            if len(severity_data) >= 2:
                change = severity_data[-1] - severity_data[0]
                avg_count = sum(severity_data) / len(severity_data)
                
                severity_trends[severity] = {
                    'change': change,
                    'average_count': round(avg_count, 2),
                    'trend': 'improving' if change < 0 else 'deteriorating' if change > 0 else 'stable'
                }
        
        return severity_trends
    
    def _generate_trend_recommendations(self, scans: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Generate recommendations based on trends"""
        recommendations = []
        
        if len(scans) < 2:
            return recommendations
        
        # Check for increasing critical/high issues
        latest_scan = scans[-1]
        previous_scan = scans[-2] if len(scans) >= 2 else scans[0]
        
        critical_high_latest = latest_scan['severities'].get('CRITICAL', 0) + latest_scan['severities'].get('HIGH', 0)
        critical_high_previous = previous_scan['severities'].get('CRITICAL', 0) + previous_scan['severities'].get('HIGH', 0)
        
        if critical_high_latest > critical_high_previous:
            recommendations.append({
                'priority': 'High',
                'title': 'Critical/High severity issues increasing',
                'description': f'Critical and high severity issues increased from {critical_high_previous} to {critical_high_latest}',
                'action': 'Immediate attention required to address new critical security issues'
            })
        
        # Check for consistently high risk scores
        recent_risk_scores = [scan['summary']['risk_score'] for scan in scans[-5:]]
        avg_risk = sum(recent_risk_scores) / len(recent_risk_scores)
        
        if avg_risk > 70:
            recommendations.append({
                'priority': 'High',
                'title': 'Consistently high risk scores',
                'description': f'Average risk score over recent scans: {avg_risk:.1f}/100',
                'action': 'Implement comprehensive security improvements to reduce overall risk'
            })
        
        return recommendations


class ReportManager:
    """Manage different types of security reports"""
    
    def __init__(self, findings: List[Finding], scan_info: Dict[str, Any], server_summary: Optional[Dict[str, Any]] = None):
        self.findings = findings
        self.scan_info = scan_info
        self.server_summary = server_summary or {}
        self.html_reporter = HTMLReporter(findings, scan_info, server_summary)
        self.pdf_reporter = PDFReporter(findings, scan_info, server_summary)
        self.compliance_mapper = ComplianceMapper()
        self.trend_tracker = TrendTracker()
    
    def generate_executive_summary(self) -> Dict[str, Any]:
        """Generate executive summary for leadership"""
        summary = {
            'scan_overview': {
                'timestamp': self.scan_info.get('timestamp'),
                'hostname': self.scan_info.get('hostname'),
                'total_findings': len(self.findings),
                'scan_duration': 'Not tracked'
            },
            'risk_assessment': self._calculate_risk_assessment(),
            'top_priorities': self._get_top_priorities(),
            'compliance_impact': self._assess_compliance_impact(),
            'resource_requirements': self._estimate_resource_requirements(),
            'executive_recommendations': self._generate_executive_recommendations()
        }
        
        return summary
    
    def generate_technical_report(self, include_trends: bool = True) -> Dict[str, Any]:
        """Generate detailed technical report"""
        report = {
            'scan_metadata': self.scan_info,
            'findings_summary': self._generate_detailed_summary(),
            'detailed_findings': [finding.to_dict() for finding in self.findings],
            'compliance_mapping': self.compliance_mapper.generate_compliance_report(self.findings),
            'remediation_guide': self._generate_remediation_guide(),
            'appendices': {
                'methodology': self._get_methodology_description(),
                'references': self._get_security_references()
            }
        }
        
        if include_trends:
            # Record current scan for trend analysis
            self.trend_tracker.record_scan(self.findings, self.scan_info)
            # Add trend analysis if available
            trend_report = self.trend_tracker.generate_trend_report(
                hostname=self.scan_info.get('hostname')
            )
            if 'error' not in trend_report:
                report['trend_analysis'] = trend_report
        
        return report
    
    def generate_all_formats(self, output_dir: str) -> Dict[str, str]:
        """Generate reports in all available formats"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        hostname = self.scan_info.get('hostname', 'unknown')
        
        generated_files = {}
        
        try:
            # HTML Report
            html_file = output_path / f"vigileguard_report_{hostname}_{timestamp}.html"
            self.html_reporter.generate_report(str(html_file))
            generated_files['html'] = str(html_file)
        except Exception as e:
            print(f"Warning: Failed to generate HTML report: {e}")
        
        try:
            # JSON Technical Report
            json_file = output_path / f"vigileguard_technical_{hostname}_{timestamp}.json"
            technical_report = self.generate_technical_report()
            with open(json_file, 'w') as f:
                json.dump(technical_report, f, indent=2, default=str)
            generated_files['json'] = str(json_file)
        except Exception as e:
            print(f"Warning: Failed to generate JSON report: {e}")
        
        try:
            # Executive Summary
            executive_file = output_path / f"vigileguard_executive_{hostname}_{timestamp}.json"
            executive_summary = self.generate_executive_summary()
            with open(executive_file, 'w') as f:
                json.dump(executive_summary, f, indent=2, default=str)
            generated_files['executive'] = str(executive_file)
        except Exception as e:
            print(f"Warning: Failed to generate executive summary: {e}")
        
        try:
            # Compliance Report
            compliance_file = output_path / f"vigileguard_compliance_{hostname}_{timestamp}.json"
            compliance_report = self.compliance_mapper.generate_compliance_report(self.findings)
            with open(compliance_file, 'w') as f:
                json.dump(compliance_report, f, indent=2, default=str)
            generated_files['compliance'] = str(compliance_file)
        except Exception as e:
            print(f"Warning: Failed to generate compliance report: {e}")
        
        try:
            # PDF Report
            pdf_file = output_path / f"vigileguard_report_{hostname}_{timestamp}.pdf"
            pdf_result = self.pdf_reporter.generate_report(str(pdf_file))
            generated_files['pdf'] = pdf_result
        except Exception as e:
            print(f"Warning: Failed to generate PDF report: {e}")
        
        return generated_files
    
    def _calculate_risk_assessment(self) -> Dict[str, Any]:
        """Calculate overall risk assessment"""
        severity_counts = {}
        for finding in self.findings:
            severity = finding.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Calculate risk score
        severity_weights = {'CRITICAL': 10, 'HIGH': 7, 'MEDIUM': 4, 'LOW': 2, 'INFO': 1}
        risk_score = sum(severity_weights.get(sev, 1) * count for sev, count in severity_counts.items())
        risk_score = min(risk_score, 100)  # Cap at 100
        
        # Determine risk level
        if risk_score >= 80:
            risk_level = "Critical"
        elif risk_score >= 60:
            risk_level = "High"
        elif risk_score >= 40:
            risk_level = "Medium"
        elif risk_score >= 20:
            risk_level = "Low"
        else:
            risk_level = "Minimal"
        
        return {
            'overall_risk_score': risk_score,
            'risk_level': risk_level,
            'severity_breakdown': severity_counts,
            'risk_factors': self._identify_risk_factors()
        }
    
    def _identify_risk_factors(self) -> List[str]:
        """Identify key risk factors"""
        risk_factors = []
        
        # Check for critical/high issues
        critical_high = sum(1 for f in self.findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH])
        if critical_high > 5:
            risk_factors.append(f"High number of critical/high severity issues ({critical_high})")
        
        # Check for specific high-risk categories
        category_counts = {}
        for finding in self.findings:
            category_counts[finding.category] = category_counts.get(finding.category, 0) + 1
        
        if category_counts.get('Network Security', 0) > 3:
            risk_factors.append("Multiple network security vulnerabilities")
        
        if category_counts.get('Web Server', 0) > 2:
            risk_factors.append("Web server security misconfigurations")
        
        if category_counts.get('User Accounts', 0) > 3:
            risk_factors.append("User account security issues")
        
        return risk_factors
    
    def _get_top_priorities(self) -> List[Dict[str, Any]]:
        """Get top priority issues for executive attention"""
        # Sort by severity and select top issues
        priority_findings = sorted(
            self.findings, 
            key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].index(x.severity.value)
        )[:5]
        
        priorities = []
        for finding in priority_findings:
            priorities.append({
                'title': finding.title,
                'severity': finding.severity.value,
                'category': finding.category,
                'business_impact': self._assess_business_impact(finding),
                'estimated_effort': self._estimate_remediation_effort(finding)
            })
        
        return priorities
    
    def _assess_business_impact(self, finding: Finding) -> str:
        """Assess business impact of a finding"""
        if finding.severity == SeverityLevel.CRITICAL:
            return "High - Immediate risk to business operations"
        elif finding.severity == SeverityLevel.HIGH:
            return "Medium-High - Significant security risk"
        elif finding.severity == SeverityLevel.MEDIUM:
            return "Medium - Moderate security concern"
        elif finding.severity == SeverityLevel.LOW:
            return "Low - Minor security improvement"
        else:
            return "Minimal - Informational"
    
    def _estimate_remediation_effort(self, finding: Finding) -> str:
        """Estimate effort required to remediate finding"""
        category = finding.category
        severity = finding.severity
        
        if category == "User Accounts" and severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            return "Medium - Policy and process changes required"
        elif category == "Network Security":
            return "Low-Medium - Configuration changes"
        elif category == "Web Server":
            return "Low - Configuration updates"
        elif category == "File Permissions":
            return "Low - Permission adjustments"
        else:
            return "Variable - Depends on specific issue"
    
    def _assess_compliance_impact(self) -> Dict[str, Any]:
        """Assess impact on compliance frameworks"""
        compliance_report = self.compliance_mapper.generate_compliance_report(self.findings)
        
        impact_summary = {
            'frameworks_affected': len(compliance_report['frameworks']),
            'highest_impact_framework': None,
            'compliance_risk_level': 'Low'
        }
        
        # Find framework with highest impact
        max_affected_controls = 0
        for framework, data in compliance_report['frameworks'].items():
            affected_controls = data['total_controls_affected']
            if affected_controls > max_affected_controls:
                max_affected_controls = affected_controls
                impact_summary['highest_impact_framework'] = framework
        
        # Determine compliance risk level
        if max_affected_controls > 10:
            impact_summary['compliance_risk_level'] = 'High'
        elif max_affected_controls > 5:
            impact_summary['compliance_risk_level'] = 'Medium'
        
        impact_summary['details'] = compliance_report['coverage_summary']
        
        return impact_summary
    
    def _estimate_resource_requirements(self) -> Dict[str, Any]:
        """Estimate resources needed for remediation"""
        critical_high_count = sum(1 for f in self.findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH])
        medium_count = sum(1 for f in self.findings if f.severity == SeverityLevel.MEDIUM)
        
        # Simple estimation model
        estimated_hours = (critical_high_count * 4) + (medium_count * 2)
        estimated_weeks = max(1, estimated_hours // 40)
        
        return {
            'estimated_remediation_hours': estimated_hours,
            'estimated_timeline_weeks': estimated_weeks,
            'recommended_team_size': min(3, max(1, critical_high_count // 3)),
            'skills_required': self._identify_required_skills(),
            'budget_impact': 'Medium' if estimated_hours > 40 else 'Low'
        }
    
    def _identify_required_skills(self) -> List[str]:
        """Identify skills needed for remediation"""
        skills = set()
        
        categories = set(f.category for f in self.findings)
        
        if 'Network Security' in categories:
            skills.add('Network Administration')
        if 'Web Server' in categories:
            skills.add('Web Server Administration')
        if 'User Accounts' in categories:
            skills.add('Identity and Access Management')
        if 'File Permissions' in categories:
            skills.add('Linux System Administration')
        
        return list(skills)
    
    def _generate_executive_recommendations(self) -> List[Dict[str, str]]:
        """Generate high-level recommendations for executives"""
        recommendations = []
        
        critical_count = sum(1 for f in self.findings if f.severity == SeverityLevel.CRITICAL)
        if critical_count > 0:
            recommendations.append({
                'priority': 'Immediate',
                'recommendation': 'Address Critical Security Issues',
                'description': f'Immediately remediate {critical_count} critical security issues',
                'business_justification': 'Critical issues pose immediate risk to business operations and data security'
            })
        
        return recommendations
    
    def _generate_detailed_summary(self) -> Dict[str, Any]:
        """Generate detailed findings summary"""
        summary = {
            'total_findings': len(self.findings),
            'by_severity': {},
            'by_category': {},
            'risk_distribution': {},
        }
        
        # Count by severity and category
        for finding in self.findings:
            severity = finding.severity.value
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            category = finding.category
            summary['by_category'][category] = summary['by_category'].get(category, 0) + 1
        
        # Risk distribution
        high_risk_findings = [f for f in self.findings if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]]
        summary['risk_distribution'] = {
            'high_risk_percentage': round((len(high_risk_findings) / len(self.findings)) * 100, 1) if self.findings else 0,
            'most_critical_category': max(summary['by_category'], key=summary['by_category'].get) if summary['by_category'] else None
        }
        
        return summary
    
    def _generate_remediation_guide(self) -> Dict[str, Any]:
        """Generate comprehensive remediation guide"""
        guide = {
            'quick_wins': [],
            'medium_term_projects': [],
            'long_term_initiatives': [],
        }
        
        # Categorize findings by remediation complexity
        for finding in self.findings:
            complexity = self._assess_remediation_complexity(finding)
            priority_item = {
                'title': finding.title,
                'category': finding.category,
                'severity': finding.severity.value,
                'recommendation': finding.recommendation,
                'estimated_effort': complexity['effort'],
            }
            
            if complexity['timeline'] == 'immediate':
                guide['quick_wins'].append(priority_item)
            elif complexity['timeline'] == 'medium':
                guide['medium_term_projects'].append(priority_item)
            else:
                guide['long_term_initiatives'].append(priority_item)
        
        return guide
    
    def _assess_remediation_complexity(self, finding: Finding) -> Dict[str, Any]:
        """Assess complexity of remediating a specific finding"""
        category = finding.category
        severity = finding.severity
        
        # Default complexity assessment
        complexity = {
            'effort': 'Low',
            'timeline': 'immediate',
        }
        
        if category == 'User Accounts':
            complexity['effort'] = 'Medium'
            complexity['timeline'] = 'medium'
        elif category == 'Network Security' and severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
            complexity['effort'] = 'Medium'
            complexity['timeline'] = 'immediate'
        elif category == 'Web Server':
            complexity['effort'] = 'Low'
            complexity['timeline'] = 'immediate'
        
        return complexity
    
    def _get_methodology_description(self) -> str:
        """Get methodology description for report appendix"""
        return """
        VigileGuard Security Audit Methodology:
        
        1. System Discovery: Automated identification of system components, services, and configurations
        2. Configuration Analysis: Review of security-relevant configuration files and settings  
        3. Permission Assessment: Analysis of file, directory, and service permissions
        4. Network Security Review: Evaluation of network services, firewall rules, and exposed ports
        5. Web Server Security: Assessment of web server configurations and SSL/TLS settings
        6. Compliance Mapping: Alignment of findings with industry security frameworks
        7. Risk Assessment: Severity scoring based on potential impact and exploitability
        8. Remediation Guidance: Actionable recommendations for issue resolution
        
        The audit covers multiple security domains including access controls, network security,
        web server configurations, and system hardening. All checks are performed using read-only
        operations where possible to minimize impact on production systems.
        """
    
    def _get_security_references(self) -> List[Dict[str, str]]:
        """Get security references for report appendix"""
        return [
            {
                'title': 'NIST Cybersecurity Framework',
                'url': 'https://www.nist.gov/cyberframework',
                'description': 'Framework for improving critical infrastructure cybersecurity'
            },
            {
                'title': 'OWASP Security Guidelines',
                'url': 'https://owasp.org/',
                'description': 'Open Web Application Security Project guidelines and best practices'
            },
            {
                'title': 'CIS Controls',
                'url': 'https://www.cisecurity.org/controls/',
                'description': 'Center for Internet Security Critical Security Controls'
            },
            {
                'title': 'Linux Security Best Practices',
                'url': 'https://linux-audit.com/linux-security-guide/',
                'description': 'Comprehensive Linux security hardening guide'
            }
        ]