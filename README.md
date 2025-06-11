# VigileGuard - Linux Security Audit Tool

🛡️ **VigileGuard** is a comprehensive security audit tool designed for developer-focused startups and Linux systems. It performs automated security checks, identifies vulnerabilities, and provides actionable recommendations for system hardening and compliance.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![GitHub issues](https://img.shields.io/github/issues/navinnm/VigileGuard)](https://github.com/navinnm/VigileGuard/issues)
[![GitHub stars](https://img.shields.io/github/stars/navinnm/VigileGuard)](https://github.com/navinnm/VigileGuard/stargazers)
[![CI/CD](https://github.com/navinnm/VigileGuard/workflows/VigileGuard%20CI/CD%20Pipeline/badge.svg)](https://github.com/navinnm/VigileGuard/actions)
[![Security Status](https://img.shields.io/badge/security-monitored-green.svg)](SECURITY.md)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

VigileGuard is a comprehensive security audit tool designed specifically for Linux systems. It provides automated security assessments, compliance mapping, and detailed reporting to help system administrators and security professionals identify and remediate security vulnerabilities.

## 🚀 Features

### Phase 1 (Core Security Checks)
- **File Permission Analysis** - Detect world-writable files, incorrect permissions on sensitive files
- **User Account Security** - Check for weak passwords, duplicate UIDs, sudo misconfigurations  
- **SSH Configuration Review** - Analyze SSH settings for security best practices
- **System Information Gathering** - Collect OS version, kernel info, running services

### Phase 2 (Advanced Security & Reporting)
- **Web Server Security** - Apache/Nginx configuration analysis, SSL/TLS checks
- **Network Security Analysis** - Port scanning, firewall configuration review
- **Enhanced HTML Reporting** - Beautiful, interactive security reports
- **Compliance Mapping** - PCI DSS, SOC 2, NIST CSF, ISO 27001 alignment
- **Notification Integrations** - Email, Slack, webhook notifications
- **Trend Tracking** - Historical analysis and security trend monitoring
- **Scheduled Scanning** - Automated recurring security audits

## 📁 Project Structure

```
VigileGuard/
├── vigileguard/                    # Main package directory
│   ├── __init__.py                # Package initialization
│   ├── vigileguard.py             # Core Phase 1 + 2 scanner
│   ├── web_security_checkers.py   # Phase 2 web security modules
│   ├── enhanced_reporting.py      # Phase 2 reporting system
│   └── phase2_integration.py      # Phase 2 integration & config
├── scripts/                       # Utility scripts
│   ├── badge_generator.py         # Generate status badges
│   ├── report_analyzer.py         # Analyze scan reports
│   └── vigileguard-install.sh     # Installation script
├── tests/                         # Test suite
│   ├── test_vigileguard.py        # Core functionality tests
│   ├── test_web_security.py       # Web security tests
│   └── test_reporting.py          # Reporting tests
├── docs/                          # Documentation
├── examples/                      # Example configurations
├── config.yaml                    # Default configuration
├── requirements.txt               # Python dependencies
├── setup.py                       # Package setup
├── pyproject.toml                 # Modern Python packaging
├── Makefile                       # Development commands
└── README.md                      # This file
```

## 🔧 Installation

### Quick Install (Recommended)

```bash
# Download and run the installer
curl -sSL https://raw.githubusercontent.com/navinnm/VigileGuard/main/install.sh | bash

# Or install from PyPI
pip install vigileguard
```

### Development Installation

```bash
# Clone the repository
git clone https://github.com/navinnm/VigileGuard.git
cd VigileGuard

# Install in development mode
make install-dev

# Or manually
pip install -e ".[dev,full]"
```

### Virtual Environment Installation

```bash
# Create and activate virtual environment
python3 -m venv vigileguard-env
source vigileguard-env/bin/activate

# Install VigileGuard
pip install vigileguard

# Or from source
pip install -e .
```

### Docker Installation

```bash
# Build Docker image
docker build -t vigileguard .

# Run in container
docker run --rm -v $(pwd)/reports:/app/reports vigileguard --format html
```

## 🚀 Quick Start

### Basic Usage

```bash
# Run basic console scan
vigileguard

# Generate HTML report
vigileguard --format html --output security-report.html

# Generate JSON report
vigileguard --format json --output security-report.json

# Generate all report formats
vigileguard --format all --output ./reports/
```

### Advanced Usage

```bash
# Use custom configuration
vigileguard --config custom-config.yaml --format html

# Specify environment
vigileguard --environment production --format json

# Enable notifications
vigileguard --notifications --format html

# Debug mode
vigileguard --debug --format console
```

### Using Make Commands

```bash
# Install and setup
make install-dev

# Run tests
make test

# Format code
make format

# Run security scans
make security

# Build package
make build

# Generate HTML report
make run-html

# Run all formats
make run-all
```

## ⚙️ Configuration

Create a configuration file at `~/.config/vigileguard/config.yaml`:

```yaml
vigileguard:
  # Output settings
  output:
    directory: "./reports"
    timestamp_format: "%Y%m%d_%H%M%S"
    
  # Security checks
  checks:
    file_permissions: true
    user_accounts: true
    ssh_configuration: true
    web_security: true
    network_security: true
    
  # Reporting
  reports:
    include_compliance: true
    severity_threshold: "INFO"
    
  # Phase 2 features
  phase2:
    enabled: true
    web_security_deep_scan: true
    enhanced_html_reports: true
    
  # Notifications (Phase 2)
  notifications:
    enabled: false
    email:
      smtp_server: "smtp.gmail.com"
      smtp_port: 587
      username: "your-email@domain.com"
      recipients: ["admin@company.com"]
    slack:
      webhook_url: "https://hooks.slack.com/..."
      channel: "#security"
```

## 📊 Report Examples

### Console Output
```
🛡️ VigileGuard Security Audit
==============================

✅ FilePermissionChecker completed - 3 findings
✅ UserAccountChecker completed - 1 findings  
✅ SSHConfigChecker completed - 2 findings
✅ WebServerSecurityChecker completed - 4 findings
✅ NetworkSecurityChecker completed - 0 findings

📊 Audit Results
================
CRITICAL: 1
HIGH: 3
MEDIUM: 4
LOW: 2
```

### HTML Report Features
- **Interactive Dashboard** - Summary cards, charts, and graphs
- **Detailed Findings** - Expandable cards with recommendations
- **Compliance Mapping** - Framework alignment visualization
- **Trend Analysis** - Historical comparison charts
- **Export Options** - PDF generation, CSV export

### JSON Report Structure
```json
{
  "scan_info": {
    "timestamp": "2025-06-11T20:39:00Z",
    "hostname": "web-server-01",
    "version": "2.0.2"
  },
  "summary": {
    "total_findings": 10,
    "by_severity": {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 4, "LOW": 2}
  },
  "findings": [...],
  "compliance": {...},
  "trends": {...}
}
```

## 🔒 Security Frameworks

VigileGuard maps findings to major compliance frameworks:

- **PCI DSS** - Payment Card Industry Data Security Standard
- **SOC 2** - Service Organization Control 2
- **NIST CSF** - NIST Cybersecurity Framework  
- **ISO 27001** - Information Security Management
- **CIS Controls** - Center for Internet Security

## 🔧 Development

### Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/navinnm/VigileGuard.git
cd VigileGuard

# Setup development environment
make dev-setup

# Run tests
make test

# Run linting
make lint

# Format code
make format
```

### Running Tests

```bash
# Unit tests
make test

# All tests with coverage
make test-all

# Specific test file
pytest tests/test_vigileguard.py -v

# Integration tests
pytest tests/ -m integration
```

### Code Quality

```bash
# Format code
make format

# Lint code
make lint

# Security checks
make security

# All quality checks
make dev-check
```

## 🐳 Docker Usage

### Build and Run

```bash
# Build image
make docker-build

# Run scan
make docker-run

# Interactive shell
make docker-shell

# Custom command
docker run --rm -v $(pwd)/reports:/app/reports vigileguard:latest --format json
```

### Docker Compose

```yaml
version: '3.8'
services:
  vigileguard:
    build: .
    volumes:
      - ./reports:/app/reports
      - ./config:/app/config
    command: ["--format", "html", "--output", "/app/reports/report.html"]
```

## 📅 Scheduled Scanning

### Cron Setup

```bash
# Setup daily scans
./install.sh --setup-cron

# Manual cron entry (daily at 2 AM)
0 2 * * * /usr/local/bin/vigileguard --format json --output /var/log/vigileguard/daily-$(date +\%Y\%m\%d).json
```

### Systemd Timer

```ini
# /etc/systemd/system/vigileguard.timer
[Unit]
Description=VigileGuard Security Scan
Requires=vigileguard.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

## 🔧 API Usage

### Python API

```python
import vigileguard

# Create audit engine
engine = vigileguard.create_audit_engine()

# Run audit
findings = engine.run_audit()

# Generate reports
report_manager = vigileguard.ReportManager(findings, scan_info)
report_manager.generate_all_formats("./reports")

# Check Phase 2 availability
if vigileguard.check_phase2_availability():
    print("Phase 2 features available")
```

### Command Line Integration

```bash
# JSON output for scripting
vigileguard --format json | jq '.summary.total_findings'

# Exit code based on findings
vigileguard --format console
echo "Exit code: $?"  # Non-zero if critical/high issues found

# Custom severity threshold
vigileguard --format json | jq '.findings[] | select(.severity=="CRITICAL")'
```

## 🚨 Troubleshooting

### Common Issues

**Phase 2 Components Not Available**
```bash
# Check if Phase 2 files exist
ls vigileguard/web_security_checkers.py
ls vigileguard/enhanced_reporting.py
ls vigileguard/phase2_integration.py

# Reinstall with Phase 2
pip uninstall vigileguard
pip install vigileguard[full]
```

**Permission Errors**
```bash
# Run with appropriate privileges
sudo vigileguard --format console

# Or use user installation
pip install --user vigileguard
```

**Missing Dependencies**
```bash
# Install all dependencies
pip install vigileguard[full]

# Or install manually
pip install rich click PyYAML requests
```

### Debug Mode

```bash
# Enable debug output
vigileguard --debug --format console

# Check imports
python -c "import vigileguard; print(vigileguard.get_version())"

# Verbose logging
export VIGILEGUARD_LOG_LEVEL=DEBUG
vigileguard --format console
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `make test`
5. Submit a pull request

### Code Standards

- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation
- Run `make dev-check` before submitting

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🛡️ Security

For security issues, please email security@vigileguard.dev or see [SECURITY.md](SECURITY.md).

## 📞 Support

- **Documentation**: [GitHub Wiki](https://github.com/navinnm/VigileGuard/wiki)
- **Issues**: [GitHub Issues](https://github.com/navinnm/VigileGuard/issues)
- **Discussions**: [GitHub Discussions](https://github.com/navinnm/VigileGuard/discussions)
- **Email**: support@vigileguard.dev

## 🙏 Acknowledgments

- Security best practices from OWASP, NIST, and CIS
- Linux security community
- Open source security tools ecosystem

---

**Made with ❤️ by the VigileGuard Team**