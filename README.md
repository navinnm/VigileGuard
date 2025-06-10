# SecurePulse - Linux Security Audit Tool

🔒 **SecurePulse** is a comprehensive security audit tool designed for Linux systems. It performs automated security checks, identifies vulnerabilities, and provides actionable recommendations for system hardening.

## ✨ Features

- **📋 Comprehensive Security Audits**
  - File and directory permission analysis
  - User account security checks
  - SSH configuration review
  - System information gathering

- **🎯 Intelligent Reporting**
  - Severity-based finding classification (CRITICAL, HIGH, MEDIUM, LOW, INFO)
  - Rich console output with color coding
  - JSON export for automation and CI/CD integration
  - Detailed remediation recommendations

- **⚙️ Flexible Configuration**
  - YAML-based configuration files
  - Customizable check severity levels
  - Excludable checks and paths
  - Custom rules and overrides

- **🚀 Developer Friendly**
  - Single executable with minimal dependencies
  - Exit codes for CI/CD integration
  - Modular architecture for easy extension

## 📦 Installation

### Quick Install (Recommended)

```bash
# Download and install
curl -fsSL https://github.com/navinnm/securepulse/releases/latest/download/install.sh | bash

# Or using pip
pip install securepulse
```

### Manual Installation

```bash
# Clone repository
git clone https://github.com/navinnm/securepulse.git
cd securepulse

# Install dependencies
pip install -r requirements.txt

# Install package
pip install -e .
```

### Dependencies

- Python 3.8+
- click >= 8.0.0
- rich >= 13.0.0
- PyYAML >= 6.0

## 🚀 Quick Start

### Basic Usage

```bash
# Run basic security audit
securepulse

# Run with custom config
securepulse --config /path/to/config.yaml

# Generate JSON report
securepulse --format json --output report.json

# Show help
securepulse --help
```

### Example Output

```
🔒 SecurePulse Security Audit
Starting audit at 2025-06-10 14:30:15

🔍 Checking file permissions...
👥 Checking user accounts...
🔑 Checking SSH configuration...
💻 Gathering system information...

📊 Audit Results
┏━━━━━━━━━━┳━━━━━━━┓
┃ Severity ┃ Count ┃
┡━━━━━━━━━━╇━━━━━━━┩
│ HIGH     │     2 │
│ MEDIUM   │     1 │
│ INFO     │     3 │
└──────────┴───────┘

╭─ HIGH - SSH ──────────────────────────────╮
│ Insecure SSH setting: permitrootlogin    │
│                                           │
│ Root login should be disabled. Current:  │
│ yes                                       │
│                                           │
│ 💡 Recommendation: Set 'PermitRootLogin  │
│ no' in /etc/ssh/sshd_config              │
╰───────────────────────────────────────────╯
```

## ⚙️ Configuration

SecurePulse uses YAML configuration files for customization:

```yaml
# config.yaml
output_format: "console"
severity_filter: "INFO"

excluded_checks:
  - "SystemInfoChecker"

severity_overrides:
  "SSH running on default port": "LOW"

ssh_checks:
  required_settings:
    PermitRootLogin: "no"
    PasswordAuthentication: "no"
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `output_format` | Output format (console/json) | `console` |
| `severity_filter` | Minimum severity to report | `INFO` |
| `excluded_checks` | List of checks to skip | `[]` |
| `excluded_paths` | Paths to exclude from scans | `["/tmp", "/proc"]` |

## 🔍 Security Checks

### File Permissions
- World-writable files detection
- SUID/SGID binary analysis  
- Sensitive file permission verification
- Home directory security

### User Accounts
- Empty password detection
- Duplicate UID identification
- Sudo configuration review
- Password policy checking

### SSH Configuration
- Root login settings
- Authentication methods
- Protocol version verification
- Key file permissions

### System Information
- OS version and support status
- Kernel version checking
- Running service analysis
- End-of-life detection

## 🔧 CI/CD Integration

SecurePulse is designed for automated security testing:

### Exit Codes
- `0`: No critical or high severity issues
- `1`: Critical or high severity issues found
- `130`: Interrupted by user
- `Other`: Error during execution

### GitHub Actions Example

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run SecurePulse
        run: |
          curl -fsSL https://github.com/navinnm/securepulse/releases/latest/download/install.sh | bash
          securepulse --format json --output security-report.json
      - name: Upload Security Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.json
```

### Jenkins Pipeline Example

```groovy
pipeline {
    agent any
    stages {
        stage('Security Audit') {
            steps {
                sh 'securepulse --format json --output security-report.json'
                archiveArtifacts artifacts: 'security-report.json'
            }
            post {
                failure {
                    echo 'Security issues found! Check the report.'
                }
            }
        }
    }
}
```

## 📊 Output Formats

### Console Output
Rich, colorized output perfect for terminal usage:
- Severity-based color coding
- Progress indicators
- Detailed finding descriptions
- Actionable recommendations

### JSON Output
Machine-readable format for automation:

```json
{
  "scan_info": {
    "timestamp": "2025-06-10T14:30:15",
    "tool": "SecurePulse",
    "version": "1.0.0",
    "hostname": "web-server-01"
  },
  "summary": {
    "total_findings": 6,
    "by_severity": {
      "HIGH": 2,
      "MEDIUM": 1,
      "INFO": 3
    }
  },
  "findings": [...]
}
```

## 🛠️ Development

### Adding Custom Checks

```python
from securepulse import SecurityChecker, SeverityLevel

class CustomChecker(SecurityChecker):
    def check(self):
        # Your custom security logic here
        self.add_finding(
            category="Custom",
            severity=SeverityLevel.MEDIUM,
            title="Custom Security Check",
            description="Description of the issue",
            recommendation="How to fix it"
        )
        return self.findings
```

### Project Structure

```
securepulse/
├── securepulse/
│   ├── __init__.py
│   ├── main.py              # Main CLI interface
│   ├── checkers/            # Security check modules
│   ├── config/              # Configuration handling
│   └── output/              # Report formatters
├── tests/                   # Test suite
├── docs/                    # Documentation
├── requirements.txt         # Dependencies
├── setup.py                 # Installation script
└── README.md               # This file
```

## 🔮 Roadmap (Future Phases)

### Phase 2: Web Server & Network Security
- Apache/Nginx configuration analysis
- SSL/TLS certificate checking
- Firewall rule auditing
- Network service enumeration

### Phase 3: API & CI/CD Integration
- REST API for remote scanning
- Web dashboard interface
- Advanced CI/CD integrations
- Multi-server fleet management

### Phase 4: Advanced Threat Detection
- Behavioral analysis
- Threat intelligence integration
- Automated remediation
- Machine learning enhancements

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/navinnm/securepulse.git
cd securepulse
pip install -e ".[dev]"
pytest tests/
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📖 **Documentation**: [https://securepulse.readthedocs.io/](https://securepulse.readthedocs.io/)
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/navinnm/securepulse/issues)
- 💬 **Community**: [GitHub Discussions](https://github.com/navinnm/securepulse/discussions)
- 📧 **Email**: security@navinnm.com

## 🏆 Acknowledgments

- Inspired by industry-standard tools like Lynis and OpenSCAP
- Built with love by the SecurePulse development team
- Special thanks to the security community for feedback and contributions

---

**⚡ SecurePulse - Securing your infrastructure, one pulse at a time.**