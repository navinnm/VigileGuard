# VigileGuard - Security Audit Engine (Phase 3)

🛡️ **VigileGuard** is a comprehensive, enterprise-grade security audit engine designed for modern development teams. It combines local scanning capabilities with powerful API integrations, CI/CD pipeline support, and real-time notifications to provide continuous security monitoring for your infrastructure.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![GitHub issues](https://img.shields.io/github/issues/navinnm/VigileGuard)](https://github.com/navinnm/VigileGuard/issues)
[![GitHub stars](https://img.shields.io/github/stars/navinnm/VigileGuard)](https://github.com/navinnm/VigileGuard/stargazers)
[![CI/CD](https://github.com/navinnm/VigileGuard/workflows/VigileGuard%20CI/CD%20Pipeline/badge.svg)](https://github.com/navinnm/VigileGuard/actions)
[![Security Status](https://img.shields.io/badge/security-monitored-green.svg)](SECURITY.md)
[![API Status](https://img.shields.io/badge/API-v3.0.7-blue.svg)](api/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](integrations/github_actions/Dockerfile)

**Fast • Developer-Friendly • CI/CD Native • Enterprise-Ready**

VigileGuard evolves through three phases to become a complete security audit ecosystem:
- **Phase 1**: Core security scanning for Linux systems
- **Phase 2**: Web server security and advanced reporting  
- **Phase 3**: API-first architecture with CI/CD integrations

## 🚀 Features

### Phase 1 (Core Security Checks) ✅
- **File Permission Analysis** - Detect world-writable files, incorrect permissions on sensitive files
- **User Account Security** - Check for weak passwords, duplicate UIDs, sudo misconfigurations  
- **SSH Configuration Review** - Analyze SSH settings for security best practices
- **System Information Gathering** - Collect OS version, kernel info, running services

### Phase 2 (Advanced Security & Reporting) ✅
- **Web Server Security** - Apache/Nginx configuration analysis, SSL/TLS checks
- **Network Security Analysis** - Port scanning, firewall configuration review
- **Enhanced HTML Reporting** - Beautiful, interactive security reports
- **Compliance Mapping** - PCI DSS, SOC 2, NIST CSF, ISO 27001 alignment
- **Notification Integrations** - Email, Slack, webhook notifications
- **Trend Tracking** - Historical analysis and security trend monitoring

### Phase 3 (API & CI/CD Integration) ✅ NEW!
- **REST API** - Complete RESTful API with authentication and RBAC
- **GitHub Actions Integration** - Native CI/CD security scanning
- **GitLab CI/CD Templates** - Ready-to-use pipeline templates
- **Jenkins Plugin Support** - Enterprise CI/CD integration
- **Webhook Notifications** - Real-time alerts to Slack, Teams, Discord
- **Multi-Format Reports** - JSON, HTML, PDF, CSV export capabilities
- **Role-Based Access Control** - Admin, Developer, Viewer permissions
- **API Key Management** - Secure programmatic access
- **Remote Scanning** - Scan infrastructure via API endpoints
- **Fleet Management** - Monitor multiple servers from central dashboard

## 🏗️ Architecture

### Phase 3 Technical Stack
```
┌─────────────────────────────────────────────────────────┐
│                    VigileGuard v3.0.7                  │
├─────────────────────────────────────────────────────────┤
│  🌐 REST API (FastAPI)                                 │
│  ├── Authentication (JWT + API Keys)                   │
│  ├── Role-Based Access Control (RBAC)                  │
│  ├── Scan Management                                    │
│  ├── Report Generation                                  │
│  └── Webhook Notifications                             │
├─────────────────────────────────────────────────────────┤
│  🔄 CI/CD Integrations                                 │
│  ├── GitHub Actions                                     │
│  ├── GitLab CI/CD                                      │
│  ├── Jenkins Pipeline                                   │
│  └── Docker Containers                                 │
├─────────────────────────────────────────────────────────┤
│  📊 Web Dashboard (React)                              │
│  ├── Scan History & Trends                             │
│  ├── Fleet Management                                   │
│  ├── Policy Configuration                              │
│  └── Compliance Reporting                              │
├─────────────────────────────────────────────────────────┤
│  🔔 Notification Systems                               │
│  ├── Slack Integration                                 │
│  ├── Microsoft Teams                                   │
│  ├── Discord Webhooks                                  │
│  └── Custom HTTP Webhooks                              │
├─────────────────────────────────────────────────────────┤
│  🛡️ Security Scanning Engine (Phases 1 & 2)           │
│  ├── Core System Checks                                │
│  ├── Web Server Security                               │
│  ├── Network Analysis                                  │
│  └── Compliance Mapping                                │
└─────────────────────────────────────────────────────────┘
```

## 📁 Project Structure

```
VigileGuard/
├── vigileguard/                      # Main scanning engine
│   ├── __init__.py                  
│   ├── vigileguard.py               # Core scanner with Phase 3 API integration
│   ├── web_security_checkers.py     # Phase 2 web security modules
│   ├── enhanced_reporting.py        # Phase 2 reporting system
│   └── phase2_integration.py        # Phase 2 integration & config
├── api/                             # Phase 3 REST API
│   ├── main.py                      # FastAPI application
│   ├── auth/                        # Authentication & authorization
│   │   ├── jwt_handler.py           # JWT token management
│   │   ├── api_key_auth.py          # API key authentication
│   │   └── rbac.py                  # Role-based access control
│   ├── models/                      # Data models
│   │   ├── user.py                  # User and API key models
│   │   ├── scan.py                  # Scan management models
│   │   ├── webhook.py               # Webhook models
│   │   └── report.py                # Report models
│   ├── routes/                      # API endpoints
│   │   ├── auth_routes.py           # Authentication endpoints
│   │   ├── scan_routes.py           # Scan management
│   │   ├── report_routes.py         # Report generation
│   │   ├── webhook_routes.py        # Webhook management
│   │   └── config_routes.py         # Configuration management
│   └── services/                    # Business logic
│       ├── scan_service.py          # Scan execution service
│       ├── report_service.py        # Report generation service
│       └── webhook_service.py       # Webhook delivery service
├── integrations/                    # CI/CD integrations
│   ├── github_actions/              # GitHub Actions integration
│   │   ├── action.yml               # Action definition
│   │   ├── Dockerfile               # Container for GitHub Actions
│   │   ├── entrypoint.py            # GitHub Actions entrypoint
│   │   ├── README.md                # GitHub Actions documentation
│   │   └── example-workflow.yml     # Example workflow
│   ├── gitlab_ci/                   # GitLab CI/CD templates
│   └── jenkins/                     # Jenkins pipeline templates
├── dashboard/                       # Web dashboard (React)
│   ├── src/                         # React source code
│   ├── public/                      # Static assets
│   └── package.json                 # Node.js dependencies
├── scripts/                         # Utility scripts
│   ├── badge_generator.py           # Generate status badges
│   ├── report_analyzer.py           # Analyze scan reports
│   └── vigileguard-install.sh       # Installation script
├── tests/                           # Test suite
│   ├── test_vigileguard.py          # Core functionality tests
│   ├── test_api.py                  # API tests
│   └── test_integrations.py         # CI/CD integration tests
├── docs/                            # Documentation
├── config.yaml                      # Default configuration
├── requirements.txt                 # Python dependencies
├── docker-compose.yml               # Multi-service deployment
└── CLAUDE.md                        # Development roadmap
```

## 📦 Installation

### Method 1: Install from PyPI (Recommended)
```bash
# Install latest stable version
pip install vigileguard

# Verify installation
vigileguard --version

# Run your first scan
vigileguard
```

### Method 2: Install from GitHub
```bash
# Install latest development version
pip install git+https://github.com/navinnm/VigileGuard.git

# Or clone and install locally
git clone https://github.com/navinnm/VigileGuard.git
cd VigileGuard
pip install -e .
```

### Method 3: Docker Installation
```bash
# Run with Docker
docker run -p 8000:8000 vigileguard/api:v3.0.7

# Or use docker-compose
docker-compose up
```

### Method 4: Development Installation
```bash
# Clone repository
git clone https://github.com/navinnm/VigileGuard.git
cd VigileGuard

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e .[dev]
```

## 🚀 Quick Start

### Option 1: Local Scanning (Phase 1 & 2)
```bash
# Install VigileGuard
pip install vigileguard

# Run basic scan
vigileguard

# Generate JSON report
vigileguard --format json --output scan_report.json

# Run with webhook notifications
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
vigileguard --notifications --webhook-url $SLACK_WEBHOOK_URL

# Show all available options
vigileguard --help
```

### Option 2: API Server (Phase 3)
```bash
# Install VigileGuard
pip install vigileguard

# Start the API server
vigileguard-api

# Or using Python module
python -m api

# API will be available at http://localhost:8000
# Interactive docs at http://localhost:8000/api/docs
```

### Option 3: Remote Scanning via API
```bash
# Install VigileGuard
pip install vigileguard

# Scan remote target via API
vigileguard --target server.example.com --api-mode

# With custom API endpoint and authentication
vigileguard \
  --target server.example.com \
  --api-endpoint https://vigileguard-api.company.com/api/v1 \
  --api-key your-api-key \
  --format json
```

### Option 4: CI/CD Integration (GitHub Actions)
```yaml
# .github/workflows/security-audit.yml
name: Security Audit
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.8'
      
      - name: Install VigileGuard
        run: pip install vigileguard
      
      - name: Run Security Scan
        run: |
          vigileguard --format json --output scan-results.json
          vigileguard --notifications --webhook-url ${{ secrets.SLACK_WEBHOOK_URL }}
        env:
          VIGILEGUARD_ENV: production
```

## 🔧 Advanced Installation

### Prerequisites
- Python 3.8+
- Linux/Unix system (for local scanning)
- Docker (optional, for containerized deployment)

### Development Installation (Advanced Users)

#### Method 1: Full Source Installation with Phase 3
```bash
# Clone repository
git clone https://github.com/navinnm/VigileGuard.git
cd VigileGuard

# Run automated Phase 3 installation
bash install_phase3.sh

# Test installation
./vigileguard-cli --help
./vigileguard-api &  # Start API server
```

#### Method 2: Manual Development Setup
```bash
# Clone repository
git clone https://github.com/navinnm/VigileGuard.git
cd VigileGuard

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in development mode with all extras
pip3 install -e .[dev,api,ci]

# Test Phase 1 & 2
vigileguard

# Test Phase 3 API
python3 -c "import api.main; print('✅ Phase 3 API OK')"
python3 -m api
```

#### Method 3: Add Phase 3 to Existing Installation
If you already have VigileGuard Phase 1 & 2 working:

```bash
# In your existing VigileGuard directory
cd /path/to/your/vigileguard

# Download Phase 3 components
wget https://github.com/navinnm/VigileGuard/archive/main.zip
unzip main.zip
cp -r VigileGuard-main/api .
cp -r VigileGuard-main/integrations .

# Install Phase 3 dependencies
pip3 install fastapi uvicorn pydantic python-multipart aiofiles httpx

# Test API
python3 -c "import api.main; print('✅ Phase 3 API Ready!')"

# Start API server
python3 -m api
```

#### Method 4: Docker Deployment
```bash
# Clone repository
git clone https://github.com/navinnm/VigileGuard.git
cd VigileGuard

# Start all services
docker-compose up -d

# Access API at http://localhost:8000
# Access dashboard at http://localhost:3000
```

#### Method 5: Deployment Package
For production deployments or isolated environments:

```bash
# Download deployment package
wget https://github.com/navinnm/VigileGuard/releases/download/v3.0.7/vigileguard-phase3-v3.0.7.tar.gz

# Extract and install
tar -xzf vigileguard-phase3-v3.0.7.tar.gz
cd vigileguard-phase3-deployment
bash quickstart.sh

# Start services
./vigileguard-api &
./vigileguard-cli --help
```

### Troubleshooting Installation

#### Common Issues:

**1. `ModuleNotFoundError: No module named 'api'`**
```bash
# Ensure you're in the correct directory
cd /path/to/VigileGuard

# Install in development mode
pip3 install -e .

# Verify installation
python3 -c "import sys; print('Python path:', sys.path)"
python3 -c "import api.main; print('API module found')"
```

**2. Missing Phase 3 Dependencies**
```bash
# Install all Phase 3 requirements
pip3 install fastapi uvicorn pydantic python-multipart aiofiles httpx requests
```

**3. Permission Issues**
```bash
# Make scripts executable
chmod +x vigileguard-cli vigileguard-api install_phase3.sh

# Check Python permissions
ls -la $(which python3)
```

**4. Port 8000 Already in Use**
```bash
# Check what's using the port
netstat -tulpn | grep :8000

# Kill the process or use different port
# Set environment variable for different port
export VIGILEGUARD_API_PORT=8001
python3 -m api
```

## 📚 Usage Examples

### CLI Usage
```bash
# Basic local scan
vigileguard

# Scan with specific checkers
vigileguard --checkers ssh,firewall,web-server

# Generate HTML report
vigileguard --format html --output security_report.html

# Remote API scanning
vigileguard --target production.example.com --api-mode

# With webhook notifications (Slack)
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
vigileguard --notifications --webhook-url $SLACK_WEBHOOK_URL

# With webhook notifications (Microsoft Teams)
export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/YOUR_TENANT_ID@YOUR_TENANT_ID/IncomingWebhook/CHANNEL_ID/CONNECTOR_ID"
vigileguard --notifications --webhook-url $TEAMS_WEBHOOK_URL

# With webhook notifications (Discord)
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/WEBHOOK_ID/WEBHOOK_TOKEN"
vigileguard --notifications --webhook-url $DISCORD_WEBHOOK_URL

# Combined scan with multiple outputs and notifications
vigileguard \
  --format json \
  --output security_scan.json \
  --notifications \
  --webhook-url $SLACK_WEBHOOK_URL \
  --checkers ssh,firewall,web-server
```

### API Usage
```bash
# Authenticate and get token
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Create scan
curl -X POST http://localhost:8000/api/v1/scans/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Scan",
    "target": "prod.example.com",
    "checkers": ["ssh", "firewall", "web-server"]
  }'

# Run scan
curl -X POST http://localhost:8000/api/v1/scans/{scan_id}/run \
  -H "Authorization: Bearer YOUR_TOKEN"

# Get results
curl http://localhost:8000/api/v1/scans/{scan_id} \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Python API
```python
import requests

# API client example
class VigileGuardAPI:
    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.headers = {"Authorization": f"Bearer {api_key}"}
    
    def create_scan(self, target, checkers=None):
        data = {"name": f"Scan {target}", "target": target}
        if checkers:
            data["checkers"] = checkers
        
        response = requests.post(
            f"{self.base_url}/scans/",
            json=data,
            headers=self.headers
        )
        return response.json()

# Usage
api = VigileGuardAPI("http://localhost:8000/api/v1", "your-api-key")
scan = api.create_scan("server.example.com", ["ssh", "firewall"])
```

## 🔐 Security & Authentication

### API Authentication
VigileGuard Phase 3 supports multiple authentication methods:

1. **JWT Tokens** - For interactive users
2. **API Keys** - For programmatic access
3. **Role-Based Access Control** - Admin, Developer, Viewer roles

### Creating API Keys
```bash
# Via API
curl -X POST http://localhost:8000/api/v1/auth/api-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "CI/CD Pipeline Key",
    "permissions": ["scan:create", "scan:run", "report:read"],
    "expires_days": 365
  }'
```

### Permission System
- **Admin**: Full system access, user management, configuration
- **Developer**: Create/run scans, generate reports, manage webhooks
- **Viewer**: Read-only access to scans and reports

## 🔔 Integrations

### Webhook Notifications

VigileGuard supports real-time notifications via webhooks to popular collaboration platforms. When `--notifications` is enabled with `--webhook-url`, scan results and security alerts are automatically sent to your team.

#### Slack Integration

**Step 1: Create Slack Webhook**
1. Go to your Slack workspace settings
2. Navigate to "Apps" → "Manage" → "Custom Integrations" → "Incoming Webhooks"
3. Click "Add to Slack" and choose your channel
4. Copy the webhook URL (format: `https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX`)

**Step 2: Use with VigileGuard CLI**
```bash
# Set webhook URL
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# Run scan with Slack notifications
vigileguard --notifications --webhook-url $SLACK_WEBHOOK_URL

# Or inline
vigileguard --notifications --webhook-url "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
```

**Step 3: Configure via API**
```bash
# Create Slack webhook via API
curl -X POST http://localhost:8000/api/v1/webhooks/slack \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Security Alerts",
    "webhook_url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
    "events": ["scan.completed", "finding.critical"],
    "channel": "#security"
  }'
```

#### Microsoft Teams Integration

**Step 1: Create Teams Webhook**
1. Open Microsoft Teams and go to your target channel
2. Click "..." → "Connectors" → "Incoming Webhook" → "Configure"
3. Give it a name like "VigileGuard Security Alerts"
4. Copy the webhook URL (format: `https://outlook.office.com/webhook/YOUR_TENANT_ID@YOUR_TENANT_ID/IncomingWebhook/CHANNEL_ID/CONNECTOR_ID`)

**Step 2: Use with VigileGuard CLI**
```bash
# Set webhook URL
export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/YOUR_TENANT_ID@YOUR_TENANT_ID/IncomingWebhook/CHANNEL_ID/CONNECTOR_ID"

# Run scan with Teams notifications
vigileguard --notifications --webhook-url $TEAMS_WEBHOOK_URL
```

**Step 3: Configure via API**
```bash
# Create Teams webhook via API
curl -X POST http://localhost:8000/api/v1/webhooks/teams \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Security Notifications",
    "webhook_url": "https://outlook.office.com/webhook/YOUR_TENANT_ID@YOUR_TENANT_ID/IncomingWebhook/CHANNEL_ID/CONNECTOR_ID",
    "events": ["scan.completed", "scan.failed"]
  }'
```

#### Discord Integration

**Step 1: Create Discord Webhook**
1. Go to your Discord server and channel settings
2. Navigate to "Integrations" → "Webhooks" → "New Webhook"
3. Name it "VigileGuard Security" and copy the webhook URL
4. URL format: `https://discord.com/api/webhooks/WEBHOOK_ID/WEBHOOK_TOKEN`

**Step 2: Use with VigileGuard CLI**
```bash
# Set webhook URL
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/WEBHOOK_ID/WEBHOOK_TOKEN"

# Run scan with Discord notifications
vigileguard --notifications --webhook-url $DISCORD_WEBHOOK_URL
```

#### Custom Webhook Integration

**Step 1: Set up your webhook endpoint**
```python
# Example webhook receiver (Flask)
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/vigileguard-webhook', methods=['POST'])
def handle_vigileguard_webhook():
    data = request.get_json()
    
    # Process the webhook data
    scan_id = data.get('scan_id')
    findings = data.get('findings', [])
    critical_count = len([f for f in findings if f['severity'] == 'CRITICAL'])
    
    print(f"Received VigileGuard scan {scan_id}: {critical_count} critical findings")
    
    return jsonify({"status": "received"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

**Step 2: Use with VigileGuard**
```bash
# Run scan with custom webhook
vigileguard --notifications --webhook-url "https://your-domain.com/vigileguard-webhook"
```

#### Webhook Payload Format

VigileGuard sends webhook notifications in the following JSON format:

```json
{
  "scan_id": "scan_20250619_190843",
  "timestamp": "2025-06-19T19:08:43.123456",
  "target": "localhost",
  "environment": "production",
  "status": "completed",
  "summary": {
    "total_findings": 28,
    "critical": 5,
    "high": 5,
    "medium": 12,
    "low": 4,
    "info": 2
  },
  "findings": [
    {
      "category": "File Permissions",
      "severity": "CRITICAL",
      "title": "World-writable files found",
      "description": "Found files that are writable by all users",
      "recommendation": "Remove world-write permissions on sensitive files"
    }
  ],
  "reports": {
    "html": "reports/vigileguard_report_localhost_20250619_190843.html",
    "json": "reports/vigileguard_technical_localhost_20250619_190843.json"
  },
  "compliance": {
    "pci_dss": "FAIL",
    "soc2": "PARTIAL",
    "iso_27001": "PASS"
  }
}
```

#### Webhook Testing

```bash
# Test webhook connectivity
vigileguard --notifications --webhook-url $SLACK_WEBHOOK_URL --debug

# Send test webhook via API
curl -X POST http://localhost:8000/api/v1/webhooks/test \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "webhook_url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
    "message": "VigileGuard webhook test"
  }'
```

### CI/CD Platforms

#### GitHub Actions
```yaml
- name: Security Scan
  uses: vigileguard/github-action@v3
  with:
    target: ${{ github.repository }}
    fail-on-critical: true
    api-endpoint: ${{ secrets.VIGILEGUARD_API_URL }}
    api-key: ${{ secrets.VIGILEGUARD_API_KEY }}
```

#### GitLab CI/CD
```yaml
include:
  - remote: 'https://raw.githubusercontent.com/navinnm/VigileGuard/main/integrations/gitlab_ci/security-audit.yml'

variables:
  VIGILEGUARD_TARGET: "production.example.com"
  VIGILEGUARD_API_KEY: $VIGILEGUARD_API_KEY
```

#### Jenkins Pipeline
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                vigileguardScan(
                    target: 'production.example.com',
                    apiEndpoint: env.VIGILEGUARD_API_URL,
                    apiKey: env.VIGILEGUARD_API_KEY,
                    failOnCritical: true
                )
            }
        }
    }
}
```

## 📊 Reports & Analytics

### Report Formats
- **Console**: Real-time colored output
- **JSON**: Machine-readable structured data
- **HTML**: Interactive web reports with charts
- **PDF**: Printable executive summaries
- **CSV**: Spreadsheet-compatible data export

### Compliance Frameworks
- **PCI DSS**: Payment card industry standards
- **SOC 2**: Service organization controls
- **ISO 27001**: Information security management
- **NIST CSF**: Cybersecurity framework
- **CIS Controls**: Critical security controls

### Sample Report Generation
```bash
# Generate compliance report
curl -X POST http://localhost:8000/api/v1/reports/export \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_ids": ["scan_123", "scan_124"],
    "format": "pdf",
    "compliance_frameworks": ["pci_dss", "soc2"]
  }' \
  --output compliance_report.pdf
```

## 🖥️ Web Dashboard

### Features
- **Real-time Scan Monitoring**: Track scan progress and status
- **Historical Trends**: Security posture improvement over time  
- **Fleet Management**: Monitor multiple servers and environments
- **Policy Configuration**: Visual security policy editor
- **Compliance Dashboard**: Framework-specific compliance tracking
- **User Management**: RBAC configuration interface

### Accessing the Dashboard
```bash
# Start dashboard (if using Docker)
docker-compose up dashboard

# Access at http://localhost:3000
```

## 🐳 Docker Deployment

### Single Container
```bash
docker run -p 8000:8000 vigileguard/api:v3.0.7
```

### Multi-Service Deployment
```yaml
# docker-compose.yml
version: '3.8'
services:
  api:
    image: vigileguard/api:v3.0.7
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://user:pass@db:5432/vigileguard
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis

  dashboard:
    image: vigileguard/dashboard:v3.0.7
    ports:
      - "3000:3000"
    environment:
      - REACT_APP_API_URL=http://localhost:8000/api/v1

  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=vigileguard
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass

  redis:
    image: redis:6-alpine
```

## 🧪 Testing

### Running Tests
```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest

# Run specific test categories
pytest tests/test_api.py              # API tests
pytest tests/test_integrations.py     # CI/CD integration tests
pytest tests/test_vigileguard.py      # Core scanner tests

# Run with coverage
pytest --cov=vigileguard --cov=api
```

### API Testing
```bash
# Test authentication
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Test webhook
curl -X POST http://localhost:8000/api/v1/webhooks/test \
  -H "Authorization: Bearer YOUR_TOKEN"

# Health check
curl http://localhost:8000/health
```

## 📈 Performance & Scaling

### Performance Metrics
- **Scan Speed**: < 30 seconds for typical infrastructure
- **API Throughput**: 100+ concurrent requests
- **Report Generation**: < 10 seconds for standard reports
- **Webhook Delivery**: < 1 second typical latency

### Scaling Considerations
- **Horizontal Scaling**: Multiple API instances behind load balancer
- **Database**: PostgreSQL with read replicas for high availability
- **Caching**: Redis for API response caching and session management
- **Queue Processing**: Celery for background scan execution

## 🛠️ Development

### Setting up Development Environment
```bash
# Clone repository
git clone https://github.com/navinnm/VigileGuard.git
cd VigileGuard

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Start development API server
python -m api.main

# Start development dashboard
cd dashboard
npm install
npm start
```

### Contributing
1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

### Development Roadmap
- **Phase 3 Completion** ✅: API, CI/CD integrations, webhooks, dashboard
- **Phase 4 Planning** 🔄: ML-based threat detection, advanced analytics
- **Cloud Integrations** 📋: AWS, GCP, Azure native scanning
- **Mobile Dashboard** 📋: React Native mobile application

## 📝 Configuration

### Configuration File (config.yaml)
```yaml
# VigileGuard Configuration
api:
  host: "0.0.0.0"
  port: 8000
  debug: false
  
database:
  url: "postgresql://user:pass@localhost:5432/vigileguard"
  
redis:
  url: "redis://localhost:6379"
  
security:
  jwt_secret: "your-secret-key"
  jwt_expiry_hours: 24
  api_key_expiry_days: 365
  
scanning:
  max_concurrent_scans: 5
  default_timeout: 300
  
notifications:
  webhook_timeout: 30
  max_retries: 3
  
compliance:
  frameworks:
    - pci_dss
    - soc2
    - iso_27001
```

### Environment Variables
```bash
# API Configuration
export VIGILEGUARD_API_HOST=0.0.0.0
export VIGILEGUARD_API_PORT=8000
export VIGILEGUARD_JWT_SECRET=your-secret-key

# Database
export DATABASE_URL=postgresql://user:pass@localhost:5432/vigileguard
export REDIS_URL=redis://localhost:6379

# External Integrations
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/YOUR_TENANT_ID@YOUR_TENANT_ID/IncomingWebhook/CHANNEL_ID/CONNECTOR_ID"
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/WEBHOOK_ID/WEBHOOK_TOKEN"
export GITHUB_TOKEN=your-github-token
```

## 🚨 Troubleshooting

### Common Issues

#### API Server Won't Start
```bash
# Check port availability
netstat -tulpn | grep :8000

# Check logs
python -m api.main --debug

# Verify dependencies
pip install -r requirements.txt
```

#### Scan Failures
```bash
# Check permissions
ls -la /etc/ssh/sshd_config

# Test connectivity
ping target-server.com

# Debug mode
vigileguard --debug
```

#### Webhook Delivery Issues
```bash
# Test webhook endpoint
curl -X POST https://your-webhook-url \
  -H "Content-Type: application/json" \
  -d '{"test": "message"}'

# Check webhook logs
curl http://localhost:8000/api/v1/webhooks/{webhook_id}/stats \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Getting Help
- 📖 **Documentation**: [docs/](docs/)
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/navinnm/VigileGuard/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/navinnm/VigileGuard/discussions)
- 🔒 **Security Issues**: security@vigileguard.com

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Security Community**: For best practices and vulnerability research
- **Open Source Libraries**: FastAPI, Rich, Click, and other dependencies
- **Contributors**: All developers who have contributed to VigileGuard
- **Beta Testers**: Organizations using VigileGuard in production

## 🔗 Links

- **Homepage**: https://vigileguard.com
- **Documentation**: https://docs.vigileguard.com
- **API Docs**: http://localhost:8000/api/docs (when running)
- **GitHub**: https://github.com/navinnm/VigileGuard
- **Docker Hub**: https://hub.docker.com/r/vigileguard/
- **PyPI**: https://pypi.org/project/vigileguard/

---

**VigileGuard v3.0.7** - Comprehensive Security Audit Engine with API & CI/CD Integration

Made with ❤️ by the VigileGuard Team