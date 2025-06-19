#!/bin/bash

# VigileGuard Phase 3 Installation Script
# Installs API server and CI/CD integration components

set -e

echo "🛡️  VigileGuard Phase 3 Installation"
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${YELLOW}Warning: Running as root. Consider using a virtual environment.${NC}"
fi

# Detect Python command
PYTHON_CMD=""
if command -v python3 &> /dev/null; then
    PYTHON_CMD="python3"
elif command -v python &> /dev/null; then
    PYTHON_CMD="python"
else
    echo -e "${RED}❌ Python 3.8+ is required but not found${NC}"
    exit 1
fi

echo -e "${BLUE}🔍 Using Python: $(which $PYTHON_CMD)${NC}"
echo -e "${BLUE}🔍 Python version: $($PYTHON_CMD --version)${NC}"

# Check Python version
PYTHON_VERSION=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
if ! $PYTHON_CMD -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"; then
    echo -e "${RED}❌ Python 3.8+ required, found $PYTHON_VERSION${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Python $PYTHON_VERSION detected${NC}"

# Check if we're in the right directory
if [[ ! -f "vigileguard/vigileguard.py" ]]; then
    echo -e "${RED}❌ Please run this script from the VigileGuard root directory${NC}"
    echo -e "${YELLOW}Expected to find: vigileguard/vigileguard.py${NC}"
    exit 1
fi

echo -e "${GREEN}✅ VigileGuard directory structure verified${NC}"

# Install Phase 3 dependencies
echo -e "${BLUE}📦 Installing Phase 3 dependencies...${NC}"

# Check if pip is available
if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
    echo -e "${RED}❌ pip is required but not found${NC}"
    exit 1
fi

PIP_CMD="pip3"
if ! command -v pip3 &> /dev/null; then
    PIP_CMD="pip"
fi

# Install requirements
echo -e "${BLUE}Installing base requirements...${NC}"
$PIP_CMD install -r requirements.txt

echo -e "${BLUE}Installing Phase 3 API requirements...${NC}"
$PIP_CMD install fastapi uvicorn pydantic python-multipart aiofiles httpx

# Install in development mode
echo -e "${BLUE}Installing VigileGuard in development mode...${NC}"
$PIP_CMD install -e .

# Create necessary directories
echo -e "${BLUE}📁 Creating directories...${NC}"
mkdir -p /tmp/vigileguard_reports
mkdir -p logs

# Set up configuration
echo -e "${BLUE}⚙️ Setting up configuration...${NC}"

# Create API configuration if it doesn't exist
if [[ ! -f "api_config.yaml" ]]; then
    cat > api_config.yaml << EOF
# VigileGuard Phase 3 API Configuration
api:
  host: "127.0.0.1"
  port: 8000
  debug: true
  
security:
  jwt_secret: "$(openssl rand -base64 32 2>/dev/null || echo 'change-this-secret-key-in-production')"
  jwt_expiry_hours: 24
  api_key_expiry_days: 365
  
scanning:
  max_concurrent_scans: 5
  default_timeout: 300
  
notifications:
  webhook_timeout: 30
  max_retries: 3
  
logging:
  level: "INFO"
  file: "logs/vigileguard_api.log"
EOF
    echo -e "${GREEN}✅ Created api_config.yaml${NC}"
fi

# Test Phase 1 & 2 (existing functionality)
echo -e "${BLUE}🧪 Testing Phase 1 & 2 functionality...${NC}"
if $PYTHON_CMD -c "import vigileguard.vigileguard; print('Phase 1 & 2 OK')" 2>/dev/null; then
    echo -e "${GREEN}✅ Phase 1 & 2 components working${NC}"
else
    echo -e "${YELLOW}⚠️ Phase 1 & 2 may have issues, but continuing...${NC}"
fi

# Test Phase 3 API imports
echo -e "${BLUE}🧪 Testing Phase 3 API components...${NC}"
if $PYTHON_CMD -c "import api.main; print('Phase 3 API OK')" 2>/dev/null; then
    echo -e "${GREEN}✅ Phase 3 API components working${NC}"
else
    echo -e "${RED}❌ Phase 3 API components failed to load${NC}"
    echo -e "${YELLOW}Please check the error above and ensure all dependencies are installed${NC}"
    exit 1
fi

# Create systemd service file (optional)
if command -v systemctl &> /dev/null && [[ $EUID -eq 0 ]]; then
    echo -e "${BLUE}🔧 Creating systemd service...${NC}"
    cat > /etc/systemd/system/vigileguard-api.service << EOF
[Unit]
Description=VigileGuard Security Audit API
After=network.target

[Service]
Type=simple
User=vigileguard
WorkingDirectory=$(pwd)
Environment=PATH=/usr/local/bin:/usr/bin:/bin
ExecStart=$PYTHON_CMD -m api
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    echo -e "${GREEN}✅ Systemd service created (/etc/systemd/system/vigileguard-api.service)${NC}"
    echo -e "${YELLOW}Note: Create 'vigileguard' user and adjust paths as needed${NC}"
fi

# Create wrapper scripts
echo -e "${BLUE}📜 Creating wrapper scripts...${NC}"

# CLI wrapper with Phase 3 options
cat > vigileguard-cli << 'EOF'
#!/bin/bash
# VigileGuard CLI wrapper with Phase 3 support

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

if command -v python3 &> /dev/null; then
    python3 -m vigileguard.vigileguard "$@"
elif command -v python &> /dev/null; then
    python -m vigileguard.vigileguard "$@"
else
    echo "Error: Python not found"
    exit 1
fi
EOF

# API server wrapper
cat > vigileguard-api << 'EOF'
#!/bin/bash
# VigileGuard API Server wrapper

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

echo "🛡️  Starting VigileGuard Phase 3 API Server..."
echo "API Documentation: http://localhost:8000/api/docs"
echo "Health Check: http://localhost:8000/health"
echo ""

if command -v python3 &> /dev/null; then
    python3 -m api
elif command -v python &> /dev/null; then
    python -m api
else
    echo "Error: Python not found"
    exit 1
fi
EOF

chmod +x vigileguard-cli vigileguard-api

echo -e "${GREEN}✅ Created wrapper scripts:${NC}"
echo -e "   - ./vigileguard-cli (CLI with Phase 3 support)"
echo -e "   - ./vigileguard-api (API server)"

# Installation summary
echo ""
echo -e "${GREEN}🎉 VigileGuard Phase 3 Installation Complete!${NC}"
echo "=================================================="
echo ""
echo -e "${BLUE}Available Commands:${NC}"
echo -e "  ${YELLOW}Local Scanning (Phase 1 & 2):${NC}"
echo -e "    ./vigileguard-cli"
echo -e "    ./vigileguard-cli --format json --output report.json"
echo ""
echo -e "  ${YELLOW}API Server (Phase 3):${NC}"
echo -e "    ./vigileguard-api"
echo -e "    $PYTHON_CMD -m api"
echo ""
echo -e "  ${YELLOW}Remote Scanning via API:${NC}"
echo -e "    ./vigileguard-cli --target server.com --api-mode"
echo -e "    ./vigileguard-cli --api-endpoint http://api.example.com --api-key KEY"
echo ""
echo -e "  ${YELLOW}CI/CD Integration:${NC}"
echo -e "    ./vigileguard-cli --webhook-url \$SLACK_URL --notifications"
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo -e "1. Start API server: ${YELLOW}./vigileguard-api${NC}"
echo -e "2. Visit API docs: ${YELLOW}http://localhost:8000/api/docs${NC}"
echo -e "3. Test authentication: ${YELLOW}curl -X POST http://localhost:8000/api/v1/auth/login${NC}"
echo -e "4. Configure webhooks for Slack/Teams/Discord notifications"
echo -e "5. Set up GitHub Actions using templates in integrations/"
echo ""
echo -e "${GREEN}Phase 3 Features Available:${NC}"
echo -e "✅ REST API with JWT authentication"
echo -e "✅ Role-based access control (RBAC)"
echo -e "✅ Remote scanning capabilities"
echo -e "✅ Webhook notifications (Slack, Teams, Discord)"
echo -e "✅ Multi-format reports (JSON, HTML, PDF, CSV)"
echo -e "✅ GitHub Actions integration"
echo -e "✅ API key management"
echo ""
echo -e "${BLUE}For help: ./vigileguard-cli --help${NC}"
echo -e "${BLUE}Documentation: https://docs.vigileguard.com${NC}"