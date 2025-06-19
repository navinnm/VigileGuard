#!/bin/bash

# Create VigileGuard Phase 3 deployment package

echo "📦 Creating VigileGuard Phase 3 deployment package..."

# Create deployment directory
DEPLOY_DIR="vigileguard-phase3-deployment"
rm -rf $DEPLOY_DIR
mkdir -p $DEPLOY_DIR

# Copy core files
echo "📁 Copying core files..."
cp -r vigileguard/ $DEPLOY_DIR/
cp -r api/ $DEPLOY_DIR/
cp -r integrations/ $DEPLOY_DIR/

# Copy configuration and documentation
cp requirements.txt $DEPLOY_DIR/
cp setup.py $DEPLOY_DIR/
cp config.yaml $DEPLOY_DIR/
cp README.md $DEPLOY_DIR/
cp CLAUDE.md $DEPLOY_DIR/
cp install_phase3.sh $DEPLOY_DIR/

# Copy scripts
mkdir -p $DEPLOY_DIR/scripts/
cp scripts/*.py $DEPLOY_DIR/scripts/ 2>/dev/null || true

# Create quick start script
cat > $DEPLOY_DIR/quickstart.sh << 'EOF'
#!/bin/bash

echo "🛡️  VigileGuard Phase 3 Quick Start"
echo "=================================="

# Run installation
if [[ -f "install_phase3.sh" ]]; then
    echo "Running Phase 3 installation..."
    bash install_phase3.sh
else
    echo "❌ install_phase3.sh not found"
    exit 1
fi

echo ""
echo "🚀 Quick Start Options:"
echo ""
echo "1. Test local scanning:"
echo "   ./vigileguard-cli"
echo ""
echo "2. Start API server:"
echo "   ./vigileguard-api"
echo ""
echo "3. Test API mode:"
echo "   ./vigileguard-cli --target localhost --api-mode"
echo ""

EOF

chmod +x $DEPLOY_DIR/quickstart.sh

# Create deployment instructions
cat > $DEPLOY_DIR/DEPLOYMENT.md << 'EOF'
# VigileGuard Phase 3 Deployment Guide

## Quick Installation

1. **Extract files** to your target directory
2. **Run installation**: `bash quickstart.sh`
3. **Start API server**: `./vigileguard-api`
4. **Access API docs**: http://localhost:8000/api/docs

## Manual Installation

1. Install dependencies:
   ```bash
   pip3 install -r requirements.txt
   pip3 install fastapi uvicorn pydantic python-multipart aiofiles httpx
   ```

2. Install in development mode:
   ```bash
   pip3 install -e .
   ```

3. Test installation:
   ```bash
   python3 -c "import api.main; print('Phase 3 API OK')"
   ```

4. Start API server:
   ```bash
   python3 -m api
   ```

## Usage Examples

### Local Scanning (Existing Phase 1 & 2)
```bash
python3 -m vigileguard.vigileguard
python3 -m vigileguard.vigileguard --format json --output report.json
```

### API Server (New Phase 3)
```bash
python3 -m api
# Access: http://localhost:8000/api/docs
```

### Remote Scanning via API
```bash
python3 -m vigileguard.vigileguard --target server.com --api-mode
python3 -m vigileguard.vigileguard --api-endpoint http://api.example.com --api-key KEY
```

### Webhook Notifications
```bash
python3 -m vigileguard.vigileguard --webhook-url $SLACK_WEBHOOK_URL --notifications
```

## API Authentication

### Login to get JWT token:
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

### Create API key:
```bash
curl -X POST http://localhost:8000/api/v1/auth/api-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My API Key",
    "permissions": ["scan:create", "scan:run", "report:read"],
    "expires_days": 365
  }'
```

## Troubleshooting

### Module Not Found Error
```bash
# Ensure you're in the right directory
cd /path/to/vigileguard-phase3-deployment

# Install in development mode
pip3 install -e .

# Test imports
python3 -c "import vigileguard.vigileguard; print('Phase 1&2 OK')"
python3 -c "import api.main; print('Phase 3 API OK')"
```

### Port Already in Use
```bash
# Check what's using port 8000
netstat -tulpn | grep :8000

# Use different port
python3 -c "
import os
os.environ['VIGILEGUARD_API_PORT'] = '8001'
import api.main
api.main.main()
"
```

### Dependencies Missing
```bash
# Install all Phase 3 dependencies
pip3 install fastapi uvicorn pydantic python-multipart aiofiles httpx requests

# Or use requirements file
pip3 install -r requirements.txt
```

## Production Deployment

### Using systemd service:
```bash
# Copy vigileguard-api.service to /etc/systemd/system/
sudo systemctl enable vigileguard-api
sudo systemctl start vigileguard-api
sudo systemctl status vigileguard-api
```

### Using Docker:
```bash
# Build image
docker build -t vigileguard:v3.0.7 .

# Run container
docker run -p 8000:8000 vigileguard:v3.0.7
```

### Environment Variables:
```bash
export VIGILEGUARD_API_HOST=0.0.0.0
export VIGILEGUARD_API_PORT=8000
export VIGILEGUARD_JWT_SECRET=your-secret-key
```

## Support

- Documentation: README.md
- API Docs: http://localhost:8000/api/docs
- Health Check: http://localhost:8000/health
- GitHub: https://github.com/navinnm/VigileGuard
EOF

# Create archive
echo "📦 Creating deployment archive..."
tar -czf vigileguard-phase3-v3.0.7.tar.gz $DEPLOY_DIR/

echo "✅ Deployment package created:"
echo "   📁 Directory: $DEPLOY_DIR/"
echo "   📦 Archive: vigileguard-phase3-v3.0.7.tar.gz"
echo ""
echo "🚀 To deploy:"
echo "   1. Copy vigileguard-phase3-v3.0.7.tar.gz to your server"
echo "   2. Extract: tar -xzf vigileguard-phase3-v3.0.7.tar.gz"
echo "   3. Install: cd $DEPLOY_DIR && bash quickstart.sh"
echo "   4. Start API: ./vigileguard-api"