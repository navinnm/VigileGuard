#!/bin/bash
# VigileGuard Cron Setup Script
# =============================

echo "🛡️ VigileGuard Cron Setup Script"
echo "================================="

# Check if vigileguard is installed
if ! command -v vigileguard &> /dev/null; then
    echo "❌ VigileGuard not found in PATH"
    echo "Please install VigileGuard first: pip install vigileguard"
    exit 1
fi

echo "✅ VigileGuard found: $(which vigileguard)"

# Create log directory
LOG_DIR="/var/log/vigileguard"
if [ ! -d "$LOG_DIR" ]; then
    echo "📁 Creating log directory: $LOG_DIR"
    sudo mkdir -p "$LOG_DIR"
    sudo chown $(whoami):$(whoami) "$LOG_DIR" 2>/dev/null || true
fi

# Setup daily scan (2 AM)
echo "⏰ Setting up daily scan at 2:00 AM..."
DAILY_CRON="0 2 * * * $(which vigileguard) --format json --output $LOG_DIR/daily-\$(date +\%Y\%m\%d).json"

# Setup weekly scan (Sunday 3 AM)  
echo "📅 Setting up weekly scan on Sunday at 3:00 AM..."
WEEKLY_CRON="0 3 * * 0 $(which vigileguard) --format all --output $LOG_DIR/weekly-\$(date +\%Y\%m\%d)"

# Add to crontab
(crontab -l 2>/dev/null; echo "$DAILY_CRON"; echo "$WEEKLY_CRON") | crontab -

if [ $? -eq 0 ]; then
    echo "✅ Cron jobs added successfully!"
    echo ""
    echo "📋 Current crontab:"
    crontab -l | grep vigileguard
    echo ""
    echo "📊 Reports will be saved to: $LOG_DIR"
    echo "💡 To remove cron jobs: crontab -e"
else
    echo "❌ Failed to add cron jobs"
    exit 1
fi