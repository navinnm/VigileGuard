#!/bin/bash
# Quick fix script to add HTML support to existing vigileguard

echo "🔧 Adding Phase 2 HTML support to VigileGuard..."

# Check if vigileguard command exists
if ! command -v vigileguard &> /dev/null; then
    echo "❌ vigileguard command not found. Please install VigileGuard first."
    exit 1
fi

# Find vigileguard.py location
VIGILEGUARD_PATH=$(which vigileguard)
VIGILEGUARD_DIR=$(dirname "$VIGILEGUARD_PATH")

echo "📍 Found vigileguard at: $VIGILEGUARD_PATH"

# Create a simple HTML reporter as a workaround
cat > /tmp/simple_html_reporter.py << 'EOF'
#!/usr/bin/env python3
"""
Simple HTML Reporter for VigileGuard
Temporary solution until Phase 2 is fully integrated
"""

import json
import sys
from datetime import datetime

def generate_simple_html_report(json_file, html_file):
    """Generate a simple HTML report from JSON output"""
    
    # Read JSON data
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading JSON file: {e}")
        sys.exit(1)
    
    # Extract data
    scan_info = data.get('scan_info', {})
    summary = data.get('summary', {})
    findings = data.get('findings', [])
    
    # Generate HTML
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VigileGuard Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; text-align: center; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: #f8f9fa; padding: 20px; border-radius: 10px; text-align: center; border-left: 4px solid #667eea; }}
        .finding {{ margin: 15px 0; padding: 20px; border-radius: 10px; border-left: 5px solid #ddd; background: #f8f9fa; }}
        .critical {{ border-left-color: #dc3545; }}
        .high {{ border-left-color: #fd7e14; }}
        .medium {{ border-left-color: #ffc107; }}
        .low {{ border-left-color: #28a745; }}
        .info {{ border-left-color: #6c757d; }}
        .severity {{ display: inline-block; padding: 4px 8px; border-radius: 4px; color: white; font-weight: bold; font-size: 0.8em; }}
        .severity.critical {{ background-color: #dc3545; }}
        .severity.high {{ background-color: #fd7e14; }}
        .severity.medium {{ background-color: #ffc107; color: #333; }}
        .severity.low {{ background-color: #28a745; }}
        .severity.info {{ background-color: #6c757d; }}
        .footer {{ text-align: center; margin-top: 40px; color: #666; border-top: 1px solid #ddd; padding-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ VigileGuard Security Report</h1>
            <p>Generated on {scan_info.get('timestamp', 'Unknown')}</p>
            <p>Host: {scan_info.get('hostname', 'Unknown')}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div style="font-size: 2em; color: #667eea;">{summary.get('total_findings', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>Critical</h3>
                <div style="font-size: 2em; color: #dc3545;">{summary.get('by_severity', {}).get('CRITICAL', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>High</h3>
                <div style="font-size: 2em; color: #fd7e14;">{summary.get('by_severity', {}).get('HIGH', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>Medium</h3>
                <div style="font-size: 2em; color: #ffc107;">{summary.get('by_severity', {}).get('MEDIUM', 0)}</div>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
    """
    
    # Add findings
    for finding in findings:
        severity = finding.get('severity', 'INFO').lower()
        html_content += f"""
        <div class="finding {severity}">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <h3 style="margin: 0;">{finding.get('title', 'Unknown')}</h3>
                <span class="severity {severity}">{finding.get('severity', 'INFO')}</span>
            </div>
            <p><strong>Category:</strong> {finding.get('category', 'Unknown')}</p>
            <p><strong>Description:</strong> {finding.get('description', 'No description')}</p>
            <p><strong>Recommendation:</strong> {finding.get('recommendation', 'No recommendation')}</p>
        </div>
        """
    
    html_content += """
        <div class="footer">
            <p>Generated by VigileGuard - Linux Security Audit Tool</p>
            <p><a href="https://github.com/navinnm/VigileGuard">GitHub Repository</a></p>
        </div>
    </div>
</body>
</html>
    """
    
    # Write HTML file
    try:
        with open(html_file, 'w') as f:
            f.write(html_content)
        print(f"✅ HTML report generated: {html_file}")
    except Exception as e:
        print(f"Error writing HTML file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python simple_html_reporter.py <input.json> <output.html>")
        sys.exit(1)
    
    json_file = sys.argv[1]
    html_file = sys.argv[2]
    generate_simple_html_report(json_file, html_file)
EOF

echo "📄 Created simple HTML reporter at /tmp/simple_html_reporter.py"

# Create a wrapper script
cat > /tmp/vigileguard_html.sh << 'EOF'
#!/bin/bash
# VigileGuard HTML Report Generator
# Temporary workaround for HTML output

TEMP_JSON="/tmp/vigileguard_temp_$(date +%s).json"
OUTPUT_HTML="$1"

if [ -z "$OUTPUT_HTML" ]; then
    OUTPUT_HTML="vigileguard_report_$(date +%Y%m%d_%H%M%S).html"
fi

echo "🛡️ Generating VigileGuard HTML report..."

# Generate JSON first
echo "📊 Running security scan..."
vigileguard --format json --output "$TEMP_JSON"

if [ $? -eq 0 ]; then
    echo "📝 Converting to HTML..."
    python3 /tmp/simple_html_reporter.py "$TEMP_JSON" "$OUTPUT_HTML"
    
    if [ $? -eq 0 ]; then
        echo "✅ HTML report generated: $OUTPUT_HTML"
        echo "🌐 Open in browser: file://$(pwd)/$OUTPUT_HTML"
        
        # Clean up
        rm -f "$TEMP_JSON"
    else
        echo "❌ Failed to generate HTML report"
        exit 1
    fi
else
    echo "❌ Failed to run security scan"
    exit 1
fi
EOF

chmod +x /tmp/vigileguard_html.sh

echo "✅ Created HTML wrapper script at /tmp/vigileguard_html.sh"
echo ""
echo "🚀 Quick Usage:"
echo "  /tmp/vigileguard_html.sh report.html"
echo ""
echo "Or to generate with current format options:"
echo "  vigileguard --format json --output temp.json"
echo "  python3 /tmp/simple_html_reporter.py temp.json report.html"