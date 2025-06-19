# VigileGuard GitHub Actions Integration

This GitHub Action runs VigileGuard security audits in your CI/CD pipeline with full integration support including PR comments, artifact uploads, and webhook notifications.

## Features

- 🔍 **Comprehensive Security Scanning** - File permissions, SSH config, web servers, network security
- 🚨 **Configurable Failure Conditions** - Fail builds on critical/high severity issues
- 📊 **Multiple Output Formats** - JSON, HTML, PDF reports
- 💬 **Pull Request Comments** - Automatic security scan summaries on PRs
- 📦 **Artifact Upload** - Detailed reports uploaded as GitHub Actions artifacts
- 🔔 **Webhook Notifications** - Slack, Teams, Discord, or custom webhooks
- ⚡ **Fast Execution** - Optimized for CI/CD with typical scans under 30 seconds

## Quick Start

Add this step to your GitHub Actions workflow:

```yaml
- name: Run Security Audit
  uses: your-org/vigileguard-action@v3
  with:
    target: 'your-server.com'
    fail-on-critical: true
    comment-pr: true
```

## Complete Example

```yaml
name: Security Audit
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: VigileGuard Security Scan
        uses: your-org/vigileguard-action@v3
        with:
          target: 'production.example.com'
          config-file: '.github/vigileguard.yml'
          checkers: 'ssh,firewall,web-server,ssl'
          fail-on-critical: true
          fail-on-high: false
          output-format: 'json'
          upload-results: true
          comment-pr: true
          webhook-url: ${{ secrets.SLACK_WEBHOOK_URL }}
          severity-threshold: 'medium'
          timeout: 300
```

## Input Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `target` | Target to scan (hostname, IP, URL) | Yes | - |
| `config-file` | Path to VigileGuard config file | No | `.vigileguard.yml` |
| `checkers` | Comma-separated list of checkers | No | `all` |
| `fail-on-critical` | Fail build on critical issues | No | `true` |
| `fail-on-high` | Fail build on high severity issues | No | `false` |
| `output-format` | Report format (json, html, cli) | No | `json` |
| `upload-results` | Upload results as artifacts | No | `true` |
| `comment-pr` | Comment results on PRs | No | `false` |
| `api-endpoint` | VigileGuard API endpoint | No | - |
| `api-key` | API key for centralized scanning | No | - |
| `webhook-url` | Webhook URL for notifications | No | - |
| `severity-threshold` | Minimum severity to report | No | `medium` |
| `timeout` | Scan timeout in seconds | No | `300` |

## Output Parameters

| Output | Description |
|--------|-------------|
| `scan-id` | Unique scan identifier |
| `report-path` | Path to generated report |
| `critical-count` | Number of critical issues |
| `high-count` | Number of high severity issues |
| `medium-count` | Number of medium severity issues |
| `low-count` | Number of low severity issues |
| `total-issues` | Total security issues found |
| `compliance-score` | Overall compliance score (0-100) |
| `scan-status` | Scan result (passed, failed, warning) |
| `artifacts-url` | GitHub Actions artifacts URL |

## Configuration File

Create `.vigileguard.yml` in your repository:

```yaml
# VigileGuard Configuration
targets:
  - name: "Production Server"
    host: "prod.example.com"
    port: 22

checkers:
  ssh:
    enabled: true
    check_key_auth: true
    check_root_login: false
  
  firewall:
    enabled: true
    allowed_ports: [22, 80, 443]
  
  web_server:
    enabled: true
    check_ssl: true
    check_headers: true

severity_thresholds:
  critical: 0
  high: 5
  medium: 10

notifications:
  slack:
    webhook_url: "${SLACK_WEBHOOK_URL}"
    channel: "#security"
```

## Advanced Usage

### Multiple Targets

```yaml
- name: Scan Multiple Servers
  uses: your-org/vigileguard-action@v3
  with:
    target: 'web1.example.com,web2.example.com,db.example.com'
    config-file: '.github/multi-server.yml'
```

### Custom Checkers

```yaml
- name: Custom Security Checks
  uses: your-org/vigileguard-action@v3
  with:
    target: 'api.example.com'
    checkers: 'ssh,ssl,headers,cors'
    severity-threshold: 'high'
```

### Centralized API Scanning

```yaml
- name: Centralized Security Scan
  uses: your-org/vigileguard-action@v3
  with:
    target: 'fleet.example.com'
    api-endpoint: 'https://vigileguard-api.company.com'
    api-key: ${{ secrets.VIGILEGUARD_API_KEY }}
```

### Webhook Notifications

```yaml
- name: Security Scan with Notifications
  uses: your-org/vigileguard-action@v3
  with:
    target: 'critical-server.example.com'
    webhook-url: ${{ secrets.SECURITY_WEBHOOK_URL }}
    fail-on-critical: true
```

## Secrets Configuration

Configure these secrets in your repository settings:

- `VIGILEGUARD_API_KEY` - API key for centralized scanning
- `SLACK_WEBHOOK_URL` - Slack webhook for notifications
- `TEAMS_WEBHOOK_URL` - Microsoft Teams webhook
- `DISCORD_WEBHOOK_URL` - Discord webhook

## PR Comments

When `comment-pr: true` is enabled, the action will automatically comment on pull requests with scan results:

```markdown
## ✅ VigileGuard Security Scan Results

**Scan ID:** `gh_org_repo_abc12345_def67890`
**Target:** `production.example.com`
**Status:** PASSED

### 📊 Summary
- **Critical Issues:** 0
- **High Issues:** 1
- **Medium Issues:** 3
- **Low Issues:** 5
- **Total Issues:** 9
- **Compliance Score:** 87.5%

### ⚠️ Security Issues Found
- Review and address the identified security issues

📋 **Detailed Report:** Check the GitHub Actions artifacts for complete results.
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Ensure the target server allows connections from GitHub Actions IPs
   - Verify SSH keys or credentials are properly configured

2. **Timeout Errors**
   - Increase `timeout` parameter for slow networks
   - Check network connectivity to target

3. **Missing Reports**
   - Verify `upload-results` is enabled
   - Check if scan completed successfully

### Debug Mode

Enable debug logging by setting the `ACTIONS_STEP_DEBUG` secret to `true` in your repository.

## Support

- **Documentation**: [VigileGuard Docs](https://docs.vigileguard.com)
- **Issues**: [GitHub Issues](https://github.com/your-org/vigileguard/issues)
- **Security**: Report security issues privately to security@vigileguard.com

## License

MIT License - see LICENSE file for details.