#!/bin/bash
# VigileGuard Installation Script
# Installs VigileGuard with Phase 1 + Phase 2 components

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_NAME="VigileGuard Installer"
VERSION="3.0.3"
REPO_URL="https://github.com/navinnm/VigileGuard"
PYTHON_MIN_VERSION="3.8"

# Installation options
INSTALL_TYPE="user"  # user, system, venv
INSTALL_DIR=""
CREATE_VENV=false
ENABLE_NOTIFICATIONS=false
SETUP_CRON=false

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python version
check_python_version() {
    if ! command_exists python3; then
        print_error "Python 3 is not installed"
        return 1
    fi
    
    local python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    local required_version=$PYTHON_MIN_VERSION
    
    if python3 -c "import sys; exit(0 if sys.version_info >= tuple(map(int, '$required_version'.split('.'))) else 1)"; then
        print_success "Python $python_version detected (>= $required_version required)"
        return 0
    else
        print_error "Python $python_version detected, but >= $required_version is required"
        return 1
    fi
}

# Function to check system requirements
check_requirements() {
    print_status "Checking system requirements..."
    
    # Check Python
    if ! check_python_version; then
        print_error "Python version check failed"
        exit 1
    fi
    
    # Check pip
    if ! command_exists pip3; then
        print_error "pip3 is not installed"
        print_status "Installing pip3..."
        if command_exists apt-get; then
            sudo apt-get update && sudo apt-get install -y python3-pip
        elif command_exists yum; then
            sudo yum install -y python3-pip
        elif command_exists pacman; then
            sudo pacman -S python-pip
        else
            print_error "Could not install pip3. Please install it manually."
            exit 1
        fi
    fi
    
    # Check git (optional)
    if ! command_exists git; then
        print_warning "Git is not installed. Some features may not work."
    fi
    
    print_success "System requirements check passed"
}

# Function to show usage
show_usage() {
    cat << EOF
🛡️ $SCRIPT_NAME v$VERSION

Usage: $0 [OPTIONS]

Installation Options:
  --user              Install for current user only (default)
  --system            Install system-wide (requires sudo)
  --venv DIR          Create virtual environment in DIR
  --install-dir DIR   Custom installation directory

Features:
  --notifications     Enable notification dependencies
  --setup-cron        Setup scheduled security scans
  --dev               Install development dependencies

General Options:
  --help             Show this help message
  --version          Show version information
  --check-only       Only check requirements, don't install

Examples:
  $0                           # Basic user installation
  $0 --venv ./venv             # Install in virtual environment
  $0 --system --notifications  # System-wide with notifications
  $0 --dev                     # Development installation

Repository: $REPO_URL
EOF
}

# Function to create virtual environment
create_virtual_environment() {
    local venv_dir="$1"
    
    print_status "Creating virtual environment in $venv_dir..."
    
    python3 -m venv "$venv_dir"
    
    # Activate virtual environment
    source "$venv_dir/bin/activate"
    
    # Upgrade pip in venv
    pip install --upgrade pip
    
    print_success "Virtual environment created and activated"
}

# Function to install VigileGuard
install_vigileguard() {
    print_status "Installing VigileGuard..."
    
    local pip_cmd="pip3"
    local install_args=""
    
    # Set installation arguments based on type
    case $INSTALL_TYPE in
        "user")
            install_args="--user"
            ;;
        "system")
            if [[ $EUID -ne 0 ]]; then
                print_error "System installation requires root privileges"
                print_status "Please run with sudo or use --user option"
                exit 1
            fi
            ;;
        "venv")
            pip_cmd="pip"  # Use pip from virtual environment
            ;;
    esac
    
    # Install base package
    if [[ -f "setup.py" ]] && [[ -f "vigileguard/__init__.py" ]]; then
        # Install from source (development)
        print_status "Installing from source..."
        if [[ "$ENABLE_DEV" == "true" ]]; then
            $pip_cmd install $install_args -e ".[dev,full]"
        elif [[ "$ENABLE_NOTIFICATIONS" == "true" ]]; then
            $pip_cmd install $install_args -e ".[notifications]"
        else
            $pip_cmd install $install_args -e .
        fi
    else
        # Install from PyPI
        print_status "Installing from PyPI..."
        if [[ "$ENABLE_DEV" == "true" ]]; then
            $pip_cmd install $install_args "vigileguard[dev,full]"
        elif [[ "$ENABLE_NOTIFICATIONS" == "true" ]]; then
            $pip_cmd install $install_args "vigileguard[notifications]"
        else
            $pip_cmd install $install_args vigileguard
        fi
    fi
    
    print_success "VigileGuard installation completed"
}

# Function to verify installation
verify_installation() {
    print_status "Verifying installation..."
    
    # Check if vigileguard command is available
    if command_exists vigileguard; then
        local version=$(vigileguard --version 2>/dev/null || echo "unknown")
        print_success "VigileGuard command available: $version"
    else
        print_warning "VigileGuard command not found in PATH"
        print_status "You may need to add ~/.local/bin to your PATH"
    fi
    
    # Test Python import
    if python3 -c "import vigileguard; print(f'✅ VigileGuard {vigileguard.__version__} imported successfully')" 2>/dev/null; then
        print_success "Python import test passed"
    else
        print_error "Python import test failed"
        return 1
    fi
    
    # Check Phase 2 availability
    if python3 -c "import vigileguard; print('✅ Phase 2 Available' if vigileguard.PHASE2_AVAILABLE else '⚠️ Phase 1 Only')" 2>/dev/null; then
        print_success "Phase detection test passed"
    else
        print_warning "Could not detect available phases"
    fi
}

# Function to setup configuration
setup_configuration() {
    print_status "Setting up configuration..."
    
    local config_dir="$HOME/.config/vigileguard"
    mkdir -p "$config_dir"
    
    # Create sample configuration
    cat > "$config_dir/config.yaml" << EOF
# VigileGuard Configuration File
vigileguard:
  # Output settings
  output:
    directory: "./reports"
    timestamp_format: "%Y%m%d_%H%M%S"
    
  # Security check settings  
  checks:
    file_permissions: true
    user_accounts: true
    ssh_configuration: true
    web_security: true
    network_security: true
    
  # Reporting settings
  reports:
    include_compliance: true
    severity_threshold: "INFO"
    max_findings_per_category: 100
    
  # Phase 2 settings
  phase2:
    enabled: true
    web_security_deep_scan: true
    network_port_scan: true
    enhanced_html_reports: true
    
  # Notification settings (disabled by default)
  notifications:
    enabled: false
    email:
      enabled: false
      smtp_server: ""
      smtp_port: 587
      username: ""
      password: ""
      recipients: []
    slack:
      enabled: false
      webhook_url: ""
      channel: "#security"
    webhook:
      enabled: false
      url: ""
EOF
    
    print_success "Configuration created at $config_dir/config.yaml"
}

# Function to setup cron jobs
setup_cron_jobs() {
    if [[ "$SETUP_CRON" != "true" ]]; then
        return
    fi
    
    print_status "Setting up scheduled scans..."
    
    # Create cron script
    local cron_script="/usr/local/bin/vigileguard-daily-scan"
    
    cat > "$cron_script" << 'EOF'
#!/bin/bash
# VigileGuard Daily Security Scan

LOG_DIR="/var/log/vigileguard"
REPORT_DIR="/var/log/vigileguard/reports"
DATE=$(date +%Y%m%d)

# Create directories
mkdir -p "$LOG_DIR" "$REPORT_DIR"

# Run scan
vigileguard --format json --output "$REPORT_DIR/daily-scan-$DATE.json" \
    >> "$LOG_DIR/vigileguard.log" 2>&1

# Clean old reports (keep 30 days)
find "$REPORT_DIR" -name "daily-scan-*.json" -mtime +30 -delete

# Send notifications for critical findings (if configured)
if command -v vigileguard-notify >/dev/null 2>&1; then
    vigileguard-notify "$REPORT_DIR/daily-scan-$DATE.json"
fi
EOF
    
    chmod +x "$cron_script"
    
    # Add to crontab (run daily at 2 AM)
    (crontab -l 2>/dev/null; echo "0 2 * * * $cron_script") | crontab -
    
    print_success "Daily security scan scheduled for 2:00 AM"
}

# Function to show post-installation instructions
show_post_install() {
    print_success "🛡️ VigileGuard Installation Complete!"
    echo ""
    echo "Quick Start Commands:"
    echo "  vigileguard --help                    # Show help"
    echo "  vigileguard --format console          # Run basic scan"
    echo "  vigileguard --format html --output report.html  # Generate HTML report"
    echo "  vigileguard --format json --output report.json  # Generate JSON report"
    echo ""
    
    if [[ "$INSTALL_TYPE" == "venv" ]]; then
        echo "Virtual Environment:"
        echo "  source $INSTALL_DIR/bin/activate     # Activate virtual environment"
        echo ""
    fi
    
    echo "Configuration:"
    echo "  ~/.config/vigileguard/config.yaml    # Edit configuration"
    echo ""
    
    echo "Documentation:"
    echo "  $REPO_URL                             # GitHub repository"
    echo "  $REPO_URL/blob/main/docs/             # Documentation"
    echo ""
    
    if [[ "$SETUP_CRON" == "true" ]]; then
        echo "Scheduled Scans:"
        echo "  Daily scans configured at 2:00 AM"
        echo "  Reports saved to /var/log/vigileguard/reports/"
        echo ""
    fi
    
    print_status "Installation completed successfully! 🎉"
}

# Main installation function
main() {
    echo "🛡️ $SCRIPT_NAME v$VERSION"
    echo "==============================="
    echo ""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_usage
                exit 0
                ;;
            --version)
                echo "$SCRIPT_NAME v$VERSION"
                exit 0
                ;;
            --check-only)
                check_requirements
                print_success "Requirements check completed"
                exit 0
                ;;
            --user)
                INSTALL_TYPE="user"
                ;;
            --system)
                INSTALL_TYPE="system"
                ;;
            --venv)
                INSTALL_TYPE="venv"
                INSTALL_DIR="$2"
                CREATE_VENV=true
                shift
                ;;
            --install-dir)
                INSTALL_DIR="$2"
                shift
                ;;
            --notifications)
                ENABLE_NOTIFICATIONS=true
                ;;
            --setup-cron)
                SETUP_CRON=true
                ;;
            --dev)
                ENABLE_DEV=true
                ENABLE_NOTIFICATIONS=true
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
        shift
    done
    
    # Set default venv directory if not specified
    if [[ "$CREATE_VENV" == "true" ]] && [[ -z "$INSTALL_DIR" ]]; then
        INSTALL_DIR="./vigileguard-venv"
    fi
    
    # Check requirements
    check_requirements
    
    # Create virtual environment if requested
    if [[ "$CREATE_VENV" == "true" ]]; then
        create_virtual_environment "$INSTALL_DIR"
    fi
    
    # Install VigileGuard
    install_vigileguard
    
    # Verify installation
    verify_installation
    
    # Setup configuration
    setup_configuration
    
    # Setup cron jobs if requested
    setup_cron_jobs
    
    # Show post-installation instructions
    show_post_install
}

# Run main function
main "$@"