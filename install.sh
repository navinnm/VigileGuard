#!/bin/bash
set -e

# VigileGuard Installation Script
# Repository: https://github.com/navinnm/VigileGuard
# This script installs VigileGuard on Linux systems

REPO_URL="https://github.com/navinnm/VigileGuard"
INSTALL_DIR="/opt/vigileguard"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/vigileguard"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# VigileGuard ASCII Art
show_banner() {
    echo -e "${BLUE}"
    cat << 'EOF'
    ____   ____.__       .__.__         ________                       .___
    \   \ /   /|__| ____ |__|  |   ____ /  _____/ __ _______ _______  __| _/
     \   Y   / |  |/ ___\|  |  | _/ __ \   \  ___|  |  \__  \\_  __ \/ __ | 
      \     /  |  / /_/  >  |  |_\  ___/|    \_\  \  |  // __ \|  | \/ /_/ | 
       \___/   |__\___  /|__|____/\___  >\______  /____/(____  /__|  \____ | 
                 /_____/              \/        \/           \/           \/ 
    
    Linux Security Audit Tool - Your Vigilant Guardian
EOF
    echo -e "${NC}"
}

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${PURPLE}[STEP]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        INSTALL_DIR="/opt/vigileguard"
        BIN_DIR="/usr/local/bin"
        CONFIG_DIR="/etc/vigileguard"
        log_info "Installing as root to system directories"
    else
        INSTALL_DIR="$HOME/.local/share/vigileguard"
        BIN_DIR="$HOME/.local/bin"
        CONFIG_DIR="$HOME/.config/vigileguard"
        log_warn "Installing as regular user to $INSTALL_DIR"
    fi
}

# Check system requirements
check_requirements() {
    log_step "Checking system requirements..."
    
    # Check Python version
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed"
        log_info "Install Python 3.8+ and try again"
        exit 1
    fi
    
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    
    if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
        log_error "Python 3.8+ is required, found $python_version"
        log_info "Please upgrade Python and try again"
        exit 1
    fi
    
    log_success "Python $python_version found"
    
    # Check pip
    if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
        log_error "pip is required but not installed"
        log_info "Install pip and try again"
        exit 1
    fi
    
    # Check git
    if ! command -v git &> /dev/null; then
        log_error "git is required but not installed"
        log_info "Install git and try again"
        exit 1
    fi
    
    log_success "All requirements satisfied"
}

# Install from source
install_from_source() {
    log_step "Installing VigileGuard from source..."
    
    # Create installation directory
    mkdir -p "$INSTALL_DIR"
    
    # Clone repository
    log_info "Cloning VigileGuard repository..."
    if [ -d "$INSTALL_DIR/.git" ]; then
        cd "$INSTALL_DIR"
        git pull origin main
        log_info "Updated existing installation"
    else
        git clone "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
        log_success "Repository cloned successfully"
    fi
    
    # Install dependencies
    log_info "Installing Python dependencies..."
    if command -v pip3 &> /dev/null; then
        PIP_CMD="pip3"
    else
        PIP_CMD="pip"
    fi
    
    if [[ $EUID -eq 0 ]]; then
        $PIP_CMD install -r requirements.txt
    else
        $PIP_CMD install --user -r requirements.txt
    fi
    
    log_success "Dependencies installed"
}

# Create executable script
create_executable() {
    log_step "Creating executable scripts..."
    
    # Create bin directory if it doesn't exist
    mkdir -p "$BIN_DIR"
    
    # Create vigileguard executable
    cat > "$BIN_DIR/vigileguard" << EOF
#!/bin/bash
# VigileGuard launcher script
cd "$INSTALL_DIR"
python3 vigileguard.py "\$@"
EOF
    
    chmod +x "$BIN_DIR/vigileguard"
    
    # Create short alias
    cat > "$BIN_DIR/vg" << EOF
#!/bin/bash
# VigileGuard short alias
cd "$INSTALL_DIR"
python3 vigileguard.py "\$@"
EOF
    
    chmod +x "$BIN_DIR/vg"
    
    log_success "Executable scripts created"
    log_info "  vigileguard - Full command"
    log_info "  vg          - Short alias"
}

# Install configuration
install_config() {
    log_step "Installing default configuration..."
    
    mkdir -p "$CONFIG_DIR"
    
    # Copy default config if it doesn't exist
    if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
        cp "$INSTALL_DIR/config.yaml" "$CONFIG_DIR/config.yaml"
        log_success "Default configuration installed at $CONFIG_DIR/config.yaml"
    else
        log_info "Configuration already exists at $CONFIG_DIR/config.yaml"
        # Backup and update
        cp "$CONFIG_DIR/config.yaml" "$CONFIG_DIR/config.yaml.backup"
        cp "$INSTALL_DIR/config.yaml" "$CONFIG_DIR/config.yaml.new"
        log_info "New config available at $CONFIG_DIR/config.yaml.new"
    fi
}

# Add to PATH
update_path() {
    log_step "Updating PATH..."
    
    if [[ $EUID -ne 0 ]]; then
        # Add to user PATH
        SHELL_RC=""
        if [ -f "$HOME/.bashrc" ]; then
            SHELL_RC="$HOME/.bashrc"
        elif [ -f "$HOME/.zshrc" ]; then
            SHELL_RC="$HOME/.zshrc"
        elif [ -f "$HOME/.profile" ]; then
            SHELL_RC="$HOME/.profile"
        fi
        
        if [ -n "$SHELL_RC" ]; then
            if ! grep -q "$BIN_DIR" "$SHELL_RC"; then
                echo "" >> "$SHELL_RC"
                echo "# VigileGuard PATH" >> "$SHELL_RC"
                echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$SHELL_RC"
                log_success "Added $BIN_DIR to PATH in $SHELL_RC"
                log_warn "Please run: source $SHELL_RC or restart your terminal"
            else
                log_info "PATH already updated"
            fi
        fi
    fi
}

# Create systemd service (optional)
create_service() {
    if [[ $EUID -eq 0 ]] && command -v systemctl &> /dev/null; then
        log_step "Creating systemd service (optional)..."
        
        cat > /etc/systemd/system/vigileguard-scan.service << EOF
[Unit]
Description=VigileGuard Security Scan
After=network.target

[Service]
Type=oneshot
ExecStart=$BIN_DIR/vigileguard --format json --output /var/log/vigileguard-scan.json
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

        cat > /etc/systemd/system/vigileguard-scan.timer << EOF
[Unit]
Description=Run VigileGuard Security Scan Daily
Requires=vigileguard-scan.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

        systemctl daemon-reload
        log_success "Systemd service created"
        log_info "  Start: systemctl start vigileguard-scan"
        log_info "  Enable daily scans: systemctl enable --now vigileguard-scan.timer"
    fi
}

# Verify installation
verify_installation() {
    log_step "Verifying installation..."
    
    # Check if vigileguard command works
    if command -v vigileguard &> /dev/null; then
        version=$(vigileguard --version 2>/dev/null || echo "1.0.0")
        log_success "VigileGuard installed successfully: $version"
        
        # Test basic functionality
        log_info "Running basic functionality test..."
        if vigileguard --help &> /dev/null; then
            log_success "Basic functionality test passed"
        else
            log_warn "Basic functionality test failed"
        fi
        
        return 0
    else
        log_error "VigileGuard command not found in PATH"
        log_info "Try running: $BIN_DIR/vigileguard --help"
        return 1
    fi
}

# Show usage information
show_usage() {
    echo
    log_success "🎉 VigileGuard installation completed!"
    echo
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo
    echo -e "${GREEN}Usage:${NC}"
    echo "  vigileguard                    # Run basic security audit"
    echo "  vigileguard --help             # Show all options"
    echo "  vigileguard --format json      # Generate JSON report"
    echo "  vg                             # Short alias"
    echo
    echo -e "${GREEN}Configuration:${NC}"
    echo "  $CONFIG_DIR/config.yaml"
    echo
    echo -e "${GREEN}Examples:${NC}"
    echo "  vigileguard --config $CONFIG_DIR/config.yaml"
    echo "  vigileguard --format json --output security-report.json"
    echo "  vigileguard --format console | less"
    echo
    echo -e "${GREEN}CI/CD Integration:${NC}"
    echo "  # Returns exit code 1 if critical/high issues found"
    echo "  vigileguard && echo 'Security audit passed'"
    echo
    echo -e "${GREEN}Documentation:${NC}"
    echo "  Repository: $REPO_URL"
    echo "  Issues:     $REPO_URL/issues"
    echo
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}Note:${NC} Restart your terminal or run:"
        echo "  export PATH=\"$BIN_DIR:\$PATH\""
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Cleanup function
cleanup() {
    if [ $? -ne 0 ]; then
        echo
        log_error "Installation failed"
        log_info "Manual installation steps:"
        log_info "1. git clone $REPO_URL"
        log_info "2. cd VigileGuard"
        log_info "3. pip install -r requirements.txt"
        log_info "4. python vigileguard.py --help"
        echo
        log_info "For support, create an issue at: $REPO_URL/issues"
    fi
}

# Uninstall function
uninstall() {
    log_step "Uninstalling VigileGuard..."
    
    # Remove executables
    rm -f "$BIN_DIR/vigileguard" "$BIN_DIR/vg"
    
    # Remove installation directory
    if [ -d "$INSTALL_DIR" ]; then
        rm -rf "$INSTALL_DIR"
        log_success "Removed installation directory"
    fi
    
    # Remove systemd service
    if [[ $EUID -eq 0 ]] && [ -f "/etc/systemd/system/vigileguard-scan.service" ]; then
        systemctl stop vigileguard-scan.timer 2>/dev/null || true
        systemctl disable vigileguard-scan.timer 2>/dev/null || true
        rm -f /etc/systemd/system/vigileguard-scan.service
        rm -f /etc/systemd/system/vigileguard-scan.timer
        systemctl daemon-reload
        log_success "Removed systemd service"
    fi
    
    log_warn "Configuration preserved at: $CONFIG_DIR"
    log_info "To remove config: rm -rf $CONFIG_DIR"
    log_success "VigileGuard uninstalled successfully"
}

# Update function
update() {
    log_step "Updating VigileGuard..."
    
    if [ ! -d "$INSTALL_DIR" ]; then
        log_error "VigileGuard not found. Run installation first."
        exit 1
    fi
    
    cd "$INSTALL_DIR"
    git pull origin main
    
    # Update dependencies
    if command -v pip3 &> /dev/null; then
        PIP_CMD="pip3"
    else
        PIP_CMD="pip"
    fi
    
    if [[ $EUID -eq 0 ]]; then
        $PIP_CMD install -r requirements.txt --upgrade
    else
        $PIP_CMD install --user -r requirements.txt --upgrade
    fi
    
    log_success "VigileGuard updated successfully"
}

# Main installation function
main() {
    trap cleanup EXIT
    
    show_banner
    echo "Installing VigileGuard - Your Vigilant Guardian for Linux Security"
    echo "Repository: $REPO_URL"
    echo
    
    check_root
    check_requirements
    install_from_source
    create_executable
    install_config
    update_path
    create_service
    
    if verify_installation; then
        show_usage
    else
        exit 1
    fi
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        show_banner
        echo "VigileGuard Installation Script"
        echo "Repository: $REPO_URL"
        echo
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --help, -h      Show this help message"
        echo "  --uninstall     Remove VigileGuard from system"
        echo "  --update        Update existing installation"
        echo "  --version       Show version information"
        echo
        echo "Installation:"
        echo "  curl -fsSL https://raw.githubusercontent.com/navinnm/VigileGuard/main/install.sh | bash"
        echo
        exit 0
        ;;
    --uninstall)
        show_banner
        echo "Uninstalling VigileGuard..."
        echo
        check_root
        uninstall
        ;;
    --update)
        show_banner
        echo "Updating VigileGuard..."
        echo
        check_root
        update
        ;;
    --version)
        echo "VigileGuard Installation Script v1.0.0"
        echo "Repository: $REPO_URL"
        exit 0
        ;;
    *)
        main
        ;;
esac