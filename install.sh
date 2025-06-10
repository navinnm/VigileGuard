#!/bin/bash
set -e

# SecurePulse Installation Script
# This script installs SecurePulse on Linux systems

REPO_URL="https://github.com/yourcompany/securepulse"
INSTALL_DIR="/opt/securepulse"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/securepulse"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        INSTALL_DIR="/opt/securepulse"
        BIN_DIR="/usr/local/bin"
        CONFIG_DIR="/etc/securepulse"
    else
        INSTALL_DIR="$HOME/.local/share/securepulse"
        BIN_DIR="$HOME/.local/bin"
        CONFIG_DIR="$HOME/.config/securepulse"
        log_warn "Installing as regular user to $INSTALL_DIR"
    fi
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."
    
    # Check Python version
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is required but not installed"
        exit 1
    fi
    
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    required_version="3.8"
    
    if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
        log_error "Python 3.8+ is required, found $python_version"
        exit 1
    fi
    
    log_success "Python $python_version found"
    
    # Check pip
    if ! command -v pip3 &> /dev/null && ! command -v pip &> /dev/null; then
        log_error "pip is required but not installed"
        exit 1
    fi
    
    # Check git
    if ! command -v git &> /dev/null; then
        log_error "git is required but not installed"
        exit 1
    fi
    
    log_success "All requirements satisfied"
}

# Install from PyPI
install_from_pypi() {
    log_info "Installing SecurePulse from PyPI..."
    
    if command -v pip3 &> /dev/null; then
        PIP_CMD="pip3"
    else
        PIP_CMD="pip"
    fi
    
    if [[ $EUID -eq 0 ]]; then
        $PIP_CMD install securepulse
    else
        $PIP_CMD install --user securepulse
    fi
    
    log_success "SecurePulse installed from PyPI"
}

# Install from source
install_from_source() {
    log_info "Installing SecurePulse from source..."
    
    # Create installation directory
    mkdir -p "$INSTALL_DIR"
    
    # Clone repository
    log_info "Cloning repository..."
    if [ -d "$INSTALL_DIR/.git" ]; then
        cd "$INSTALL_DIR"
        git pull
    else
        git clone "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi
    
    # Install dependencies
    log_info "Installing dependencies..."
    if command -v pip3 &> /dev/null; then
        PIP_CMD="pip3"
    else
        PIP_CMD="pip"
    fi
    
    if [[ $EUID -eq 0 ]]; then
        $PIP_CMD install -r requirements.txt
        $PIP_CMD install -e .
    else
        $PIP_CMD install --user -r requirements.txt
        $PIP_CMD install --user -e .
    fi
    
    log_success "SecurePulse installed from source"
}

# Create symlink
create_symlink() {
    log_info "Creating symlink..."
    
    # Find securepulse executable
    if [[ $EUID -eq 0 ]]; then
        SECUREPULSE_PATH=$(which securepulse 2>/dev/null || echo "/usr/local/bin/securepulse")
    else
        SECUREPULSE_PATH="$HOME/.local/bin/securepulse"
    fi
    
    # Create bin directory if it doesn't exist
    mkdir -p "$BIN_DIR"
    
    # Create symlink
    if [ -f "$SECUREPULSE_PATH" ]; then
        ln -sf "$SECUREPULSE_PATH" "$BIN_DIR/sp"
        log_success "Created symlink: sp -> $SECUREPULSE_PATH"
    fi
}

# Install configuration
install_config() {
    log_info "Installing default configuration..."
    
    mkdir -p "$CONFIG_DIR"
    
    # Create default config if it doesn't exist
    if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
        cat > "$CONFIG_DIR/config.yaml" << 'EOF'
# SecurePulse Default Configuration
output_format: "console"
severity_filter: "INFO"
excluded_checks: []
excluded_paths:
  - "/tmp"
  - "/var/tmp" 
  - "/proc"
  - "/sys"
EOF
        log_success "Created default configuration at $CONFIG_DIR/config.yaml"
    else
        log_info "Configuration already exists at $CONFIG_DIR/config.yaml"
    fi
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    if command -v securepulse &> /dev/null; then
        version=$(securepulse --version 2>/dev/null || echo "unknown")
        log_success "SecurePulse installed successfully: $version"
        
        # Test basic functionality
        log_info "Running basic functionality test..."
        if securepulse --help &> /dev/null; then
            log_success "Basic functionality test passed"
        else
            log_warn "Basic functionality test failed"
        fi
        
        return 0
    else
        log_error "SecurePulse command not found"
        return 1
    fi
}

# Cleanup function
cleanup() {
    if [ $? -ne 0 ]; then
        log_error "Installation failed"
        log_info "You can try manual installation:"
        log_info "1. git clone $REPO_URL"
        log_info "2. cd securepulse"
        log_info "3. pip install -r requirements.txt"
        log_info "4. pip install -e ."
    fi
}

# Main installation function
main() {
    trap cleanup EXIT
    
    echo "🔒 SecurePulse Installation Script"
    echo "================================="
    echo
    
    check_root
    check_requirements
    
    # Try PyPI first, fall back to source
    if install_from_pypi 2>/dev/null; then
        log_success "Installed from PyPI"
    else
        log_warn "PyPI installation failed, trying source installation"
        install_from_source
    fi
    
    create_symlink
    install_config
    
    if verify_installation; then
        echo
        log_success "🎉 SecurePulse installation completed!"
        echo
        echo "Usage:"
        echo "  securepulse              # Run basic audit"
        echo "  securepulse --help       # Show help"
        echo "  sp                       # Short alias"
        echo
        echo "Configuration:"
        echo "  $CONFIG_DIR/config.yaml"
        echo
        echo "Documentation:"
        echo "  https://github.com/yourcompany/securepulse"
        echo
    else
        exit 1
    fi
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "SecurePulse Installation Script"
        echo
        echo "Usage: $0 [options]"
        echo
        echo "Options:"
        echo "  --help, -h      Show this help message"
        echo "  --source        Force installation from source"
        echo "  --pypi          Force installation from PyPI"
        echo
        exit 0
        ;;
    --source)
        check_root
        check_requirements
        install_from_source
        create_symlink
        install_config
        verify_installation
        ;;
    --pypi)
        check_root
        check_requirements
        install_from_pypi
        create_symlink
        install_config
        verify_installation
        ;;
    *)
        main
        ;;
esac