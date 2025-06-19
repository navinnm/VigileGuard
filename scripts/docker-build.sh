#!/bin/bash
# scripts/docker-build.sh - Build VigileGuard Docker images

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Configuration
IMAGE_NAME="vigileguard"
VERSION=$(python -c "import vigileguard; print(vigileguard.__version__)" 2>/dev/null || echo "3.0.0")
BUILD_PRODUCTION=true
BUILD_DEVELOPMENT=false
PUSH_TO_REGISTRY=false
REGISTRY=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dev|--development)
            BUILD_DEVELOPMENT=true
            shift
            ;;
        --prod|--production)
            BUILD_PRODUCTION=true
            shift
            ;;
        --push)
            PUSH_TO_REGISTRY=true
            shift
            ;;
        --registry)
            REGISTRY="$2"
            shift 2
            ;;
        --version)
            VERSION="$2"
            shift 2
            ;;
        --help|-h)
            echo "VigileGuard Docker Build Script"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --dev, --development    Build development image"
            echo "  --prod, --production    Build production image (default)"
            echo "  --push                  Push images to registry after build"
            echo "  --registry REGISTRY     Docker registry to use"
            echo "  --version VERSION       Version tag for images"
            echo "  --help, -h              Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0                      # Build production image"
            echo "  $0 --dev               # Build development image"
            echo "  $0 --push --registry ghcr.io/navinnm  # Build and push to GitHub Container Registry"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Set registry prefix if provided
if [[ -n "$REGISTRY" ]]; then
    IMAGE_PREFIX="$REGISTRY/"
else
    IMAGE_PREFIX=""
fi

print_status "Building VigileGuard Docker images..."
print_status "Version: $VERSION"
print_status "Registry: ${REGISTRY:-'local'}"

# Build production image
if [[ "$BUILD_PRODUCTION" == "true" ]]; then
    print_status "Building production image..."
    
    docker build \
        -t "${IMAGE_PREFIX}${IMAGE_NAME}:latest" \
        -t "${IMAGE_PREFIX}${IMAGE_NAME}:${VERSION}" \
        -t "${IMAGE_PREFIX}${IMAGE_NAME}:production" \
        -f Dockerfile \
        --label "org.opencontainers.image.version=${VERSION}" \
        --label "org.opencontainers.image.created=$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        .
    
    print_success "Production image built successfully"
    
    # Push production images if requested
    if [[ "$PUSH_TO_REGISTRY" == "true" && -n "$REGISTRY" ]]; then
        print_status "Pushing production images to registry..."
        docker push "${IMAGE_PREFIX}${IMAGE_NAME}:latest"
        docker push "${IMAGE_PREFIX}${IMAGE_NAME}:${VERSION}"
        docker push "${IMAGE_PREFIX}${IMAGE_NAME}:production"
        print_success "Production images pushed to registry"
    fi
fi

# Build development image
if [[ "$BUILD_DEVELOPMENT" == "true" ]]; then
    print_status "Building development image..."
    
    docker build \
        -t "${IMAGE_PREFIX}${IMAGE_NAME}:dev" \
        -t "${IMAGE_PREFIX}${IMAGE_NAME}:${VERSION}-dev" \
        -t "${IMAGE_PREFIX}${IMAGE_NAME}:development" \
        -f Dockerfile.dev \
        --label "org.opencontainers.image.version=${VERSION}-dev" \
        --label "org.opencontainers.image.created=$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
        --label "environment=development" \
        .
    
    print_success "Development image built successfully"
    
    # Push development images if requested
    if [[ "$PUSH_TO_REGISTRY" == "true" && -n "$REGISTRY" ]]; then
        print_status "Pushing development images to registry..."
        docker push "${IMAGE_PREFIX}${IMAGE_NAME}:dev"
        docker push "${IMAGE_PREFIX}${IMAGE_NAME}:${VERSION}-dev"
        docker push "${IMAGE_PREFIX}${IMAGE_NAME}:development"
        print_success "Development images pushed to registry"
    fi
fi

# Display built images
print_status "Built images:"
docker images | grep "$IMAGE_NAME" | head -10

print_success "Docker build completed successfully! 🐳"

echo ""
echo "Quick Start Commands:"
echo "  # Run production container"
echo "  docker run --rm -v \$(pwd)/reports:/app/reports ${IMAGE_PREFIX}${IMAGE_NAME}:latest --format html"
echo ""
echo "  # Run development container"
if [[ "$BUILD_DEVELOPMENT" == "true" ]]; then
    echo "  docker run --rm -it -v \$(pwd):/app ${IMAGE_PREFIX}${IMAGE_NAME}:dev"
fi
echo ""
echo "  # Use docker-compose"
echo "  docker-compose up vigileguard"

---

#!/bin/bash
# scripts/docker-run.sh - Run VigileGuard in Docker with various configurations

set -e

# Default configuration
IMAGE_NAME="vigileguard:latest"
OUTPUT_FORMAT="html"
OUTPUT_FILE="security-report"
CONFIG_FILE="config.yaml"
REPORTS_DIR="./reports"
RUN_MODE="scan"
INTERACTIVE=false
DEVELOPMENT=false

# Helper functions
show_usage() {
    cat << EOF
VigileGuard Docker Runner

Usage: $0 [OPTIONS]

Scan Options:
  --format FORMAT         Output format (console, json, html, all) [default: html]
  --output FILE          Output file name (without extension) [default: security-report]
  --config FILE          Configuration file [default: config.yaml]
  --reports-dir DIR      Reports directory [default: ./reports]

Run Modes:
  --scan                 Run security scan (default)
  --shell                Open interactive shell
  --dev                  Use development image with interactive shell
  --test                 Run test suite

Docker Options:
  --image IMAGE          Docker image to use [default: vigileguard:latest]
  --interactive, -i      Run in interactive mode
  --remove-after         Remove container after execution (default)

Examples:
  $0                           # Basic HTML scan
  $0 --format json             # JSON scan
  $0 --format all              # All formats
  $0 --shell                   # Interactive shell
  $0 --dev                     # Development environment
  $0 --test                    # Run tests

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --reports-dir)
            REPORTS_DIR="$2"
            shift 2
            ;;
        --image)
            IMAGE_NAME="$2"
            shift 2
            ;;
        --scan)
            RUN_MODE="scan"
            shift
            ;;
        --shell)
            RUN_MODE="shell"
            INTERACTIVE=true
            shift
            ;;
        --dev)
            RUN_MODE="dev"
            IMAGE_NAME="vigileguard:dev"
            INTERACTIVE=true
            shift
            ;;
        --test)
            RUN_MODE="test"
            shift
            ;;
        --interactive|-i)
            INTERACTIVE=true
            shift
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Create reports directory
mkdir -p "$REPORTS_DIR"

# Prepare Docker run command
DOCKER_CMD="docker run --rm"

# Add interactive flags if needed
if [[ "$INTERACTIVE" == "true" ]]; then
    DOCKER_CMD="$DOCKER_CMD -it"
fi

# Add volume mounts
DOCKER_CMD="$DOCKER_CMD -v $(pwd)/$REPORTS_DIR:/app/reports"

# Add config file if it exists
if [[ -f "$CONFIG_FILE" ]]; then
    DOCKER_CMD="$DOCKER_CMD -v $(pwd)/$CONFIG_FILE:/app/config.yaml:ro"
fi

# Add development volume mount if in dev mode
if [[ "$RUN_MODE" == "dev" ]]; then
    DOCKER_CMD="$DOCKER_CMD -v $(pwd):/app"
fi

# Set container name
DOCKER_CMD="$DOCKER_CMD --name vigileguard-runner-$$"

# Add image
DOCKER_CMD="$DOCKER_CMD $IMAGE_NAME"

# Execute based on run mode
case $RUN_MODE in
    "scan")
        echo "🛡️ Running VigileGuard security scan..."
        echo "Format: $OUTPUT_FORMAT"
        echo "Output: $REPORTS_DIR/$OUTPUT_FILE.*"
        
        if [[ "$OUTPUT_FORMAT" == "all" ]]; then
            $DOCKER_CMD --format all --output /app/reports/
        else
            OUTPUT_EXT=""
            case $OUTPUT_FORMAT in
                "html") OUTPUT_EXT=".html" ;;
                "json") OUTPUT_EXT=".json" ;;
                "console") OUTPUT_EXT="" ;;
            esac
            
            if [[ "$OUTPUT_FORMAT" == "console" ]]; then
                $DOCKER_CMD --format console
            else
                $DOCKER_CMD --format "$OUTPUT_FORMAT" --output "/app/reports/$OUTPUT_FILE$OUTPUT_EXT"
            fi
        fi
        ;;
        
    "shell")
        echo "🐚 Opening interactive shell in VigileGuard container..."
        $DOCKER_CMD /bin/bash
        ;;
        
    "dev")
        echo "🚀 Starting VigileGuard development environment..."
        $DOCKER_CMD
        ;;
        
    "test")
        echo "🧪 Running VigileGuard test suite..."
        $DOCKER_CMD pytest tests/ -v
        ;;
        
    *)
        echo "Unknown run mode: $RUN_MODE"
        exit 1
        ;;
esac

echo "✅ VigileGuard Docker run completed!"

---

#!/bin/bash
# scripts/cron-entrypoint.sh - Entrypoint for scheduled VigileGuard scans

set -e

# Configuration
SCAN_INTERVAL=${SCAN_INTERVAL:-3600}  # Default: 1 hour
OUTPUT_FORMAT=${OUTPUT_FORMAT:-json}
REPORTS_DIR="/app/reports"
CONFIG_FILE="/app/config.yaml"

# Helper functions
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

cleanup_old_reports() {
    log "Cleaning up old reports (keeping last 30 days)..."
    find "$REPORTS_DIR" -name "*.json" -mtime +30 -delete 2>/dev/null || true
    find "$REPORTS_DIR" -name "*.html" -mtime +30 -delete 2>/dev/null || true
}

run_scan() {
    local timestamp=$(date +'%Y%m%d_%H%M%S')
    local output_file="$REPORTS_DIR/vigileguard_${timestamp}"
    
    log "Starting VigileGuard security scan..."
    log "Output format: $OUTPUT_FORMAT"
    log "Output file: $output_file"
    
    if [[ -f "$CONFIG_FILE" ]]; then
        vigileguard --config "$CONFIG_FILE" --format "$OUTPUT_FORMAT" --output "$output_file"
    else
        vigileguard --format "$OUTPUT_FORMAT" --output "$output_file"
    fi
    
    log "Security scan completed successfully"
}

# Main loop
log "VigileGuard scheduled scanner starting..."
log "Scan interval: $SCAN_INTERVAL seconds"
log "Output format: $OUTPUT_FORMAT"
log "Reports directory: $REPORTS_DIR"

# Ensure reports directory exists
mkdir -p "$REPORTS_DIR"

# Run initial scan
run_scan

# Schedule subsequent scans
while true; do
    log "Waiting $SCAN_INTERVAL seconds until next scan..."
    sleep "$SCAN_INTERVAL"
    
    # Cleanup old reports before new scan
    cleanup_old_reports
    
    # Run scheduled scan
    run_scan
done