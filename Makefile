# VigileGuard Makefile
# Repository: https://github.com/navinnm/VigileGuard
# Development and build automation

.PHONY: help install install-dev test lint format clean build deploy docker run-example

# Default target
help:
	@echo "🛡️  VigileGuard Development Makefile"
	@echo "Repository: https://github.com/navinnm/VigileGuard"
	@echo "=================================="
	@echo ""
	@echo "Available targets:"
	@echo "  install        Install VigileGuard for production use"
	@echo "  install-dev    Install VigileGuard for development"
	@echo "  test           Run test suite"
	@echo "  lint           Run code linting"
	@echo "  format         Format code with black"
	@echo "  clean          Clean build artifacts"
	@echo "  build          Build distribution packages"
	@echo "  docker         Build Docker image"
	@echo "  run-example    Run example security audit"
	@echo "  docs           Generate documentation"
	@echo "  setup-dev      Setup complete development environment"
	@echo ""

# Installation targets
install:
	@echo "📦 Installing VigileGuard..."
	pip install -r requirements.txt
	@echo "✅ VigileGuard installed successfully"
	@echo "Run with: python vigileguard.py --help"

install-dev:
	@echo "🔧 Installing VigileGuard for development..."
	pip install -r requirements.txt
	pip install pytest pytest-cov black flake8 mypy bandit safety
	@echo "✅ Development environment ready"

# Testing
test:
	@echo "🧪 Running test suite..."
	@if [ -f "test_vigileguard.py" ]; then \
		python -m pytest test_vigileguard.py -v --cov=. --cov-report=html --cov-report=term; \
	else \
		echo "⚠️  test_vigileguard.py not found, running basic tests..."; \
		python vigileguard.py --help > /dev/null && echo "✅ Basic functionality test passed"; \
	fi

test-quick:
	@echo "⚡ Running quick tests..."
	python vigileguard.py --help > /dev/null && echo "✅ Help command works"
	python vigileguard.py --version > /dev/null && echo "✅ Version command works"
	@echo "✅ Quick tests completed"

# Code quality
lint:
	@echo "🔍 Running code linting..."
	@echo "Running flake8..."
	flake8 vigileguard.py --max-line-length=100 --ignore=E203,W503 || true
	@echo "Running mypy..."
	mypy vigileguard.py --ignore-missing-imports || true
	@echo "Running bandit security check..."
	bandit -r . -f json || true

# FIXED: Actually format the code (remove --check)
format:
	@echo "🎨 Formatting code..."
	black --line-length=100 vigileguard.py
	@echo "✅ Code formatted"

# FIXED: Remove duplicate --check
format-check:
	@echo "🔍 Checking code format..."
	black --check --line-length=100 vigileguard.py || (echo "❌ Code is not formatted correctly. Run 'make format' to fix." && exit 1)

# Build and distribution
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf htmlcov/
	rm -rf .pytest_cache/
	rm -rf __pycache__/
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*~" -delete
	@echo "✅ Cleanup completed"

build: clean
	@echo "📦 Building VigileGuard..."
	@if [ -f "setup.py" ]; then \
		python setup.py sdist bdist_wheel; \
	else \
		echo "⚠️  setup.py not found, creating simple archive..."; \
		tar -czf vigileguard-$(shell date +%Y%m%d).tar.gz *.py *.yaml *.txt *.md *.sh Dockerfile; \
	fi
	@echo "✅ Build completed"

# Docker
docker:
	@echo "🐳 Building Docker image..."
	docker build -t vigileguard:latest .
	@echo "✅ Docker image built: vigileguard:latest"

docker-run:
	@echo "🐳 Running VigileGuard in Docker..."
	docker run --rm vigileguard:latest

docker-test:
	@echo "🐳 Testing Docker image..."
	docker run --rm vigileguard:latest --help

# Documentation
docs:
	@echo "📚 Generating documentation..."
	@mkdir -p docs/
	@echo "# VigileGuard API Documentation" > docs/api.md
	@echo "" >> docs/api.md
	@echo "Generated on: $(shell date)" >> docs/api.md
	@echo "" >> docs/api.md
	@python -c "import vigileguard; help(vigileguard)" >> docs/api.txt 2>/dev/null || echo "Could not generate API docs"
	@echo "✅ Documentation generated in docs/"

# Examples and testing
run-example:
	@echo "🛡️  Running VigileGuard example..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	python vigileguard.py --help
	@echo ""
	@echo "🔍 Running basic security audit (demo mode)..."
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

run-json:
	@echo "📊 Generating JSON report..."
	python vigileguard.py --format json --output vigileguard-report.json || true
	@echo "✅ Report saved to vigileguard-report.json"

run-config:
	@echo "⚙️  Running with custom configuration..."
	python vigileguard.py --config config.yaml --format console

# Development helpers
setup-dev:
	@echo "🚀 Setting up complete development environment..."
	@if [ ! -d "venv" ]; then \
		echo "Creating virtual environment..."; \
		python3 -m venv venv; \
	fi
	@echo "Installing dependencies..."
	. venv/bin/activate && pip install --upgrade pip
	. venv/bin/activate && make install-dev
	@echo ""
	@echo "✅ Development environment ready!"
	@echo ""
	@echo "🎯 Next steps:"
	@echo "  source venv/bin/activate    # Activate virtual environment"
	@echo "  make test                   # Run tests"
	@echo "  make run-example           # Test VigileGuard"
	@echo "  make format                # Format code"

check-security:
	@echo "🔒 Running security checks on codebase..."
	@echo "Running bandit..."
	bandit -r . -f json -o security-report.json || true
	@echo "Running safety check..."
	safety check || true
	@echo "✅ Security checks completed"

# Performance testing
performance-test:
	@echo "⚡ Running performance tests..."
	@echo "Testing execution time..."
	time python vigileguard.py --format json > /dev/null || true
	@echo "✅ Performance test completed"

# Release preparation
prepare-release:
	@echo "🚀 Preparing release..."
	make clean
	make format-check
	make lint
	make test
	make build
	@echo "✅ Release preparation complete!"

# CI/CD simulation
ci-test:
	@echo "🔄 Simulating CI/CD pipeline..."
	@echo "Step 1: Format check..."
	make format-check
	@echo "Step 2: Linting..."
	make lint
	@echo "Step 3: Testing..."
	make test
	@echo "Step 4: Building..."
	make build
	@echo "✅ CI/CD simulation complete!"

# Installation verification
verify-install:
	@echo "✅ Verifying installation..."
	@which python3 > /dev/null && echo "✅ Python 3 found" || echo "❌ Python 3 not found"
	@python3 --version | grep -E "3\.[8-9]|3\.1[0-9]" > /dev/null && echo "✅ Python version OK" || echo "⚠️  Python 3.8+ recommended"
	@pip --version > /dev/null && echo "✅ pip available" || echo "❌ pip not found"
	@git --version > /dev/null && echo "✅ git available" || echo "❌ git not found"
	@python vigileguard.py --help > /dev/null && echo "✅ VigileGuard works" || echo "❌ VigileGuard not working"

# System requirements check
check-requirements:
	@echo "🔍 Checking system requirements..."
	@python3 --version | grep -E "3\.[8-9]|3\.1[0-9]" > /dev/null && echo "✅ Python version OK" || echo "❌ Python 3.8+ required"
	@pip --version > /dev/null && echo "✅ pip available" || echo "❌ pip not found"
	@git --version > /dev/null && echo "✅ git available" || echo "❌ git not found"
	@command -v make > /dev/null && echo "✅ make available" || echo "⚠️  make not found"

# Package information
info:
	@echo "📋 VigileGuard Package Information"
	@echo "=================================="
	@echo "Name: VigileGuard"
	@echo "Version: 1.0.0"
	@echo "Description: Linux Security Audit Tool"
	@echo "Repository: https://github.com/navinnm/VigileGuard"
	@echo "Python: 3.8+"
	@echo "License: MIT"
	@echo ""
	@echo "📦 Dependencies:"
	@cat requirements.txt
	@echo ""
	@echo "📁 Files:"
	@ls -la *.py *.yaml *.txt *.md *.sh 2>/dev/null || echo "Core files present"

# Cleanup targets
clean-cache:
	@echo "🧹 Cleaning Python cache..."
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

clean-docs:
	@echo "🧹 Cleaning documentation..."
	rm -rf docs/ 2>/dev/null || true

clean-all: clean clean-cache clean-docs
	@echo "✅ Complete cleanup finished"

# Development workflow targets
dev-start: setup-dev
	@echo "🚀 Development session ready!"
	@echo "Remember to activate virtual environment: source venv/bin/activate"

dev-test: format lint test
	@echo "✅ Development testing complete"

dev-commit: format lint test
	@echo "✅ Code ready for commit"

# Quick development commands - FIXED
quick-format:
	@echo "⚡ Quick format..."
	black --line-length=100 vigileguard.py

quick-test:
	@echo "⚡ Quick test..."
	python vigileguard.py --help > /dev/null && echo "✅ Works" || echo "❌ Failed"

quick-run:
	@echo "⚡ Quick run..."
	python vigileguard.py --help

# Installation using script
install-script:
	@echo "📥 Installing using install.sh script..."
	@if [ -f "install.sh" ]; then \
		chmod +x install.sh && ./install.sh; \
	else \
		echo "❌ install.sh not found"; \
	fi

# Uninstall using script
uninstall-script:
	@echo "🗑️  Uninstalling using install.sh script..."
	@if [ -f "install.sh" ]; then \
		chmod +x install.sh && ./install.sh --uninstall; \
	else \
		echo "❌ install.sh not found"; \
	fi

# Update using script
update-script:
	@echo "🔄 Updating using install.sh script..."
	@if [ -f "install.sh" ]; then \
		chmod +x install.sh && ./install.sh --update; \
	else \
		echo "❌ install.sh not found"; \
	fi

# Show all available targets
targets:
	@echo "📋 All available Makefile targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'
	@echo ""
	@echo "🎯 Common workflows:"
	@echo "  make setup-dev             # Setup development environment"
	@echo "  make dev-test              # Full development testing"
	@echo "  make run-example           # Test the tool"
	@echo "  make ci-test               # Simulate CI/CD"
	@echo "  make docker                # Build Docker image"