# VigileGuard Makefile
# Provides easy commands for development, testing, and deployment

.PHONY: help install install-dev clean test test-all lint format security build package deploy docs run run-phase2 docker

# Default target
help:
	@echo "🛡️ VigileGuard Development Commands"
	@echo "=================================="
	@echo ""
	@echo "Setup & Installation:"
	@echo "  install      Install VigileGuard in current environment"
	@echo "  install-dev  Install VigileGuard with development dependencies"
	@echo "  clean        Clean build artifacts and cache files"
	@echo ""
	@echo "Development:"
	@echo "  test         Run unit tests"
	@echo "  test-all     Run all tests including integration tests"
	@echo "  lint         Run code linting (flake8, mypy)"
	@echo "  format       Format code with black"
	@echo "  security     Run security scans (bandit, safety)"
	@echo ""
	@echo "Building & Packaging:"
	@echo "  build        Build source and wheel distributions"
	@echo "  package      Create distribution packages"
	@echo "  deploy       Deploy to PyPI (requires credentials)"
	@echo ""
	@echo "Running:"
	@echo "  run          Run VigileGuard Phase 1"
	@echo "  run-phase2   Run VigileGuard Phase 2"
	@echo "  run-html     Generate HTML report"
	@echo "  run-all      Generate all report formats"
	@echo ""
	@echo "Docker:"
	@echo "  docker       Build and run VigileGuard in Docker"
	@echo "  docker-build Build Docker image"
	@echo "  docker-run   Run VigileGuard in Docker container"
	@echo ""
	@echo "Documentation:"
	@echo "  docs         Generate documentation"

# Variables
PYTHON := python3
PIP := pip3
PACKAGE_NAME := vigileguard
VERSION := $(shell $(PYTHON) -c "import vigileguard; print(vigileguard.__version__)" 2>/dev/null || echo "3.0.4")

# Setup & Installation
install:
	@echo "📦 Installing VigileGuard..."
	$(PIP) install -e .
	@echo "✅ Installation complete!"

install-dev:
	@echo "📦 Installing VigileGuard with development dependencies..."
	$(PIP) install -e ".[dev,full]"
	@echo "✅ Development installation complete!"

clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	rm -rf .mypy_cache/
	rm -rf .tox/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	@echo "✅ Cleanup complete!"

# Development
test:
	@echo "🧪 Running unit tests..."
	pytest tests/ -v --tb=short
	@echo "✅ Tests complete!"

test-all:
	@echo "🧪 Running all tests..."
	pytest tests/ -v --tb=short --cov=$(PACKAGE_NAME) --cov-report=html --cov-report=term-missing
	@echo "✅ All tests complete!"

lint:
	@echo "🔍 Running code linting..."
	@echo "Running flake8..."
	flake8 $(PACKAGE_NAME)/ tests/
	@echo "Running mypy..."
	mypy $(PACKAGE_NAME)/
	@echo "✅ Linting complete!"

format:
	@echo "🎨 Formatting code with black..."
	black $(PACKAGE_NAME)/ tests/ scripts/
	@echo "✅ Formatting complete!"

security:
	@echo "🔒 Running security scans..."
	@echo "Running bandit..."
	bandit -r $(PACKAGE_NAME)/ -f json -o bandit-report.json || true
	@echo "Running safety check..."
	safety check --json --output safety-report.json || true
	@echo "✅ Security scans complete!"

# Building & Packaging
build: clean
	@echo "🏗️ Building distribution packages..."
	$(PYTHON) -m build
	@echo "✅ Build complete!"

package: build
	@echo "📦 Creating distribution packages..."
	@echo "Package version: $(VERSION)"
	@echo "Source distribution: dist/$(PACKAGE_NAME)-$(VERSION).tar.gz"
	@echo "Wheel distribution: dist/$(PACKAGE_NAME)-$(VERSION)-py3-none-any.whl"
	@echo "✅ Packaging complete!"

deploy: package
	@echo "🚀 Deploying to PyPI..."
	@echo "⚠️  Make sure you have proper credentials configured!"
	@read -p "Deploy to PyPI? [y/N] " confirm && [ "$$confirm" = "y" ]
	twine upload dist/*
	@echo "✅ Deployment complete!"

# Running
run:
	@echo "🛡️ Running VigileGuard Phase 1..."
	$(PYTHON) -m $(PACKAGE_NAME).vigileguard --format console

run-phase2:
	@echo "🛡️ Running VigileGuard Phase 2..."
	$(PYTHON) -m $(PACKAGE_NAME).phase2_integration --format console

run-html:
	@echo "🛡️ Generating HTML report..."
	mkdir -p reports
	$(PYTHON) -m $(PACKAGE_NAME).vigileguard --format html --output reports/vigileguard-report.html
	@echo "✅ HTML report generated: reports/vigileguard-report.html"

run-json:
	@echo "🛡️ Generating JSON report..."
	mkdir -p reports
	$(PYTHON) -m $(PACKAGE_NAME).vigileguard --format json --output reports/vigileguard-report.json
	@echo "✅ JSON report generated: reports/vigileguard-report.json"

run-all:
	@echo "🛡️ Generating all report formats..."
	mkdir -p reports
	$(PYTHON) -m $(PACKAGE_NAME).vigileguard --format all --output reports/
	@echo "✅ All reports generated in reports/ directory"

# Docker
docker: docker-build docker-run

docker-build:
	@echo "🐳 Building Docker image..."
	docker build -t $(PACKAGE_NAME):latest .
	docker build -t $(PACKAGE_NAME):$(VERSION) .
	@echo "✅ Docker image built!"

docker-run:
	@echo "🐳 Running VigileGuard in Docker..."
	docker run --rm -v $(PWD)/reports:/app/reports $(PACKAGE_NAME):latest --format html --output /app/reports/docker-report.html
	@echo "✅ Docker run complete!"

docker-shell:
	@echo "🐳 Opening shell in VigileGuard container..."
	docker run --rm -it -v $(PWD)/reports:/app/reports $(PACKAGE_NAME):latest /bin/bash

# Documentation
docs:
	@echo "📚 Generating documentation..."
	@echo "TODO: Add documentation generation (Sphinx, MkDocs, etc.)"
	@echo "For now, see README.md and docs/ directory"

# Utility targets
check-deps:
	@echo "🔍 Checking dependencies..."
	$(PIP) check
	@echo "✅ Dependencies OK!"

version:
	@echo "VigileGuard version: $(VERSION)"

info:
	@echo "🛡️ VigileGuard Project Information"
	@echo "================================"
	@echo "Package: $(PACKAGE_NAME)"
	@echo "Version: $(VERSION)"
	@echo "Python: $(shell $(PYTHON) --version)"
	@echo "Pip: $(shell $(PIP) --version)"
	@echo "Current directory: $(PWD)"
	@echo ""
	@echo "Files in current directory:"
	@ls -la

# Development workflow shortcuts
dev-setup: install-dev
	@echo "🔧 Development environment setup complete!"
	@echo "You can now run: make test, make lint, make run"

dev-check: format lint test security
	@echo "✅ All development checks passed!"

release-check: dev-check build
	@echo "✅ Release checks passed! Ready to deploy."

# Continuous Integration shortcuts
ci: clean install-dev test-all lint security
	@echo "✅ CI pipeline complete!"

# Quick commands for common tasks
quick-test:
	@pytest tests/ -x -v

quick-scan:
	@$(PYTHON) -m $(PACKAGE_NAME).vigileguard --format console | head -20

# Help for specific targets
help-install:
	@echo "Installation Help:"
	@echo "=================="
	@echo ""
	@echo "make install      - Install VigileGuard in current environment"
	@echo "make install-dev  - Install with development dependencies"
	@echo ""
	@echo "For system-wide installation:"
	@echo "  sudo make install"
	@echo ""
	@echo "For virtual environment:"
	@echo "  python -m venv venv"
	@echo "  source venv/bin/activate"
	@echo "  make install"

help-docker:
	@echo "Docker Help:"
	@echo "============"
	@echo ""
	@echo "make docker-build - Build VigileGuard Docker image"
	@echo "make docker-run   - Run VigileGuard in container"
	@echo "make docker-shell - Open interactive shell in container"
	@echo ""
	@echo "Manual Docker commands:"
	@echo "  docker run --rm vigileguard:latest --help"
	@echo "  docker run --rm -v \$(pwd)/reports:/app/reports vigileguard:latest --format html"