# SecurePulse Makefile
# Development and build automation

.PHONY: help install install-dev test lint format clean build deploy docker run-example

# Default target
help:
	@echo "SecurePulse Development Makefile"
	@echo "================================"
	@echo ""
	@echo "Available targets:"
	@echo "  install        Install SecurePulse for production use"
	@echo "  install-dev    Install SecurePulse for development"
	@echo "  test           Run test suite"
	@echo "  lint           Run code linting"
	@echo "  format         Format code with black"
	@echo "  clean          Clean build artifacts"
	@echo "  build          Build distribution packages"
	@echo "  deploy         Deploy to PyPI (requires credentials)"
	@echo "  docker         Build Docker image"
	@echo "  run-example    Run example security audit"
	@echo "  docs           Generate documentation"
	@echo ""

# Installation targets
install:
	@echo "Installing SecurePulse..."
	pip install -r requirements.txt
	pip install -e .

install-dev:
	@echo "Installing SecurePulse for development..."
	pip install -r requirements.txt
	pip install -e ".[dev]"
	pip install pytest pytest-cov black flake8 mypy

# Testing
test:
	@echo "Running test suite..."
	python -m pytest tests/ -v --cov=securepulse --cov-report=html --cov-report=term

test-quick:
	@echo "Running quick tests..."
	python test_example.py

# Code quality
lint:
	@echo "Running linting..."
	flake8 securepulse/ --max-line-length=100 --ignore=E203,W503
	mypy securepulse/ --ignore-missing-imports

format:
	@echo "Formatting code..."
	black securepulse/ tests/ --line-length=100

format-check:
	@echo "Checking code format..."
	black securepulse/ tests/ --check --line-length=100

# Build and distribution
clean:
	@echo "Cleaning build artifacts..."
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

build: clean
	@echo "Building distribution packages..."
	python setup.py sdist bdist_wheel

deploy: build
	@echo "Deploying to PyPI..."
	twine upload dist/*

deploy-test: build
	@echo "Deploying to Test PyPI..."
	twine upload --repository testpypi dist/*

# Docker
docker:
	@echo "Building Docker image..."
	docker build -t securepulse:latest .

docker-run:
	@echo "Running SecurePulse in Docker..."
	docker run --rm -it securepulse:latest

# Documentation
docs:
	@echo "Generating documentation..."
	mkdir -p docs/
	python -c "import securepulse; help(securepulse)" > docs/api.txt
	@echo "Documentation generated in docs/"

# Examples and testing
run-example:
	@echo "Running example security audit..."
	python -m securepulse --help
	@echo ""
	@echo "Running basic audit (dry run)..."
	python -m securepulse --format json | head -20

run-demo:
	@echo "Running demonstration audit..."
	python -m securepulse --config config.yaml --format console

# Development helpers
setup-dev:
	@echo "Setting up development environment..."
	python -m venv venv
	. venv/bin/activate && pip install --upgrade pip
	. venv/bin/activate && make install-dev
	@echo "Development environment ready!"
	@echo "Activate with: source venv/bin/activate"

check-security:
	@echo "Running security checks on codebase..."
	pip install bandit safety
	bandit -r securepulse/
	safety check

performance-test:
	@echo "Running performance tests..."
	time python -m securepulse --format json > /dev/null

# Release preparation
prepare-release:
	@echo "Preparing release..."
	make clean
	make format
	make lint
	make test
	make build
	@echo "Release preparation complete!"

# CI/CD simulation
ci-test:
	@echo "Simulating CI/CD pipeline..."
	make format-check
	make lint
	make test
	make build
	@echo "CI/CD simulation complete!"

# Installation verification
verify-install:
	@echo "Verifying installation..."
	which securepulse || echo "securepulse not in PATH"
	securepulse --version
	securepulse --help > /dev/null && echo "✅ Help command works"
	python -c "import securepulse; print('✅ Python module imports successfully')"

# System requirements check
check-requirements:
	@echo "Checking system requirements..."
	python --version | grep -E "3\.[8-9]|3\.1[0-9]" && echo "✅ Python version OK" || echo "❌ Python 3.8+ required"
	pip --version > /dev/null && echo "✅ pip available" || echo "❌ pip not found"
	git --version > /dev/null && echo "✅ git available" || echo "❌ git not found"

# Package information
info:
	@echo "Package Information"
	@echo "==================="
	@echo "Name: SecurePulse"
	@echo "Version: 1.0.0"
	@echo "Description: Linux Security Audit Tool"
	@echo "Python: 3.8+"
	@echo "License: MIT"
	@echo ""
	@echo "Dependencies:"
	@cat requirements.txt

# Cleanup targets
clean-cache:
	@echo "Cleaning Python cache..."
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

clean-docs:
	@echo "Cleaning documentation..."
	rm -rf docs/

clean-all: clean clean-cache clean-docs
	@echo "Complete cleanup finished"

# Development workflow targets
dev-start: setup-dev
	@echo "Starting development session..."
	@echo "Remember to activate virtual environment: source venv/bin/activate"

dev-test: format lint test
	@echo "Development testing complete"

dev-commit: format lint test
	@echo "Code ready for commit"

# Quick development commands
quick-format:
	black securepulse/main.py --line-length=100

quick-test:
	python test_example.py -v

quick-run:
	python securepulse/main.py --help