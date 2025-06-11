# Dockerfile.dev - Development version with additional tools

FROM python:3.11-slim

# Set environment variables for development
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# Create development user
RUN groupadd -g 1000 vigileguard && \
    useradd -m -u 1000 -g 1000 -s /bin/bash vigileguard

# Install system dependencies + development tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    # System tools
    git \
    curl \
    wget \
    procps \
    net-tools \
    openssh-client \
    findutils \
    grep \
    coreutils \
    vim \
    nano \
    less \
    # Development tools
    build-essential \
    gcc \
    g++ \
    make \
    # Network tools for testing
    nmap \
    netcat-openbsd \
    telnet \
    # Additional utilities
    tree \
    htop \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Copy package files
COPY requirements.txt .
COPY pyproject.toml .
COPY setup.py .
COPY README.md .

# Install Python dependencies + development tools
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir \
    # Development dependencies
    pytest \
    pytest-cov \
    black \
    flake8 \
    mypy \
    bandit \
    safety \
    # Interactive tools
    ipython \
    jupyter \
    # Documentation tools
    sphinx \
    mkdocs

# Copy source code (this will be overridden by volume in dev)
COPY vigileguard/ ./vigileguard/
COPY scripts/ ./scripts/
COPY tests/ ./tests/
COPY examples/ ./examples/

# Install VigileGuard in development mode
RUN pip install --no-cache-dir -e ".[dev,full]"

# Create necessary directories
RUN mkdir -p /app/reports /app/logs /app/temp && \
    chown -R vigileguard:vigileguard /app

# Switch to development user
USER vigileguard

# Set up development environment
RUN echo 'alias ll="ls -la"' >> ~/.bashrc && \
    echo 'alias la="ls -la"' >> ~/.bashrc && \
    echo 'alias ..="cd .."' >> ~/.bashrc && \
    echo 'export PS1="\[\033[01;32m\]\u@vigileguard-dev\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "' >> ~/.bashrc

# Verify installation
RUN python -c "import vigileguard; print(f'✅ VigileGuard {vigileguard.__version__} (dev) installed')" && \
    vigileguard --version && \
    echo "Development environment ready! 🚀"

# Development entry point
ENTRYPOINT ["/bin/bash", "-c"]
CMD ["echo 'VigileGuard Development Environment' && echo 'Available commands:' && echo '  vigileguard --help' && echo '  pytest tests/' && echo '  black vigileguard/' && echo '  flake8 vigileguard/' && echo '' && echo 'Starting interactive shell...' && /bin/bash"]

# Add development labels
LABEL org.opencontainers.image.title="VigileGuard Development" \
      org.opencontainers.image.description="VigileGuard Development Environment" \
      org.opencontainers.image.version="2.0.0-dev" \
      org.opencontainers.image.source="https://github.com/navinnm/VigileGuard" \
      environment="development"