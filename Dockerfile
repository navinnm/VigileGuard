# VigileGuard Docker Image
# Repository: https://github.com/navinnm/VigileGuard
# Lightweight container for running security audits

FROM python:3.11-slim

# Metadata
LABEL maintainer="VigileGuard Team <https://github.com/navinnm/VigileGuard>"
LABEL description="VigileGuard - Linux Security Audit Tool"
LABEL version="1.0.0"
LABEL repository="https://github.com/navinnm/VigileGuard"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    sudo \
    procps \
    net-tools \
    openssh-client \
    findutils \
    grep \
    coreutils \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -s /bin/bash vigileguard && \
    echo "vigileguard ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY vigileguard.py .
COPY config.yaml .

# Create config directory and copy config
RUN mkdir -p /etc/vigileguard && \
    cp config.yaml /etc/vigileguard/ && \
    chown -R vigileguard:vigileguard /etc/vigileguard

# Create a simple wrapper script
RUN echo '#!/bin/bash\npython /app/vigileguard.py "$@"' > /usr/local/bin/vigileguard && \
    chmod +x /usr/local/bin/vigileguard

# Switch to non-root user
USER vigileguard

# Set environment variables
ENV PYTHONPATH=/app
ENV VIGILEGUARD_CONFIG=/etc/vigileguard/config.yaml

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD vigileguard --help > /dev/null || exit 1

# Default command
ENTRYPOINT ["vigileguard"]
CMD ["--help"]

# Build and usage instructions:
#
# Build the image:
#   docker build -t vigileguard:latest .
#
# Basic usage:
#   docker run --rm vigileguard:latest
#   docker run --rm vigileguard:latest --format json
#
# Mount host filesystem for scanning:
#   docker run --rm -v /:/host:ro vigileguard:latest --config /etc/vigileguard/config.yaml
#
# Save report to host:
#   docker run --rm -v $(pwd):/output vigileguard:latest --format json --output /output/report.json
#
# Interactive mode:
#   docker run --rm -it vigileguard:latest /bin/bash
#
# Custom configuration:
#   docker run --rm -v $(pwd)/custom-config.yaml:/etc/vigileguard/config.yaml vigileguard:latest