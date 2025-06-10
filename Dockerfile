# SecurePulse Docker Image
# Lightweight container for running security audits

FROM python:3.11-slim

# Metadata
LABEL maintainer="SecurePulse Team <security@yourcompany.com>"
LABEL description="SecurePulse - Linux Security Audit Tool"
LABEL version="1.0.0"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    sudo \
    procps \
    net-tools \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -s /bin/bash securepulse && \
    echo "securepulse ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

# Set working directory
WORKDIR /app

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install SecurePulse
RUN pip install -e .

# Create config directory
RUN mkdir -p /etc/securepulse && \
    cp config.yaml /etc/securepulse/ && \
    chown -R securepulse:securepulse /etc/securepulse

# Switch to non-root user
USER securepulse

# Set environment variables
ENV PYTHONPATH=/app
ENV SECUREPULSE_CONFIG=/etc/securepulse/config.yaml

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD securepulse --help > /dev/null || exit 1

# Default command
ENTRYPOINT ["securepulse"]
CMD ["--help"]

# Build instructions:
# docker build -t securepulse:latest .
# 
# Usage examples:
# docker run --rm securepulse:latest
# docker run --rm -v /host/path:/data securepulse:latest --output /data/report.json --format json
# docker run --rm -it securepulse:latest --config /etc/securepulse/config.yaml