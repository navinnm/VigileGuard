# VigileGuard Docker Image - Working Version
# Repository: https://github.com/navinnm/VigileGuard
# Secure and functional container for running security audits

FROM python:3.11-slim

# Metadata
LABEL maintainer="VigileGuard Team <https://github.com/navinnm/VigileGuard>"
LABEL description="VigileGuard - Linux Security Audit Tool"
LABEL version="1.0.4"
LABEL repository="https://github.com/navinnm/VigileGuard"

# Create non-root user first
ARG UID=1000
ARG GID=1000
RUN groupadd -g ${GID} vigileguard && \
    useradd -m -u ${UID} -g ${GID} -s /bin/bash vigileguard

# Install system dependencies (no version pinning to avoid conflicts)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    procps \
    net-tools \
    openssh-client \
    findutils \
    grep \
    coreutils \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY vigileguard.py .
COPY config.yaml .

# Create config directory and set permissions
RUN mkdir -p /home/vigileguard/.config/vigileguard && \
    cp config.yaml /home/vigileguard/.config/vigileguard/ && \
    chown -R vigileguard:vigileguard /home/vigileguard /app

# Switch to non-root user
USER vigileguard

# Set environment variables
ENV PYTHONPATH=/app
ENV VIGILEGUARD_CONFIG=/home/vigileguard/.config/vigileguard/config.yaml
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python /app/vigileguard.py --help > /dev/null 2>&1 || exit 1

# Default command
ENTRYPOINT ["python", "/app/vigileguard.py"]
CMD ["--help"]