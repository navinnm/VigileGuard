# VigileGuard Docker Image - Security Hardened
# Repository: https://github.com/navinnm/VigileGuard
# Lightweight and secure container for running security audits

# Use specific version instead of latest for reproducibility
FROM python:3.11.9-slim-bookworm

# Metadata
LABEL maintainer="VigileGuard Team <https://github.com/navinnm/VigileGuard>"
LABEL description="VigileGuard - Linux Security Audit Tool"
LABEL version="1.0.3"
LABEL repository="https://github.com/navinnm/VigileGuard"
LABEL org.opencontainers.image.source="https://github.com/navinnm/VigileGuard"
LABEL org.opencontainers.image.description="Secure Linux security audit container"
LABEL org.opencontainers.image.licenses="MIT"

# Security: Run as non-root from the start
ARG UID=1000
ARG GID=1000

# Install system dependencies with security considerations
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Essential tools only
    git=1:2.39.2-1.1 \
    curl=7.88.1-10+deb12u5 \
    procps=2:4.0.2-3 \
    net-tools=1.60+git20161116.90da8a0-1 \
    openssh-client=1:9.2p1-2+deb12u2 \
    findutils=4.9.0-4 \
    grep=3.8-5 \
    coreutils=9.1-1 \
    # Security: Remove sudo - not needed in container
    # sudo \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get purge -y --auto-remove \
    && apt-get clean

# Create non-root user with specific UID/GID for security
RUN groupadd -g ${GID} vigileguard && \
    useradd -m -u ${UID} -g ${GID} -s /bin/bash vigileguard

# Set working directory with proper ownership
WORKDIR /app
RUN chown vigileguard:vigileguard /app

# Security: Switch to non-root user early
USER vigileguard

# Copy requirements first for better layer caching
COPY --chown=vigileguard:vigileguard requirements.txt .

# Install Python dependencies with security flags
RUN pip install --no-cache-dir --user --upgrade pip==24.0 && \
    pip install --no-cache-dir --user -r requirements.txt && \
    # Security: Remove pip cache and temporary files
    rm -rf ~/.cache/pip

# Copy application files with proper ownership
COPY --chown=vigileguard:vigileguard vigileguard.py .
COPY --chown=vigileguard:vigileguard config.yaml .

# Create config directory in user space (not /etc)
RUN mkdir -p ~/.config/vigileguard && \
    cp config.yaml ~/.config/vigileguard/

# Security: Create wrapper script in user space
RUN mkdir -p ~/.local/bin && \
    echo '#!/bin/bash\npython /app/vigileguard.py "$@"' > ~/.local/bin/vigileguard && \
    chmod +x ~/.local/bin/vigileguard

# Set secure environment variables
ENV PYTHONPATH=/app
ENV PATH="/home/vigileguard/.local/bin:${PATH}"
ENV VIGILEGUARD_CONFIG=/home/vigileguard/.config/vigileguard/config.yaml
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Security: Add security-focused health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python /app/vigileguard.py --help > /dev/null 2>&1 || exit 1

# Security: Use exec form for better signal handling
ENTRYPOINT ["python", "/app/vigileguard.py"]
CMD ["--help"]

# Multi-stage build example for even better security (optional)
# FROM python:3.11.9-slim-bookworm AS builder
# ... build dependencies ...
# FROM python:3.11.9-slim-bookworm AS runtime
# COPY --from=builder /app /app

# Build and usage instructions:
#
# Build the image:
#   docker build -t vigileguard:1.0.3 .
#   docker build --build-arg UID=$(id -u) --build-arg GID=$(id -g) -t vigileguard:1.0.3 .
#
# Basic usage:
#   docker run --rm vigileguard:1.0.3
#   docker run --rm vigileguard:1.0.3 --format json
#
# Mount host filesystem for scanning (read-only):
#   docker run --rm --read-only -v /:/host:ro vigileguard:1.0.3
#
# Save report to host:
#   docker run --rm -v $(pwd):/output vigileguard:1.0.3 --format json --output /output/report.json
#
# Security scan with limited capabilities:
#   docker run --rm --read-only --cap-drop=ALL --cap-add=DAC_OVERRIDE \
#     -v /:/host:ro vigileguard:1.0.3 --format json
#
# Custom configuration:
#   docker run --rm -v $(pwd)/custom-config.yaml:/home/vigileguard/.config/vigileguard/config.yaml:ro \
#     vigileguard:1.0.3