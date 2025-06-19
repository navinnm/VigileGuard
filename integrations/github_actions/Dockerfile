FROM python:3.11-slim

LABEL maintainer="VigileGuard Team"
LABEL version="3.0.0"
LABEL description="VigileGuard Security Audit GitHub Action"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    openssh-client \
    netcat-traditional \
    nmap \
    dnsutils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install GitHub CLI for PR commenting
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
    && apt-get update && apt-get install -y gh && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy VigileGuard source code
COPY vigileguard/ ./vigileguard/
COPY api/ ./api/
COPY config.yaml ./
COPY integrations/github_actions/entrypoint.py ./

# Create reports directory
RUN mkdir -p /app/reports

# Make entrypoint executable
RUN chmod +x entrypoint.py

# Set environment variables
ENV PYTHONPATH=/app
ENV VIGILEGUARD_HOME=/app

# Run as non-root user for security
RUN useradd -m -u 1000 vigileguard && chown -R vigileguard:vigileguard /app
USER vigileguard

# Entrypoint
ENTRYPOINT ["python", "/app/entrypoint.py"]