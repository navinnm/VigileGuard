# Dockerfile.debug - Minimal version for debugging
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app

# Install minimal system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    procps net-tools findutils grep coreutils && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy and install requirements first
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY vigileguard/ ./vigileguard/
COPY pyproject.toml .
COPY README.md .

# Debug: Show what we have
RUN echo "=== DEBUG: Directory structure ===" && \
    ls -la && \
    echo "=== DEBUG: Vigileguard directory ===" && \
    ls -la vigileguard/ && \
    echo "=== DEBUG: Python path ===" && \
    python -c "import sys; print('\n'.join(sys.path))"

# Debug: Test imports step by step
RUN echo "=== DEBUG: Testing imports ===" && \
    echo "1. Testing basic Python import:" && \
    python -c "print('Python works')" && \
    echo "2. Testing sys.path manipulation:" && \
    python -c "import sys; sys.path.insert(0, '/app'); print('Path manipulation works')" && \
    echo "3. Testing vigileguard directory access:" && \
    python -c "import os; print('vigileguard exists:', os.path.exists('/app/vigileguard'))" && \
    echo "4. Testing vigileguard.py file:" && \
    python -c "import os; print('vigileguard.py exists:', os.path.exists('/app/vigileguard/vigileguard.py'))" && \
    echo "5. Testing direct module import:" && \
    python -c "import sys; sys.path.insert(0, '/app'); from vigileguard import vigileguard; print('Direct import works')" && \
    echo "6. Testing __init__.py import:" && \
    python -c "import sys; sys.path.insert(0, '/app'); import vigileguard; print('Package import works')"

# Try installation
RUN echo "=== DEBUG: Installing package ===" && \
    pip install -e . && \
    echo "Installation completed"

# Test post-installation
RUN echo "=== DEBUG: Post-installation tests ===" && \
    echo "1. Testing package import after installation:" && \
    python -c "import vigileguard; print(f'Version: {getattr(vigileguard, \"__version__\", \"unknown\")}')" && \
    echo "2. Testing pip list:" && \
    pip list | grep -i vigile || echo "Not found in pip list" && \
    echo "3. Testing which vigileguard:" && \
    which vigileguard || echo "vigileguard command not found" && \
    echo "4. Testing direct execution:" && \
    python /app/vigileguard/vigileguard.py --version || echo "Direct execution failed" && \
    echo "5. Testing CLI command:" && \
    vigileguard --version || echo "CLI command failed"

# Create non-root user
RUN groupadd -g 1000 vigileguard && \
    useradd -m -u 1000 -g 1000 -s /bin/bash vigileguard && \
    chown -R vigileguard:vigileguard /app

USER vigileguard

# Final test as user
RUN echo "=== DEBUG: Final tests as user ===" && \
    python -c "import vigileguard; print('User import works')" && \
    echo "Debug completed successfully!"

# Simple entry point
ENTRYPOINT ["/bin/bash"]