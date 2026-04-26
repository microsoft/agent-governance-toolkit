# Dockerfile for CMVK — Verification Kernel
# Supports both the CLI and sandbox code execution

FROM python:3.11-slim@sha256:4057d02a202f69bfbfe10f65300519f612eb00fc595b8499f77d3cfe5b1b9fd4 as base

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    git \
    && rm -rf /var/lib/apt/lists/*

# ============================================
# Builder stage - install dependencies
# ============================================
FROM base as builder

# Install Python dependencies
COPY requirements.txt .
# pinned: versions declared in requirements.txt with upper bounds
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Install the package in editable mode
# pinned: local package, dependencies declared in pyproject.toml
RUN pip install --no-cache-dir -e .

# ============================================
# Production stage
# ============================================
FROM base as production

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY . .

# Install the package
# pinned: local package, dependencies declared in pyproject.toml
RUN pip install --no-cache-dir -e .

# Create non-root user for security
RUN useradd -m -u 1000 cmvkuser && \
    chown -R cmvkuser:cmvkuser /app

# Create directories for logs and results
RUN mkdir -p /app/logs/traces /app/experiments/results && \
    chown -R cmvkuser:cmvkuser /app/logs /app/experiments/results

USER cmvkuser

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "from src import __version__; print(__version__)" || exit 1

# Default command - show help
CMD ["cmvk", "--help"]

# ============================================
# Sandbox stage - isolated code execution
# ============================================
FROM base as sandbox

# Create sandboxed user with minimal privileges
RUN useradd -m -u 1000 sandboxuser

WORKDIR /sandbox
RUN chown -R sandboxuser:sandboxuser /sandbox

USER sandboxuser

# Set resource limits
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Default command for sandbox
CMD ["python3"]
