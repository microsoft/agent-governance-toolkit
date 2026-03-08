# =============================================================================
# IATP Sidecar Proxy - Production Docker Image
# =============================================================================
# This Dockerfile creates a production-ready IATP Sidecar that can protect
# any agent by intercepting and validating all requests.
#
# Build:
#   docker build -t iatp-sidecar .
#
# Run:
#   docker run -p 8081:8081 \
#     -e IATP_AGENT_URL=http://my-agent:8000 \
#     -e IATP_AGENT_ID=my-agent \
#     iatp-sidecar
# =============================================================================

FROM python:3.11-slim@sha256:4057d02a202f69bfbfe10f65300519f612eb00fc595b8499f77d3cfe5b1b9fd4

# Set labels
LABEL maintainer="Imran Siddique"
LABEL description="Inter-Agent Trust Protocol (IATP) Sidecar Proxy"
LABEL version="0.2.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for caching)
COPY requirements.txt .

# Install Python dependencies
# pinned: versions declared in requirements.txt with upper bounds
RUN pip install --no-cache-dir -r requirements.txt

# Copy IATP library
COPY iatp/ /app/iatp/
COPY setup.py /app/
COPY README.md /app/

# Install IATP as a package
# pinned: local package, dependencies declared in setup.py
RUN pip install --no-cache-dir -e .

# Set Python path
ENV PYTHONPATH=/app

# =============================================================================
# Environment Configuration
# =============================================================================
# These can be overridden at runtime with -e flags

# The URL of the upstream agent this sidecar protects
ENV IATP_AGENT_URL=http://localhost:8000

# The port the sidecar listens on
ENV IATP_PORT=8081

# Unique identifier for the agent
ENV IATP_AGENT_ID=default-agent

# Trust level: verified_partner, trusted, standard, unknown, untrusted
ENV IATP_TRUST_LEVEL=standard

# Reversibility: full, partial, none
ENV IATP_REVERSIBILITY=partial

# Data retention: ephemeral, temporary, permanent
ENV IATP_RETENTION=temporary

# Require human approval for sensitive operations
ENV IATP_HUMAN_IN_LOOP=false

# Allow data use for training
ENV IATP_TRAINING_CONSENT=false

# =============================================================================
# Expose port and configure health check
# =============================================================================

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/health || exit 1

# =============================================================================
# Run the sidecar
# =============================================================================

CMD ["uvicorn", "iatp.main:app", "--host", "0.0.0.0", "--port", "8081"]
