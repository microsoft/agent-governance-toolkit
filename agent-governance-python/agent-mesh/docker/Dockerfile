# AgentMesh Component Dockerfile
# Single Dockerfile for all four AgentMesh components:
#   trust-engine, policy-server, audit-collector, api-gateway
#
# Build:
#   docker build --build-arg COMPONENT=trust-engine \
#     -t ghcr.io/microsoft/agentmesh/trust-engine:0.3.0 \
#     -f agent-governance-python/agent-mesh/docker/Dockerfile .
#
# Run:
#   docker run -p 8443:8443 ghcr.io/microsoft/agentmesh/trust-engine:0.3.0

ARG PYTHON_VERSION=3.11

FROM python:${PYTHON_VERSION}-slim@sha256:233de06753d30d120b1a3ce359d8d3be8bda78524cd8f520c99883bfe33964cf AS base

LABEL maintainer="Microsoft Corporation"
LABEL org.opencontainers.image.source="https://github.com/microsoft/agent-governance-toolkit"
LABEL org.opencontainers.image.description="Agent Governance Toolkit — AgentMesh component"
LABEL org.opencontainers.image.licenses="MIT"

# Component to run: trust-engine | policy-server | audit-collector | api-gateway
ARG COMPONENT=trust-engine
ENV AGENTMESH_COMPONENT=${COMPONENT}

WORKDIR /app

# Install system dependencies (none needed beyond slim base)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    && rm -rf /var/lib/apt/lists/*

# Copy package source from repo root context
COPY agent-governance-python/agent-mesh/pyproject.toml ./
COPY agent-governance-python/agent-mesh/README.md ./
COPY agent-governance-python/agent-mesh/src/ ./src/

# Install the package with server extras (fastapi + uvicorn)
RUN pip install --no-cache-dir ".[server]"

# Create non-root user
RUN useradd -m -s /bin/bash -u 1000 agentmesh
USER agentmesh

# Environment defaults
ENV PYTHONUNBUFFERED=1
ENV LOG_LEVEL=info
ENV HOST=0.0.0.0

# Component-specific defaults
# trust-engine: 8443, policy-server: 8444, audit-collector: 8445, api-gateway: 8446
EXPOSE 8443 8444 8445 8446

# Use tini as PID 1 for proper signal handling
ENTRYPOINT ["tini", "--"]
CMD ["python", "-m", "agentmesh.server"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request; port=os.getenv('PORT','8443'); urllib.request.urlopen(f'http://localhost:{port}/healthz')" || exit 1
