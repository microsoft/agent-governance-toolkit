# AgentMesh Component Dockerfile
# Single Dockerfile for all AgentMesh server components:
#   trust-engine, policy-server, audit-collector, api-gateway, registry, relay
#
# Build examples:
#   docker build --build-arg COMPONENT=registry \
#     -t ghcr.io/microsoft/agentmesh/registry:0.3.0 \
#     -f agent-governance-python/agent-mesh/docker/Dockerfile .
#
#   docker build --build-arg COMPONENT=relay \
#     -t ghcr.io/microsoft/agentmesh/relay:0.3.0 \
#     -f agent-governance-python/agent-mesh/docker/Dockerfile .
#
#   docker build --build-arg COMPONENT=trust-engine \
#     -t ghcr.io/microsoft/agentmesh/trust-engine:0.3.0 \
#     -f agent-governance-python/agent-mesh/docker/Dockerfile .
#
# Run:
#   docker run -p 8082:8082 ghcr.io/microsoft/agentmesh/registry:0.3.0
#   docker run -p 8083:8083 ghcr.io/microsoft/agentmesh/relay:0.3.0

ARG PYTHON_VERSION=3.11

FROM python:${PYTHON_VERSION}-slim@sha256:233de06753d30d120b1a3ce359d8d3be8bda78524cd8f520c99883bfe33964cf AS base

LABEL maintainer="Microsoft Corporation"
LABEL org.opencontainers.image.source="https://github.com/microsoft/agent-governance-toolkit"
LABEL org.opencontainers.image.description="Agent Governance Toolkit - AgentMesh component"
LABEL org.opencontainers.image.licenses="MIT"

# Component to run:
#   trust-engine | policy-server | audit-collector | api-gateway | registry | relay
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

# Default ports by component:
#   registry: 8082, relay: 8083
#   trust-engine: 8443, policy-server: 8444, audit-collector: 8445, api-gateway: 8446
EXPOSE 8082 8083 8443 8444 8445 8446

# Use tini as PID 1 for proper signal handling
ENTRYPOINT ["tini", "--"]
# Component-aware entrypoint: registry and relay have their own modules,
# all others use the legacy agentmesh.server module.
CMD ["sh", "-c", "case $AGENTMESH_COMPONENT in registry) exec python -m agentmesh.registry;; relay) exec python -m agentmesh.relay;; *) exec python -m agentmesh.server;; esac"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os,urllib.request; port=os.getenv('PORT','8082'); urllib.request.urlopen(f'http://localhost:{port}/healthz')" || exit 1
