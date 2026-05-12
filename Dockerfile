# syntax=docker/dockerfile:1.7

# Python version is pinned in the FROM line below (tag + digest). The image
# digest is the single source of truth for reproducibility; do not add an ARG
# here unless it is actually referenced by the FROM line.
FROM python:3.11-slim@sha256:9358444059ed78e2975ada2c189f1c1a3144a5dab6f35bff8c981afb38946634 AS base

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NODE_MAJOR=22

WORKDIR /workspace

RUN for i in 1 2 3; do apt-get update && break || sleep 5; done \
    && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        curl \
        git \
        gnupg \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list \
    && for i in 1 2 3; do apt-get update && break || sleep 5; done \
    && apt-get install -y --no-install-recommends nodejs \
    && python -m pip install --upgrade pip==24.3.1 setuptools==75.8.0 wheel==0.45.1 \
    && rm -rf /var/lib/apt/lists/*

FROM base AS dev

COPY . /workspace

# Install local packages (Scorecard: pinned via pyproject.toml)
# Requirements file dependencies have version constraints
RUN python -m pip install --no-cache-dir \
        -e "agent-governance-python/agent-primitives[dev]" \
        -e "agent-governance-python/agent-mcp-governance[dev]" \
        -e "agent-governance-python/agent-os[full,dev]" \
        -e "agent-governance-python/agent-mesh[agent-os,dev,server]" \
        -e "agent-governance-python/agent-hypervisor[api,dev,nexus]" \
        -e "agent-governance-python/agent-runtime" \
        -e "agent-governance-python/agent-sre[api,dev]" \
        -e "agent-governance-python/agent-compliance" \
        -e "agent-governance-python/agent-marketplace[cli,dev]" \
        -e "agent-governance-python/agent-lightning[agent-os,dev]" \
    && python -m pip install --no-cache-dir \
        -r agent-governance-python/agent-hypervisor/examples/dashboard/requirements.txt \
    && cd /workspace/agent-governance-typescript \
    && npm ci --legacy-peer-deps

# Run as non-root for the developer workflow. The compose `dev` and
# `dashboard` services bind-mount the repo at /workspace; running the
# entrypoint as root creates files on the host owned by uid 0, which
# is both an isolation hazard and an ergonomic problem (host editor
# can't easily fix permissions). Create the user AFTER the package
# installs so the system-site-packages writes don't need a sudo step.
RUN useradd --create-home --shell /bin/bash --uid 1000 dev \
    && chown -R dev:dev /workspace

USER dev

ENTRYPOINT ["bash", "/workspace/scripts/docker/dev-entrypoint.sh"]
CMD ["sleep", "infinity"]

FROM dev AS test

CMD ["pytest"]
