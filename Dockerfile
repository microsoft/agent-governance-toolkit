# syntax=docker/dockerfile:1.7

ARG PYTHON_VERSION=3.11

FROM python:3.11-slim@sha256:9358444059ed78e2975ada2c189f1c1a3144a5dab6f35bff8c981afb38946634 AS base

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NODE_MAJOR=22

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        curl \
        git \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_MAJOR}.x nodistro main" \
        > /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
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
        -e "agent-os[full,dev]" \
        -e "agent-mesh[agent-os,dev,server]" \
        -e "agent-hypervisor[api,dev,nexus]" \
        -e "agent-runtime" \
        -e "agent-sre[api,dev]" \
        -e "agent-compliance" \
        -e "agent-marketplace[cli,dev]" \
        -e "agent-lightning[agent-os,dev]" \
    && python -m pip install --no-cache-dir \
        -r agent-governance-python/agent-hypervisor/examples/dashboard/requirements.txt \
    && cd /workspace/agent-governance-typescript \
    && npm ci

ENTRYPOINT ["bash", "/workspace/scripts/docker/dev-entrypoint.sh"]
CMD ["sleep", "infinity"]

FROM dev AS test

CMD ["pytest"]
