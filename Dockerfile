# syntax=docker/dockerfile:1.7

ARG PYTHON_VERSION=3.11

FROM python:${PYTHON_VERSION}-slim AS base

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
    && curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && python -m pip install --upgrade pip setuptools wheel \
    && rm -rf /var/lib/apt/lists/*

FROM base AS dev

COPY . /workspace

RUN python -m pip install --no-cache-dir \
        -e "packages/agent-os[full,dev]" \
        -e "packages/agent-mesh[agent-os,dev,server]" \
        -e "packages/agent-hypervisor[api,dev,nexus]" \
        -e "packages/agent-runtime" \
        -e "packages/agent-sre[api,dev]" \
        -e "packages/agent-compliance" \
        -e "packages/agent-marketplace[cli,dev]" \
        -e "packages/agent-lightning[agent-os,dev]" \
    && python -m pip install --no-cache-dir \
        -r packages/agent-hypervisor/examples/dashboard/requirements.txt \
    && cd /workspace/packages/agent-mesh/sdks/typescript \
    && npm ci

ENTRYPOINT ["bash", "/workspace/scripts/docker/dev-entrypoint.sh"]
CMD ["sleep", "infinity"]

FROM dev AS test

CMD ["pytest"]
