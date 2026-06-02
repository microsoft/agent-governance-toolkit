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
    && rm -rf /var/lib/apt/lists/* \
    # OPA CLI — required by OPAEvaluator local mode (opa eval subprocess)
    && curl -fsSL -o /usr/local/bin/opa \
        https://openpolicyagent.org/downloads/v1.4.2/opa_linux_amd64_static \
    && echo "2c0ccdbbe0b8e2a5d12d9c42d92f1f34f494ffb32d1f3c4ddc36101be637d66f  /usr/local/bin/opa" \
        | sha256sum -c - \
    && chmod 755 /usr/local/bin/opa

FROM base AS dev

# Stage 1: TypeScript dependencies cache on package-lock.json alone, so
# a Python-only source change doesn't trigger a full `npm ci` rebuild
# (the slowest part of the dev image). Only package-lock.json / package.json
# changes will invalidate this layer.
COPY agent-governance-typescript/package.json \
     agent-governance-typescript/package-lock.json \
     /workspace/agent-governance-typescript/
RUN cd /workspace/agent-governance-typescript \
    && npm ci --legacy-peer-deps

# Stage 2: bring in the full source. Subsequent layers are invalidated
# by any source change, but the `npm ci` above is preserved.
COPY . /workspace

# Stage 3: Python editable installs. A BuildKit cache mount on the pip
# download cache preserves wheel downloads across rebuilds even when
# this layer is re-executed (editable installs need source, so the
# layer itself can't be reused — but the download cache can).
#
# Scorecard: pinned via pyproject.toml. Requirements file dependencies
# have version constraints.
# Scorecard: editable installs pinned to repo checkout via pyproject.toml
#
# The consolidated v4.0.0 packages (agent-governance-toolkit-{core,cli,
# integrations,protocols}) are not yet published to PyPI, but the legacy
# shim packages below declare hard dependencies on them. Pre-install them
# from local source with --no-deps so the subsequent shim installs resolve
# without reaching out to PyPI for the unpublished names.
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install --no-deps \
        -e "agent-governance-python/agent-governance-toolkit-core" \
        -e "agent-governance-python/agent-governance-toolkit-integrations" \
        -e "agent-governance-python/agent-governance-toolkit-cli" \
        -e "agent-governance-python/agent-governance-toolkit-protocols" \
    && python -m pip install \
        "pydantic>=2.5.0,<3.0" \
        "pyyaml>=6.0,<7.0" \
    && python -m pip install --no-deps \
        -e "agent-governance-python/agt-policies" \
    && python -m pip install \
        "cedarpy>=4.0.0,<5.0" \
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
    && python -m pip install \
        -r agent-governance-python/agent-hypervisor/examples/dashboard/requirements.txt

# Stage 4: build and install the native Agent Control Specification Python SDK
# (`agent_control_specification`). agt-policies' v5 runtime bridge hard-requires
# this compiled binding — without it every adapter that routes a check through
# the bridge raises at runtime. Mirrors the `test (agent-os)` CI matrix job,
# which builds the same wheel via maturin. The C toolchain (gcc, build-essential)
# is already provided by the base stage; only Rust + maturin are added here.
# Scorecard: rustup installer is fetched over pinned TLS; the toolchain channel
# is pinned to `stable` and the SDK is built from the in-repo source checkout.
RUN --mount=type=cache,target=/root/.cache/pip \
    --mount=type=cache,target=/root/.cargo/registry \
    curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain stable \
    && . "$HOME/.cargo/env" \
    && python -m pip install maturin==1.8.7 \
    && python -m pip install --no-build-isolation ./policy-engine/sdk/python \
    && python -c "import agent_control_specification; print('agent_control_specification OK')"

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
