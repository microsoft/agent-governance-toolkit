#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel)}"
ROOT="$(cd "$ROOT" && pwd)"
IMAGE="quay.io/pypa/manylinux_2_28_x86_64@sha256:d4290a169db70a3349c89a92ab2304103910759ad97a21044487e1d233ce43b0"
RUSTUP_VERSION="1.27.1"
RUSTUP_SHA256="6aeece6993e902708983b209d04c0d1dbb14ebb405ddb87def578d41f920f56d"
RUST_TOOLCHAIN="1.89.0"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to build the ACS Python manylinux wheel" >&2
  exit 1
fi

docker run --rm \
  -e "RUSTUP_VERSION=$RUSTUP_VERSION" \
  -e "RUSTUP_SHA256=$RUSTUP_SHA256" \
  -e "RUST_TOOLCHAIN=$RUST_TOOLCHAIN" \
  -v "$ROOT:/work" \
  -w /work/policy-engine \
  "$IMAGE" \
  /bin/bash -lc '
    set -euo pipefail
    for attempt in 1 2 3 4 5; do
      if curl --proto '"'"'=https'"'"' --tlsv1.2 -fSLo /tmp/rustup-init \
        --connect-timeout 20 \
        "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init"; then
        break
      fi
      if [ "$attempt" = "5" ]; then
        exit 1
      fi
      sleep $((attempt * 5))
    done
    echo "${RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum -c -
    chmod +x /tmp/rustup-init
    /tmp/rustup-init -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}"
    export PATH="$HOME/.cargo/bin:$PATH"
    rustc --version
    cargo --version
    /opt/python/cp311-cp311/bin/python -m pip install --no-cache-dir --disable-pip-version-check \
      --require-hashes --no-deps \
      -r /work/.github/release-tools/release-tools.txt
    rm -rf /work/policy-engine/sdk/python/dist
    mkdir -p /work/policy-engine/sdk/python/dist
    /opt/python/cp311-cp311/bin/python -m maturin build \
      --release \
      --sdist \
      --out /work/policy-engine/sdk/python/dist \
      --compatibility manylinux_2_28 \
      --manifest-path /work/policy-engine/sdk/python/Cargo.toml
  '
