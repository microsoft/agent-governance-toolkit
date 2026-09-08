#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel)}"
ROOT="$(cd "$ROOT" && pwd)"
PLATFORM="${2:-linux-x86_64}"
BUILD_SDIST="${3:-true}"
RUSTUP_VERSION="1.27.1"
RUST_TOOLCHAIN="1.89.0"

case "$PLATFORM" in
  linux-x86_64)
    IMAGE="quay.io/pypa/manylinux_2_28_x86_64@sha256:d4290a169db70a3349c89a92ab2304103910759ad97a21044487e1d233ce43b0"
    RUST_TARGET="x86_64-unknown-linux-gnu"
    RUSTUP_TARGET="x86_64-unknown-linux-gnu"
    RUSTUP_SHA256="6aeece6993e902708983b209d04c0d1dbb14ebb405ddb87def578d41f920f56d"
    BUILD_PYTHON="/opt/python/cp311-cp311/bin/python"
    ;;
  linux-aarch64)
    IMAGE="quay.io/pypa/manylinux_2_28_aarch64@sha256:e7035406e58d96b7407246af1f6514a3cbd753a0025b42b9adfbeadd3b29ba80"
    RUST_TARGET="aarch64-unknown-linux-gnu"
    RUSTUP_TARGET="aarch64-unknown-linux-gnu"
    RUSTUP_SHA256="1cffbf51e63e634c746f741de50649bbbcbd9dbe1de363c9ecef64e278dba2b2"
    BUILD_PYTHON="/opt/python/cp311-cp311/bin/python"
    ;;
  linux-aarch64-cross)
    IMAGE="ghcr.io/rust-cross/manylinux_2_28-cross:aarch64@sha256:ca53fa07ecf1c3e6408c51fbca64c036d9d29af832d3f8bb954910e89097f275"
    RUST_TARGET="aarch64-unknown-linux-gnu"
    BUILD_PYTHON="python3.11"
    case "$(uname -m)" in
      x86_64)
        RUSTUP_TARGET="x86_64-unknown-linux-gnu"
        RUSTUP_SHA256="6aeece6993e902708983b209d04c0d1dbb14ebb405ddb87def578d41f920f56d"
        ;;
      aarch64)
        RUSTUP_TARGET="aarch64-unknown-linux-gnu"
        RUSTUP_SHA256="1cffbf51e63e634c746f741de50649bbbcbd9dbe1de363c9ecef64e278dba2b2"
        ;;
      *)
        echo "unsupported ACS Python cross-build host: $(uname -m)" >&2
        exit 2
        ;;
    esac
    ;;
  *)
    echo "unsupported ACS Python wheel platform: $PLATFORM" >&2
    exit 2
    ;;
esac

if [[ "$BUILD_SDIST" != "true" && "$BUILD_SDIST" != "false" ]]; then
  echo "BUILD_SDIST must be true or false" >&2
  exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to build the ACS Python manylinux wheel" >&2
  exit 1
fi

docker run --rm \
  -e "HOST_UID=$(id -u)" \
  -e "HOST_GID=$(id -g)" \
  -e "RUSTUP_VERSION=$RUSTUP_VERSION" \
  -e "RUSTUP_SHA256=$RUSTUP_SHA256" \
  -e "RUST_TOOLCHAIN=$RUST_TOOLCHAIN" \
  -e "RUST_TARGET=$RUST_TARGET" \
  -e "RUSTUP_TARGET=$RUSTUP_TARGET" \
  -e "BUILD_PYTHON=$BUILD_PYTHON" \
  -e "BUILD_SDIST=$BUILD_SDIST" \
  -v "$ROOT:/work" \
  -w /work/policy-engine \
  "$IMAGE" \
  /bin/bash -lc '
    set -euo pipefail
    for attempt in 1 2 3 4 5; do
      if curl --proto '"'"'=https'"'"' --tlsv1.2 -fSLo /tmp/rustup-init \
        --connect-timeout 20 \
        "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${RUSTUP_TARGET}/rustup-init"; then
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
    rustup target add --toolchain "${RUST_TOOLCHAIN}" "${RUST_TARGET}"
    rustc --version
    cargo --version
    "${BUILD_PYTHON}" -m pip install --no-cache-dir --disable-pip-version-check \
      --require-hashes --no-deps \
      -r /work/.github/release-tools/release-tools.txt
    rm -rf /work/policy-engine/sdk/python/dist
    mkdir -p /work/policy-engine/sdk/python/dist
    maturin_args=(build \
      --release \
      --locked \
      --out /work/policy-engine/sdk/python/dist \
      --compatibility manylinux_2_28 \
      --target "${RUST_TARGET}" \
      --manifest-path /work/policy-engine/sdk/python/Cargo.toml)
    if [ "${BUILD_SDIST}" = "true" ]; then
      maturin_args+=(--sdist)
    fi
    "${BUILD_PYTHON}" -m maturin "${maturin_args[@]}"
    chown -R "${HOST_UID}:${HOST_GID}" /work/policy-engine/sdk/python/dist
  '
