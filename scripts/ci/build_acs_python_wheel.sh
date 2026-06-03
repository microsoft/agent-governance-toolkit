#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

ROOT="${1:-$(git rev-parse --show-toplevel)}"
ROOT="$(cd "$ROOT" && pwd)"
IMAGE="quay.io/pypa/manylinux_2_28_x86_64@sha256:d4290a169db70a3349c89a92ab2304103910759ad97a21044487e1d233ce43b0"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required to build the ACS Python manylinux wheel" >&2
  exit 1
fi

docker run --rm \
  -v "$ROOT:/work" \
  -w /work/policy-engine \
  "$IMAGE" \
  /bin/bash -lc '
    set -euo pipefail
    /opt/python/cp311-cp311/bin/python -m pip install --no-cache-dir --disable-pip-version-check \
      --require-hashes --no-deps \
      -r /work/.github/pipelines/release-tools/release-tools.txt
    rm -rf /work/policy-engine/sdk/python/dist
    mkdir -p /work/policy-engine/sdk/python/dist
    /opt/python/cp311-cp311/bin/python -m maturin build \
      --release \
      --sdist \
      --out /work/policy-engine/sdk/python/dist \
      --compatibility manylinux_2_28 \
      --manifest-path /work/policy-engine/sdk/python/Cargo.toml
  '
