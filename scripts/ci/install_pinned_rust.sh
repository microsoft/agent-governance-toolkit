#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

RUSTUP_VERSION="1.27.1"
RUST_TOOLCHAIN="1.89.0"
RUST_TARGET="${1:-}"

case "$RUST_TARGET" in
  "" | x86_64-unknown-linux-gnu | x86_64-apple-darwin | aarch64-apple-darwin | x86_64-pc-windows-msvc) ;;
  *)
    echo "unsupported ACS Rust target: $RUST_TARGET" >&2
    exit 2
    ;;
esac

case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    RUSTUP_TARGET="x86_64-unknown-linux-gnu"
    RUSTUP_FILE="rustup-init"
    RUSTUP_SHA256="6aeece6993e902708983b209d04c0d1dbb14ebb405ddb87def578d41f920f56d"
    ;;
  Darwin:x86_64)
    RUSTUP_TARGET="x86_64-apple-darwin"
    RUSTUP_FILE="rustup-init"
    RUSTUP_SHA256="f547d77c32d50d82b8228899b936bf2b3c72ce0a70fb3b364e7fba8891eba781"
    ;;
  Darwin:arm64)
    RUSTUP_TARGET="aarch64-apple-darwin"
    RUSTUP_FILE="rustup-init"
    RUSTUP_SHA256="760b18611021deee1a859c345d17200e0087d47f68dfe58278c57abe3a0d3dd0"
    ;;
  MINGW*:x86_64 | MSYS*:x86_64 | CYGWIN*:x86_64)
    RUSTUP_TARGET="x86_64-pc-windows-msvc"
    RUSTUP_FILE="rustup-init.exe"
    RUSTUP_SHA256="193d6c727e18734edbf7303180657e96e9d5a08432002b4e6c5bbe77c60cb3e8"
    ;;
  *)
    echo "unsupported ACS Rust build host: $(uname -s) $(uname -m)" >&2
    exit 2
    ;;
esac

# Print the lowercase hex SHA-256 of a file using whichever hashing tool the
# build host provides. Linux and Git Bash ship sha256sum, macOS ships shasum,
# and any remaining host falls back to a Python interpreter.
compute_sha256() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return
  fi
  local python_bin=""
  if command -v python3 >/dev/null 2>&1; then
    python_bin="python3"
  elif command -v python >/dev/null 2>&1; then
    python_bin="python"
  else
    echo "no SHA-256 tool available (need sha256sum, shasum, or python)" >&2
    exit 1
  fi
  "$python_bin" - "$file" <<'PY'
from hashlib import sha256
from pathlib import Path
import sys

print(sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
}

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT
INSTALLER="$TEMP_DIR/$RUSTUP_FILE"
curl --proto '=https' --tlsv1.2 --retry 5 --retry-all-errors --retry-delay 5 \
  --connect-timeout 20 -fSLo "$INSTALLER" \
  "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${RUSTUP_TARGET}/${RUSTUP_FILE}"
ACTUAL_SHA256="$(compute_sha256 "$INSTALLER")"
if [[ "$ACTUAL_SHA256" != "$RUSTUP_SHA256" ]]; then
  echo "rustup installer checksum mismatch" >&2
  exit 1
fi
chmod +x "$INSTALLER"
"$INSTALLER" -y --profile minimal --default-toolchain "$RUST_TOOLCHAIN"
export PATH="$HOME/.cargo/bin:$PATH"
if [[ -n "$RUST_TARGET" ]]; then
  rustup target add --toolchain "$RUST_TOOLCHAIN" "$RUST_TARGET"
fi
rustc --version
cargo --version
echo "##vso[task.prependpath]$HOME/.cargo/bin"
