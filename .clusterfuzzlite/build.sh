#!/bin/bash -eu

cd $SRC/agent-governance-toolkit

# Install the governance packages (no root-level pyproject.toml)
pip3 install ./packages/agent-os 2>/dev/null || true
pip3 install ./packages/agent-mesh 2>/dev/null || true
pip3 install ./packages/agent-compliance 2>/dev/null || true
pip3 install atheris

# Build fuzz targets
for fuzzer in $(find $SRC/agent-governance-toolkit/fuzz -name 'fuzz_*.py'); do
  compile_python_fuzzer "$fuzzer"
done
