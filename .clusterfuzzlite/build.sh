#!/bin/bash -eu

cd $SRC/agent-governance-toolkit

# Install the governance packages (paths updated after mono-repo reorg)
pip3 install ./agent-governance-python/agent-os 2>/dev/null || true
pip3 install ./agent-governance-python/agent-mesh 2>/dev/null || true
pip3 install ./agent-governance-python/agent-compliance 2>/dev/null || true
pip3 install atheris==2.3.0

# Build fuzz targets
for fuzzer in $(find $SRC/agent-governance-toolkit/agent-governance-python/fuzz -name 'fuzz_*.py'); do
  compile_python_fuzzer "$fuzzer"
done
