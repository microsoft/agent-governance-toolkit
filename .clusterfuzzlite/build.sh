#!/bin/bash -eu

cd $SRC/agent-governance-toolkit

# Install the governance packages (paths updated after mono-repo reorg).
# Fail loudly if any install fails — silently building fuzzers without
# their target packages produces fuzzers that exercise none of the code
# under test. The script already runs with `bash -eu`, so an unswallowed
# failure here aborts the build instead of producing empty harnesses.
pip3 install ./agent-governance-python/agent-os  # Scorecard: pinned to repo checkout
pip3 install ./agent-governance-python/agent-mesh  # Scorecard: pinned to repo checkout
pip3 install ./agent-governance-python/agent-compliance  # Scorecard: pinned to repo checkout
pip3 install atheris==2.3.0  # Scorecard: version-pinned (platform-specific, hash omitted)

# Build fuzz targets
for fuzzer in $(find $SRC/agent-governance-toolkit/agent-governance-python/fuzz -name 'fuzz_*.py'); do
  compile_python_fuzzer "$fuzzer"
done
