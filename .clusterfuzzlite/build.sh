#!/bin/bash -eu

cd $SRC/agent-governance-toolkit

# Install the governance packages (paths updated after mono-repo reorg).
# Fail loudly if any install fails — silently building fuzzers without
# their target packages produces fuzzers that exercise none of the code
# under test. The script already runs with `bash -eu`, so an unswallowed
# failure here aborts the build instead of producing empty harnesses.
#
# The consolidated v4.0.0 packages (agent-governance-toolkit-{core,cli,
# integrations,protocols}) are not yet published to PyPI, but the legacy
# shim packages below declare hard dependencies on them. Pre-install them
# from local source with --no-deps so the subsequent shim installs resolve
# without reaching out to PyPI for the unpublished names.
pip3 install --no-deps \
    ./agent-governance-python/agent-governance-toolkit-core \
    ./agent-governance-python/agent-governance-toolkit-cli \
    ./agent-governance-python/agent-governance-toolkit-integrations \
    ./agent-governance-python/agent-governance-toolkit-protocols  # Scorecard: pinned to repo checkout
pip3 install ./agent-governance-python/agent-os  # Scorecard: pinned to repo checkout
pip3 install ./agent-governance-python/agent-mesh  # Scorecard: pinned to repo checkout
pip3 install ./agent-governance-python/agent-compliance  # Scorecard: pinned to repo checkout
pip3 install atheris==2.3.0  # Scorecard: version-pinned (platform-specific, hash omitted)

# Build fuzz targets
for fuzzer in $(find $SRC/agent-governance-toolkit/agent-governance-python/fuzz -name 'fuzz_*.py'); do
  compile_python_fuzzer "$fuzzer"
done
