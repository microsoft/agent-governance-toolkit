#!/bin/bash -eu

cd $SRC/agent-governance-toolkit

pip3 install .

# Build fuzz targets
for fuzzer in $(find $SRC/agent-governance-toolkit/fuzz -name 'fuzz_*.py'); do
  compile_python_fuzzer "$fuzzer"
done
