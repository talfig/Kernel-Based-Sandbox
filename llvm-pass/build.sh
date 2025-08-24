#!/usr/bin/env bash
set -euo pipefail
mkdir -p build
cd build
cmake -DLLVM_DIR=$(llvm-config --cmakedir) ..
cmake --build . -j
echo "Built: $(pwd)/libLibCallPass.so"
