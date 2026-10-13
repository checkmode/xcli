#!/usr/bin/env bash
set -euo pipefail
source_dir=$(cd -- "$(dirname -- "$0")/../cpp" && pwd)
build_dir=${1:-"$source_dir/build"}
cmake -G Ninja -S "$source_dir" -B "$build_dir" -DCMAKE_BUILD_TYPE=RelWithDebInfo
nice -n 10 cmake --build "$build_dir" -j2
ctest --test-dir "$build_dir" --output-on-failure
