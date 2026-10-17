#!/usr/bin/env bash
# Compatibility spelling only: the old in-place updater has been removed.
set -euo pipefail
[[ $# == 2 ]] || { echo '用法：deploy/update-panel.sh EXPORTED_SOURCE FULL_COMMIT' >&2; exit 1; }
source_dir=$(realpath -- "$1")
exec python3 -B "$source_dir/deploy/update.py" --source "$source_dir" --commit "$2"
