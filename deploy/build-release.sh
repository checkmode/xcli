#!/usr/bin/env bash
# Build a complete application bundle from a fixed, committed Git tree on Linux.
set -euo pipefail
[[ $# == 3 ]] || { echo '用法：deploy/build-release.sh GIT_REPOSITORY FULL_COMMIT OUTPUT_TAR_GZ' >&2; exit 1; }
[[ $(uname -s) == Linux && $EUID != 0 ]] || { echo '请在 Linux 构建环境中以普通构建账号运行。' >&2; exit 1; }
repo=$(realpath -- "$1")
revision=$2
output=$(realpath -m -- "$3")
[[ $revision =~ ^[0-9a-f]{40}$ && ! -e "$output" ]] || exit 1
[[ $(git -C "$repo" rev-parse "$revision^{commit}") == "$revision" ]] || exit 1
work=$(mktemp -d "${TMPDIR:-/tmp}/xcli-build.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/source"
git -C "$repo" archive "$revision" | tar -x -C "$work/source"
# The fixed revision owns the build and packaging code as well as the application.
bash "$work/source/deploy/build-source-release.sh" "$work/source" "$revision" "$output"
