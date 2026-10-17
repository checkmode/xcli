#!/usr/bin/env bash
# Shared build implementation for Git exports and the HTTPS bootstrap archives.
set -euo pipefail
[[ $# == 3 ]] || { echo '用法：build-source-release.sh EXPORTED_SOURCE FULL_COMMIT OUTPUT_TAR_GZ' >&2; exit 1; }
[[ $(uname -s) == Linux && $EUID != 0 ]] || { echo '请在 Linux 中以普通构建账号运行。' >&2; exit 1; }
source_dir=$(realpath -- "$1")
revision=$2
output=$(realpath -m -- "$3")
[[ $revision =~ ^[0-9a-f]{40}$ && ! -e "$output" ]] || exit 1
work=$(mktemp -d "${TMPDIR:-/tmp}/xcli-build.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/source"
# The bootstrap's root-owned source is copied into the builder's private workspace.
cp -R "$source_dir/." "$work/source/"
export PYTHONDONTWRITEBYTECODE=1
XG_SOURCE_REVISION="${revision:0:12}" bash "$work/source/deploy/build-cpp.sh" "$work/build"
python3 -m unittest discover -s "$work/source/deploy/tests" -v
python3 - "$work/source" "$work/build/xray-gateway-panel" "$revision" <<'PY'
import pathlib, sys
source=pathlib.Path(sys.argv[1]); sys.path.insert(0,str(source/'deploy'))
import release
binary=pathlib.Path(sys.argv[2])
release.atomic_json(source/'.xcli-build-receipt.json', {'revision':sys.argv[3],
    'binary_sha256':release.digest(binary),'source_digest':release.build_input_digest(source)})
PY
release_id="$(date -u +%Y%m%dT%H%M%SZ | tr '[:upper:]' '[:lower:]')-${revision:0:12}-$(uname -m)-$(python3 -c 'import uuid;print(uuid.uuid4().hex[:8])')"
python3 "$work/source/deploy/release.py" pack --source "$work/source" \
    --binary "$work/build/xray-gateway-panel" --revision "$revision" --id "$release_id" --output "$output"
(cd -- "$(dirname -- "$output")" && sha256sum "$(basename -- "$output")") > "$output.sha256"
