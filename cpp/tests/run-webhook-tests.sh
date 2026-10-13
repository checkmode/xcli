#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 && $# == 2 ]] || { echo 'Usage: sudo run-webhook-tests.sh SOURCE_DIR TEST_BINARY'; exit 1; }
source_dir=$(realpath -- "$1")
test_binary=$(realpath -- "$2")
# All networking stays on a namespace-local loopback interface, with no route to the Internet.
unshare --mount --net --propagation private /bin/bash -s -- "$source_dir" "$test_binary" <<'SH'
set -euo pipefail
ip link set lo up
ip address add 8.8.8.8/32 dev lo
export XG_ISOLATED_NETWORK=1
export XG_LEGACY_APP="$1/app.py"
export XG_TEST_BINARY="$2"
cd -- "$1"
python3 -m pytest -q cpp/tests/test_webhook_https.py
SH
