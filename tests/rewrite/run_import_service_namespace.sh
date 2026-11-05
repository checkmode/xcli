#!/usr/bin/env bash
# Run only disposable import-service commands inside private mount/network namespaces.
set -euo pipefail
if [[ "${1:-}" != "--inside" ]]; then
  if [[ "$EUID" != 0 || "$#" != 2 || "${1:0:1}" != / ]]; then
    echo 'usage: sudo bash run_import_service_namespace.sh ABSOLUTE_REPO UNPRIVILEGED_USER' >&2
    exit 2
  fi
  exec unshare --mount --net --fork /bin/bash "$0" --inside "$1" "$2"
fi
if [[ "$EUID" != 0 || "$#" != 3 || "$(readlink /proc/self/ns/net)" == "$(readlink /proc/1/ns/net)" ||
      "$(readlink /proc/self/ns/mnt)" == "$(readlink /proc/1/ns/mnt)" ]]; then
  echo 'refusing to run outside private namespaces' >&2
  exit 2
fi
repo="$2"
run_user="$3"
id "$run_user" >/dev/null
[[ "$(id -u "$run_user")" != 0 && -x "$repo/rewrite/rust/target/debug/xcli-import-service" &&
   -x "$repo/rewrite/rust/target/debug/examples/import_runner_fixture" && -x /usr/bin/systemctl ]]
mount --make-rprivate /
ip link set lo up
fixture="$(mktemp -d /var/tmp/xcli-import-ns.XXXXXXXX)"
lib_mounted=0
sbin_mounted=0
systemctl_mounted=0
cleanup() {
  if [[ "$systemctl_mounted" == 1 ]]; then umount /usr/bin/systemctl || true; fi
  if [[ "$sbin_mounted" == 1 ]]; then umount /usr/sbin || true; fi
  if [[ "$lib_mounted" == 1 ]]; then umount /usr/local/lib || true; fi
  if [[ "$fixture" == /var/tmp/xcli-import-ns.* && -d "$fixture" ]]; then rm -rf -- "$fixture"; fi
}
trap cleanup EXIT
mount -t tmpfs -o mode=0755 tmpfs /usr/local/lib
lib_mounted=1
install -d -o root -g root -m 0755 /usr/local/lib/xcli
mount -t tmpfs -o mode=0755 tmpfs /usr/sbin
sbin_mounted=1
printf '#!/bin/sh\nexit 0\n' > "$fixture/mock-command"
chmod 0755 "$fixture/mock-command"
install -o root -g root -m 0755 "$fixture/mock-command" /usr/local/lib/xcli/xray
install -o root -g root -m 0755 "$fixture/mock-command" /usr/local/lib/xcli/xcli-panel-checkpoint
install -o root -g root -m 0755 "$fixture/mock-command" /usr/sbin/nginx
mount --bind "$fixture/mock-command" /usr/bin/systemctl
systemctl_mounted=1
cd "$repo"
test_env=(XCLI_TEST_REPORT_UID="$(id -u "$run_user")" XCLI_TEST_REPORT_GID="$(id -g "$run_user")"
  XCLI_PANEL_SERVICE="$repo/rewrite/rust/target/debug/xcli-panel-service"
  XCLI_IMPORT_RUNNER="$repo/rewrite/rust/target/debug/examples/import_runner_fixture"
  XCLI_IMPORT_SERVICE="$repo/rewrite/rust/target/debug/xcli-import-service" XCLI_TEST_IMPORT_APPLY=1)
if [[ -f "$repo/rewrite/web/dist/gateway/main.js" ]] && command -v node >/dev/null; then
  test_env+=(XCLI_WEB_GATEWAY="$repo/rewrite/web/dist/gateway/main.js" XCLI_TEST_NODE="$(command -v node)")
fi
env "${test_env[@]}" /usr/bin/python3 -m unittest discover -s tests/rewrite -p test_import_worker_http.py -v
