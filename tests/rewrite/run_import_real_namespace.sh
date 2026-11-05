#!/usr/bin/env bash
# Real disposable Xray/Nginx, private networking, simulated service manager.
set -euo pipefail
if [[ "${1:-}" != "--inside" ]]; then
  if [[ "$EUID" != 0 || "$#" != 3 || "${1:0:1}" != / || "${3:0:1}" != / ]]; then
    echo 'usage: sudo bash run_import_real_namespace.sh REPO USER XRAY_BINARY' >&2
    exit 2
  fi
  exec unshare --mount --net --fork /bin/bash "$0" --inside "$1" "$2" "$3"
fi
if [[ "$EUID" != 0 || "$#" != 4 || "$(readlink /proc/self/ns/net)" == "$(readlink /proc/1/ns/net)" ||
      "$(readlink /proc/self/ns/mnt)" == "$(readlink /proc/1/ns/mnt)" ]]; then
  echo 'refusing to run outside private namespaces' >&2
  exit 2
fi
repo="$2"
run_user="$3"
xray="$4"
[[ "$(id -u "$run_user")" != 0 && -x "$xray" && -x /usr/sbin/nginx && -x /usr/bin/systemctl ]]
mount --make-rprivate /
ip link set lo up
ip addr add 1.1.1.1/32 dev lo
fixture="$(mktemp -d /var/tmp/xcli-import-real-ns.XXXXXXXX)"
lib_mounted=0
nginx_mounted=0
run_mounted=0
systemctl_mounted=0
cleanup() {
  for name in panel core nginx; do
    pid_file="/run/xcli-test/$name.pid"
    if [[ -f "$pid_file" ]]; then
      pid="$(cat "$pid_file")"
      if [[ "$pid" =~ ^[0-9]+$ && "$(readlink "/proc/$pid/ns/net" 2>/dev/null || true)" == "$(readlink /proc/self/ns/net)" ]]; then
        kill "$pid" 2>/dev/null || true
      fi
    fi
  done
  if [[ "$systemctl_mounted" == 1 ]]; then umount /usr/bin/systemctl || true; fi
  if [[ "$run_mounted" == 1 ]]; then umount /run || true; fi
  if [[ "$nginx_mounted" == 1 ]]; then umount /etc/nginx || true; fi
  if [[ "$lib_mounted" == 1 ]]; then umount /usr/local/lib || true; fi
  if [[ "$fixture" == /var/tmp/xcli-import-real-ns.* && -d "$fixture" ]]; then rm -rf -- "$fixture"; fi
}
trap cleanup EXIT
install -o root -g root -m 0755 "$xray" "$fixture/xray"
mount -t tmpfs -o mode=0755 tmpfs /usr/local/lib
lib_mounted=1
install -d -o root -g root -m 0755 /usr/local/lib/xcli
install -o root -g root -m 0755 "$fixture/xray" /usr/local/lib/xcli/xray
install -o root -g root -m 0755 "$repo/rewrite/rust/target/debug/xcli-panel-checkpoint" /usr/local/lib/xcli/xcli-panel-checkpoint
mount -t tmpfs -o mode=0755 tmpfs /etc/nginx
nginx_mounted=1
mount -t tmpfs -o mode=0755 tmpfs /run
run_mounted=1
install -d -o root -g root -m 0755 /run/xcli-test
cat > "$fixture/systemctl" <<'PY'
#!/usr/bin/python3
import json,socket,sys
try:
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(45);s.connect('/run/xcli-test/manager.sock')
    s.sendall(json.dumps(sys.argv[1:]).encode()+b'\n')
    data=b''
    while not data.endswith(b'\n'):data+=s.recv(4096)
    sys.exit(int(data.strip()))
except Exception:sys.exit(1)
PY
chmod 0755 "$fixture/systemctl"
mount --bind "$fixture/systemctl" /usr/bin/systemctl
systemctl_mounted=1
cd "$repo"
test_env=(XCLI_TEST_REPORT_UID="$(id -u "$run_user")" XCLI_TEST_REPORT_GID="$(id -g "$run_user")"
  XCLI_PANEL_SERVICE="$repo/rewrite/rust/target/debug/xcli-panel-service"
  XCLI_PANEL_INIT="$repo/rewrite/rust/target/debug/examples/provision_fixture"
  XCLI_IMPORT_SERVICE="$repo/rewrite/rust/target/debug/xcli-import-service")
if [[ -f "$repo/rewrite/web/dist/gateway/main.js" ]] && command -v node >/dev/null; then
  test_env+=(XCLI_WEB_GATEWAY="$repo/rewrite/web/dist/gateway/main.js" XCLI_TEST_NODE="$(command -v node)")
fi
env "${test_env[@]}" /usr/bin/python3 -m unittest discover -s tests/rewrite -p test_import_service_real.py -v
