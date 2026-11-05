#!/usr/bin/env bash
# Disposable mount/network namespace; never installs files or changes host networking.
set -euo pipefail
if [[ "${1:-}" != "--inside" ]]; then
  if [[ "$EUID" != 0 || "$#" != 2 || "${1:0:1}" != / ]]; then
    echo 'usage: sudo bash run_notification_namespace.sh ABSOLUTE_REPO UNPRIVILEGED_USER' >&2
    exit 2
  fi
  exec unshare --mount --net --fork /bin/bash "$0" --inside "$1" "$2"
fi
if [[ "$EUID" != 0 || "$#" != 3 || "$(readlink /proc/self/ns/net)" == "$(readlink /proc/1/ns/net)" ||
      "$(readlink /proc/self/ns/mnt)" == "$(readlink /proc/1/ns/mnt)" ]]; then
  echo 'refusing to run outside a private mount and network namespace' >&2
  exit 2
fi
repo="$2"
run_user="$3"
id "$run_user" >/dev/null
[[ "$(id -u "$run_user")" != 0 && -x "$repo/rewrite/rust/target/debug/xcli-webhook-sender" &&
   -x "$repo/rewrite/rust/target/debug/xcli-panel-service" && -f /etc/ssl/certs/ca-certificates.crt ]]
mount --make-rprivate /
fixture="$(mktemp -d /var/tmp/xcli-notification-ns.XXXXXXXX)"
lib_mounted=0
hosts_mounted=0
cert_mounted=0
cleanup() {
  if [[ "$cert_mounted" == 1 ]]; then umount /etc/ssl/certs/ca-certificates.crt || true; fi
  if [[ "$hosts_mounted" == 1 ]]; then umount /etc/hosts || true; fi
  if [[ "$lib_mounted" == 1 ]]; then umount /usr/local/lib || true; fi
  if [[ "$fixture" == /var/tmp/xcli-notification-ns.* && -d "$fixture" ]]; then rm -rf -- "$fixture"; fi
}
trap cleanup EXIT
chown "$run_user" "$fixture"
chmod 0755 "$fixture"
runuser -u "$run_user" -- openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj /CN=receiver.fixture -addext subjectAltName=DNS:receiver.fixture \
  -addext basicConstraints=critical,CA:FALSE -keyout "$fixture/key.pem" -out "$fixture/cert.pem" >/dev/null 2>&1
chmod 0644 "$fixture/cert.pem"
printf '127.0.0.1 localhost\n1.1.1.1 receiver.fixture\n' > "$fixture/hosts"
chmod 0644 "$fixture/hosts"
mount -t tmpfs -o mode=0755 tmpfs /usr/local/lib
lib_mounted=1
install -d -o root -g root -m 0755 /usr/local/lib/xcli
install -o root -g root -m 0755 "$repo/rewrite/rust/target/debug/xcli-webhook-sender" /usr/local/lib/xcli/xcli-webhook-sender
mount --bind "$fixture/hosts" /etc/hosts
hosts_mounted=1
mount --bind "$fixture/cert.pem" /etc/ssl/certs/ca-certificates.crt
cert_mounted=1
ip link set lo up
ip addr add 1.1.1.1/32 dev lo
cd "$repo"
runuser -u "$run_user" -- env XCLI_PANEL_SERVICE="$repo/rewrite/rust/target/debug/xcli-panel-service" \
  XCLI_TEST_NOTIFY_CERT="$fixture/cert.pem" XCLI_TEST_NOTIFY_KEY="$fixture/key.pem" XCLI_TEST_HOST_NET_NS="$(readlink /proc/1/ns/net)" \
  python3 -m unittest discover -s tests/rewrite -p test_notification_e2e.py -v
