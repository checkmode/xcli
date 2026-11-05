#!/usr/bin/env bash
# Exercise the experimental installer without changing host files or services.
set -euo pipefail
if [[ "${1:-}" != --inside ]]; then
  if [[ "$EUID" != 0 || ( "$#" != 4 && "$#" != 5 ) ]]; then
    echo 'usage: sudo bash run_fresh_install_namespace.sh REPO RELEASE NODE XRAY [GIT_CHECKOUT]' >&2
    exit 2
  fi
  for role in panel node replace; do
    unshare --mount --net --fork /bin/bash "$0" --inside "$1" "$2" "$3" "$4" "$role" "${5:-}"
  done
  exit
fi
if [[ "$EUID" != 0 || "$#" != 7 || "$(readlink /proc/self/ns/net)" == "$(readlink /proc/1/ns/net)" ||
      "$(readlink /proc/self/ns/mnt)" == "$(readlink /proc/1/ns/mnt)" ]]; then
  echo 'refusing to run outside private namespaces' >&2
  exit 2
fi
repo="$2" release="$3" node="$4" xray="$5" role="$6" checkout="$7"
iptables_binary="$(readlink -f "$(command -v iptables)")"
ip6tables_binary="$(readlink -f "$(command -v ip6tables)")"
mount --make-rprivate /
fixture="$(mktemp -d /var/tmp/xcli-fresh-ns.XXXXXXXX)"
cleanup() {
  for file in "$fixture"/*.pid; do
    [[ -f "$file" ]] || continue
    pid="$(cat "$file")"
    if [[ "$pid" =~ ^[0-9]+$ && "$(readlink "/proc/$pid/ns/net" 2>/dev/null || true)" == "$(readlink /proc/self/ns/net)" ]]; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  [[ "$fixture" == /var/tmp/xcli-fresh-ns.* ]] && rm -rf -- "$fixture"
}
trap cleanup EXIT
chmod 0755 "$fixture"
cp "$xray" "$fixture/xray"
cp "$node" "$fixture/node"
mkdir -p "$fixture/nginx/modules-enabled" "$fixture/ssl"
cp /etc/nginx/mime.types "$fixture/nginx/mime.types"
for module in /etc/nginx/modules-enabled/*.conf; do
  [[ -e "$module" ]] && cp -L "$module" "$fixture/nginx/modules-enabled/"
done
cp -a /etc/ssl/. "$fixture/ssl/"
cp /etc/ld.so.cache "$fixture/ld.so.cache"
for mountpoint in /etc /usr/local/lib /usr/local/sbin /var/lib /var/cache /var/backups /var/log /var/www /opt /run /sys/fs/cgroup; do
  mount -t tmpfs -o mode=0755 tmpfs "$mountpoint"
done
ip link set lo up
ip addr add 1.1.1.1/32 dev lo
ip -6 addr add 2001:db8::8/128 dev lo nodad
mkdir -p /etc/nginx /etc/ssl /etc/pam.d /etc/systemd/system /var/lib/nginx /var/log/nginx /var/www /run/systemd/system /sys/fs/cgroup/system.slice/xcli-core.service
mkdir -p /etc/alternatives
ln -s "$iptables_binary" /etc/alternatives/iptables
ln -s "$ip6tables_binary" /etc/alternatives/ip6tables
cp -a "$fixture/nginx/." /etc/nginx/
ln -s /usr/lib/nginx/modules /etc/nginx/modules
cp -a "$fixture/ssl/." /etc/ssl/
cp "$fixture/ld.so.cache" /etc/ld.so.cache
printf 'events {}\n' > /etc/nginx/nginx.conf
printf 'root:x:0:0:root:/root:/bin/sh\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n' > /etc/passwd
printf 'root:x:0:\nwww-data:x:33:\n' > /etc/group
printf 'root:!:19000:0:99999:7:::\nwww-data:!:19000:0:99999:7:::\n' > /etc/shadow
printf 'root:!::\nwww-data:!::\n' > /etc/gshadow
printf 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n' > /etc/nsswitch.conf
printf 'ID=ubuntu\nVERSION_ID=24.04\n' > /etc/os-release
printf '8.8.8.8 panel.example.com node.example.com\n' > /etc/hosts
printf '2001:db8::8 panel.example.com node.example.com\n' >> /etc/hosts
printf 'nameserver 1.1.1.1\n' > /etc/resolv.conf
printf 'auth sufficient pam_rootok.so\naccount sufficient pam_permit.so\nsession sufficient pam_permit.so\n' > /etc/pam.d/runuser
printf 'auth sufficient pam_rootok.so\naccount sufficient pam_permit.so\nsession sufficient pam_permit.so\n' > /etc/pam.d/runuser-l
if [[ -n "$checkout" && "$role" != replace ]]; then
  # A pristine system has no nginx configuration before the package is installed.
  mv /etc/nginx /etc/nginx.fixture
  check_args=(--role "$role" --yes --check --no-cache --no-email --agree-tos --public-ip 8.8.8.8)
  if [[ "$role" == panel ]]; then
    check_args+=(--domain panel.example.com)
  else
    check_args+=(--domain node.example.com --panel https://panel.example.com)
  fi
  if [[ -n "${XCLI_TEST_BOOTSTRAP_ARCHIVE:-}" ]]; then
    mkdir -p "$fixture/bin"
    cp "$repo/tests/rewrite/fixture-curl.sh" "$fixture/bin/curl"
    chmod 0755 "$fixture/bin/curl"
    PATH="$fixture/bin:$PATH" bash "$checkout/install.sh" "${check_args[@]}"
  else
    bash "$checkout/rewrite/install-experimental.sh" "${check_args[@]}"
  fi
  mv /etc/nginx.fixture /etc/nginx
fi
cd "$repo"
replace=0
if [[ "$role" == replace ]]; then role=panel; replace=1; fi
XCLI_TEST_FIXTURE="$fixture" XCLI_TEST_ROLE="$role" XCLI_TEST_RELEASE="$release" XCLI_TEST_NODE="$fixture/node" \
  XCLI_TEST_REPLACE="$replace" \
  PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m unittest discover -s tests/rewrite -p test_fresh_install_namespace.py -v
