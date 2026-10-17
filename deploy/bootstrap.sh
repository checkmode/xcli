#!/usr/bin/env bash
set -euo pipefail
# Historical migration only; never overwrite a managed application release.
if [[ -L /opt/xcli/current ]]; then
    echo '部署已纳入完整版本管理；请使用 update.sh 或 xcli-release。' >&2
    exit 1
fi
[[ $EUID == 0 ]] || { echo 'Run with sudo'; exit 1; }
[[ $(uname -m) == aarch64 ]] || { echo 'Expected ARM64'; exit 1; }
backup=/root/xray-gateway-before-$(date -u +%Y%m%dT%H%M%SZ)
install -d -m700 "$backup"
iptables-save > "$backup/iptables.v4"
ip6tables-save > "$backup/iptables.v6"
[[ ! -d /etc/nginx ]] || cp -a /etc/nginx "$backup/"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends python3-fastapi python3-uvicorn python3-qrcode python3-pil python3-httpx python3-pytest nginx libnginx-mod-stream certbot unzip ca-certificates curl
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl --fail --location --retry 3 -o "$work/xray.zip" https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-arm64-v8a.zip
printf '%s  %s\n' 4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c "$work/xray.zip" | sha256sum -c -
unzip -q "$work/xray.zip" -d "$work/xray"
install -D -m755 "$work/xray/xray" /usr/local/lib/xray-gateway/xray
/usr/local/lib/xray-gateway/xray version
getent passwd xgateway >/dev/null || useradd --system --home /var/lib/xray-gateway --shell /usr/sbin/nologin xgateway
install -d -o xgateway -g xgateway -m700 /var/lib/xray-gateway
install -d -o root -g xgateway -m750 /etc/xray-gateway
install -d -m755 /opt/xray-gateway /var/www/acme
printf 'Bootstrap complete. Backup: %s\n' "$backup"
