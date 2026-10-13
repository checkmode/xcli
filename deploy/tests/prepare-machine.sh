#!/usr/bin/env bash
set -euo pipefail
: "${GITHUB_ACTIONS:?This fixture is restricted to disposable CI machines}"
# Only the disposable GitHub runner is modified by this test fixture.
sudo systemctl disable --now nginx 2>/dev/null || true
if dpkg-query -W nginx >/dev/null 2>&1; then sudo apt-get purge -y nginx nginx-common; fi
sudo rm -rf /etc/nginx
fixture=$(mktemp -d /var/tmp/xcli-cert.XXXXXXXX)
chmod 755 "$fixture"
printf 'FIXTURE=%s\n' "$fixture" >> "$GITHUB_ENV"
public_ip=$(curl -q -4 -fsS --retry 3 --max-time 20 https://api.ipify.org)
printf 'PUBLIC_IP=%s\n' "$public_ip" >> "$GITHUB_ENV"
printf '%s panel.install.example\n' "$public_ip" | sudo tee -a /etc/hosts >/dev/null
sudo ip addr add "$public_ip/32" dev lo
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3 -subj /CN=Xcli-Install-Test-CA \
  -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$fixture/ca.key" -out "$fixture/ca.crt"
openssl req -newkey rsa:2048 -nodes -sha256 -subj /CN=panel.install.example \
  -keyout "$fixture/server.key" -out "$fixture/server.csr"
printf 'subjectAltName=DNS:panel.install.example\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' > "$fixture/extensions"
openssl x509 -req -in "$fixture/server.csr" -CA "$fixture/ca.crt" -CAkey "$fixture/ca.key" \
  -CAcreateserial -days 3 -sha256 -extfile "$fixture/extensions" -out "$fixture/server.crt"
sudo cp "$fixture/ca.crt" /usr/local/share/ca-certificates/xcli-install-test.crt
sudo update-ca-certificates
