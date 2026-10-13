#!/usr/bin/env bash
set -euo pipefail
python3 - <<'PY'
from pathlib import Path
p=Path('/etc/letsencrypt/renewal/gateway.example.com.conf')
original=p.read_text();account=next(x.split('=',1)[1].strip() for x in original.splitlines() if x.startswith('account ='))
p.write_text('''version = 4.0.0
archive_dir = /etc/letsencrypt/archive/gateway.example.com
cert = /etc/letsencrypt/live/gateway.example.com/cert.pem
privkey = /etc/letsencrypt/live/gateway.example.com/privkey.pem
chain = /etc/letsencrypt/live/gateway.example.com/chain.pem
fullchain = /etc/letsencrypt/live/gateway.example.com/fullchain.pem
[renewalparams]
account = '''+account+'''
authenticator = webroot
server = https://acme-v02.api.letsencrypt.org/directory
key_type = ecdsa
webroot_path = /var/www/acme,
[[webroot_map]]
gateway.example.com = /var/www/acme
''')
p.chmod(0o600)
PY
install -d -m755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/xray-gateway-nginx <<'EOF'
#!/bin/sh
set -eu
/usr/sbin/nginx -t
/bin/systemctl reload nginx
EOF
chmod 755 /etc/letsencrypt/renewal-hooks/deploy/xray-gateway-nginx
systemctl enable --now certbot.timer
certbot certificates --cert-name gateway.example.com
