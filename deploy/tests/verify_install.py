#!/usr/bin/env python3
"""Post-install smoke check, only for disposable CI machines (requires root)."""
import contextlib
import hashlib
import http.cookiejar
import json
import pathlib
import sqlite3
import subprocess
import urllib.request


def main():
    credential = pathlib.Path('/root/xray-gateway-admin.txt')
    fields = dict(line.split(': ', 1) for line in credential.read_text().splitlines())
    settings = json.loads(pathlib.Path('/etc/xray-gateway/settings.json').read_text())
    domain = settings['domain']
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in
              (credential, pathlib.Path('/etc/xray-gateway/settings.json'), pathlib.Path('/etc/xray-gateway/security.key'))}
    assert credential.stat().st_mode & 0o777 == 0o600
    cookie = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(cookie))
    request = urllib.request.Request('https://' + domain + '/api/login',
        data=json.dumps({'username': 'admin', 'password': fields['Password']}).encode(),
        headers={'Content-Type': 'application/json', 'Origin': 'https://' + domain})
    with client.open(request, timeout=15) as response:
        login = json.load(response)
        assert response.status == 200 and login.get('csrf')
    with client.open('https://' + domain + '/api/overview', timeout=15) as response:
        assert response.status == 200
    assert any(item.secure for item in cookie)
    with contextlib.closing(sqlite3.connect('/var/lib/xray-gateway/gateway.sqlite')) as db:
        assert db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
        assert db.execute('SELECT count(*) FROM users').fetchone()[0] == 0
        assert db.execute('SELECT enabled FROM mfa').fetchone()[0] == 0
        assert db.execute('SELECT enabled FROM notification_config').fetchone()[0] == 0
    result = subprocess.run(['bash', 'install.sh', '--yes'], capture_output=True)
    assert result.returncode != 0 and '已有配置' in result.stderr.decode()
    for name, digest in before.items():
        assert hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() == digest
    subprocess.run(['python3', '/opt/xray-gateway/scripts/gatewayctl.py', 'status'], check=True)
    print('Initial administrator login, HTTPS cookie, database, disabled-by-default features, recovery tool and repeat-install refusal passed.')
    rollback = sorted(pathlib.Path('/root').glob('xcli-install-*/rollback.sh'))[-1]
    subprocess.run(['sh', str(rollback)], check=True)
    for service in ('xray-gateway-panel', 'xray-gateway-core', 'xray-gateway-monitor', 'xray-gateway-firewall', 'nginx'):
        assert subprocess.run(['systemctl', 'is-active', '--quiet', service]).returncode != 0
    for chain in ('XG_IN', 'XG_OUT'):
        assert subprocess.run(['iptables', '-w', '-S', chain], capture_output=True).returncode != 0
    for name, digest in before.items():
        assert hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() == digest
    print('Rollback stopped only the new services, removed owned firewall chains and retained credentials and settings.')


if __name__ == '__main__':
    main()
