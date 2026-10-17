#!/usr/bin/env python3
"""Install and roll back a residential fixture only on disposable CI servers."""
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request

SOURCE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE / 'cpp/tests'))
from migration_state import snapshot


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.geteuid() != 0:
        raise SystemExit('This fixture is only for root on disposable GitHub Actions machines')
    settings_path = Path('/etc/xray-gateway/settings.json')
    before_settings = settings_path.read_bytes()
    settings = json.loads(before_settings)
    reservations = []
    ports = []
    for _ in range(10):
        sock = socket.socket()
        sock.bind((settings['public_ip'], 0))
        ports.append(sock.getsockname()[1])
        reservations.append(sock)
    backup_base = Path('/var/backups/xcli/configuration') if Path('/opt/xcli/current').is_symlink() else Path('/root')
    backup = backup_base / 'xcli-residential-ci'
    root = Path('/root/xcli-residential-fixture')
    root.mkdir(mode=0o700)
    upstream = root / 'upstream.json'
    upstream.write_text(json.dumps({'log': {'loglevel': 'none'},
        'inbounds': [{'listen': settings['public_ip'], 'port': port, 'protocol': 'socks',
                      'settings': {'auth': 'password', 'accounts': [{'user': 'fixture-user', 'pass': 'fixture-password'}]}} for port in ports],
        'outbounds': [{'protocol': 'freedom', 'streamSettings': {'sockopt': {'domainStrategy': 'UseIPv4'}}}]}))
    upstream.chmod(0o600)
    pool = root / 'proxies.json'
    pool.write_text(json.dumps({'proxies': [{'tag': f'residential-{index:02d}', 'address': settings['public_ip'], 'port': port,
                                         'username': 'fixture-user', 'password': 'fixture-password', 'country': 'US'} for index, port in enumerate(ports, 1)]}))
    pool.chmod(0o600)
    db = Path('/var/lib/xray-gateway/gateway.sqlite')
    before = snapshot(db, settings_path)
    nginx_pid = subprocess.check_output(['systemctl', 'show', 'nginx', '-p', 'MainPID', '--value'])
    base = settings['origin']
    fields = dict(line.split(': ', 1) for line in Path('/root/xray-gateway-admin.txt').read_text().splitlines())
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))
    def api(path, data=None, csrf=None):
        headers = {'Origin': base}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        if csrf:
            headers['X-CSRF-Token'] = csrf
        request = urllib.request.Request(base + '/api/' + path, data=None if data is None else json.dumps(data).encode(), headers=headers)
        with client.open(request, timeout=10) as response:
            return json.load(response)
    auth = api('login', {'username': 'admin', 'password': fields['Password']})
    users = api('overview')['users']
    assert users, 'Seed upgrade users before this test'
    uid = next(u['id'] for u in users if u['status'] == 'active')
    links = api('users/' + uid + '/links')
    for sock in reservations:
        sock.close()
    process = subprocess.Popen(['/usr/local/lib/xray-gateway/xray', 'run', '-config', str(upstream)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    exceptions = []
    try:
        # The disposable fixture uses this VM's public IP on loopback. The
        # gateway deliberately rejects LOCAL destinations; allow only these
        # authenticated test ports, and remove every exception afterwards.
        for port in ports:
            rule = ['-d', settings['public_ip'] + '/32', '-p', 'tcp', '--dport', str(port),
                    '-m', 'comment', '--comment', 'xcli-residential-ci', '-j', 'RETURN']
            subprocess.run(['iptables', '-w', '-I', 'XG_OUT', '1', *rule], check=True)
            exceptions.append(rule)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                for port in ports:
                    with socket.create_connection((settings['public_ip'], port), timeout=.2):
                        pass
                break
            except OSError:
                assert process.poll() is None
                time.sleep(.1)
        subprocess.run(['python3', str(SOURCE / 'deploy/residential.py'), 'install', '--source', str(SOURCE),
                        '--pool', str(pool), '--backup', str(backup)], check=True)
        nodes = api('users/' + uid + '/links')
        for name, value in links.items():
            assert nodes[name] == value, 'Existing client links changed'
        with client.open(nodes['subscription'], timeout=10) as response:
            encoded = response.read()
        import base64
        subscription = base64.b64decode(encoded).decode()
        assert len(subscription.splitlines()) == 13
        assert all(nodes[f'residential-{index:02d}'] in subscription for index in range(1, 11))
        assert 'fixture-user' not in subscription and 'fixture-password' not in subscription
        now = snapshot(db, settings_path)
        for name in ('identity_digest', 'admin_digest', 'security'):
            assert now[name] == before[name], name + ' changed'
        for uid, values in before['traffic'].items():
            assert all(a >= b for a, b in zip(now['traffic'][uid], values))
        report = api('overview')['monitor']
        residential = next(row for row in report['checks'] if row['transport'] == 'residential-01')
        assert residential['status'] == 'healthy' and residential['doh_ms'] is not None and residential['udp_supported'] is False
        assert len(report['checks']) == 13 and all(row['status'] == 'healthy' for row in report['checks'])
        subprocess.run(['bash', str(backup / 'rollback.sh')], check=True)
        assert settings_path.read_bytes() == before_settings
        assert api('session')['csrf'] == auth['csrf'], 'Existing login session changed'
        assert subprocess.check_output(['systemctl', 'show', 'nginx', '-p', 'MainPID', '--value']) == nginx_pid
        assert not Path('/etc/xray-gateway/residential-proxies.json').exists()
        print('Real residential installation, private credentials, fixed exit, DoH, user preservation and rollback verified.')
    finally:
        for rule in exceptions:
            subprocess.run(['iptables', '-w', '-D', 'XG_OUT', *rule], check=True)
        api('logout', {}, auth['csrf'])
        process.terminate()
        process.wait(timeout=10)


if __name__ == '__main__':
    main()
