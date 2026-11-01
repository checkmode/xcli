#!/usr/bin/env python3
"""Verify the occupied-443 installation and rollback on a disposable CI host."""
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import subprocess
import urllib.request

assert os.environ.get('GITHUB_ACTIONS') == 'true', 'Only run on a disposable CI host'
temp = Path(os.environ['RUNNER_TEMP'])
baseline_config = (temp / 'nginx-before.sha256').read_text().strip()
baseline_pid = (temp / 'rdh-before.pid').read_text().strip()


def fixture_unchanged():
    subprocess.run(['systemctl', 'is-active', '--quiet', 'xcli-fixture-rdh'], check=True)
    assert subprocess.check_output(['systemctl', 'show', 'xcli-fixture-rdh', '-p', 'MainPID', '--value'], text=True).strip() == baseline_pid
    assert hashlib.sha256(Path('/etc/nginx/nginx.conf').read_bytes()).hexdigest() == baseline_config


fixture_unchanged()
settings = json.loads(Path('/etc/xray-gateway/settings.json').read_text())
assert settings['public_port'] == 1443 and settings['hysteria2_port'] == 1443
assert settings['origin'] == 'https://panel.install.example:1443'
assert Path('/etc/nginx/xcli.conf').is_file()
subprocess.run(['nginx', '-t', '-c', '/etc/nginx/xcli.conf'], check=True)
subprocess.run(['xcli-release', 'check'], check=True)
fields = dict(line.split(': ', 1) for line in Path('/etc/xray-gateway/initial-admin.txt').read_text().splitlines())
assert fields['URL'] == settings['origin'] + '/'
client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
request = urllib.request.Request(settings['origin'] + '/api/login',
    data=json.dumps({'username': 'admin', 'password': fields['Password']}).encode(),
    headers={'Content-Type': 'application/json', 'Origin': settings['origin']})
with client.open(request, timeout=15) as response:
    assert response.status == 200 and json.load(response).get('csrf')
with client.open(settings['origin'] + '/api/overview', timeout=15) as response:
    overview = json.load(response)
    assert overview['server']['transports'] == ['reality', 'websocket', 'hysteria2']
    assert overview['monitor']['status'] == 'healthy'
fixture_unchanged()
rollback = sorted(Path('/var/backups/xcli/install').glob('*/rollback.sh'))[-1]
subprocess.run(['sh', str(rollback)], check=True)
fixture_unchanged()
assert not Path('/etc/systemd/system/nginx.service.d/90-xcli.conf').exists()
assert subprocess.run(['systemctl', 'is-active', '--quiet', 'nginx']).returncode != 0
print('Independent 443 service and its config survived installation, all three probes, and rollback.')
