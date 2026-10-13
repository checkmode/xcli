#!/usr/bin/env python3
"""Upgrade/rollback acceptance for the disposable CI machine only."""
import base64
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request

STATE = Path('/root/xcli-upgrade-test.json')
COOKIE = Path('/root/xcli-upgrade-cookie.txt')


def main():
    phase = sys.argv[1]
    settings = json.loads(Path('/etc/xray-gateway/settings.json').read_text())
    origin = settings['origin']
    cookies = http.cookiejar.LWPCookieJar(str(COOKIE))
    if COOKIE.exists():
        cookies.load(ignore_discard=True, ignore_expires=True)
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(cookies))
    state = json.loads(STATE.read_text()) if STATE.exists() else {}

    def request(path, method='GET', value=None):
        headers = {'Origin': origin, 'Content-Type': 'application/json'}
        if state.get('csrf'):
            headers['X-CSRF-Token'] = state['csrf']
        req = urllib.request.Request(origin + path, method=method,
            data=None if value is None else json.dumps(value).encode(), headers=headers)
        with client.open(req, timeout=15) as response:
            return response.read()

    def api(path, method='GET', value=None):
        return json.loads(request(path, method, value))

    def create(name):
        uid = api('/api/users', 'POST', {'name': name})['id']
        return {'id': uid, 'links': api('/api/users/' + uid + '/links')}

    if phase == 'seed':
        fields = dict(line.split(': ', 1) for line in Path('/root/xray-gateway-admin.txt').read_text().splitlines())
        state['csrf'] = api('/api/login', 'POST', {'username': 'admin', 'password': fields['Password']})['csrf']
        state['users'] = [create('before-upgrade-one'), create('before-upgrade-two')]
        state['settings'] = settings
        state['nginx_pid'] = subprocess.check_output(['systemctl', 'show', 'nginx', '-p', 'MainPID', '--value']).decode().strip()
        state['core_sha256'] = __import__('hashlib').sha256(Path('/usr/local/lib/xray-gateway/xray').read_bytes()).hexdigest()
        cookies.save(ignore_discard=True, ignore_expires=True)
        COOKIE.chmod(0o600)
    else:
        expected = {'reality', 'websocket', 'hysteria2'} if phase == 'upgraded' else {'reality', 'websocket'}
        deadline = time.monotonic() + 100
        while True:
            overview = api('/api/overview')
            report = overview['monitor']
            if report['status'] == 'healthy' and {item['transport'] for item in report['checks']} == expected:
                break
            assert time.monotonic() < deadline, 'Public entry self-tests failed after ' + phase
            time.sleep(2)
        assert api('/api/session')['csrf'] == state['csrf'], 'Existing browser session was lost'
        assert subprocess.check_output(['systemctl', 'show', 'nginx', '-p', 'MainPID', '--value']).decode().strip() == state['nginx_pid']
        for user in state['users']:
            links = api('/api/users/' + user['id'] + '/links')
            assert all(links[key] == user['links'][key] for key in ('reality', 'websocket', 'subscription'))
            path = user['links']['subscription'][len(origin):]
            subscription = base64.b64decode(request(path)).decode().splitlines()
            assert len(subscription) == len(expected)
            assert subscription[:2] == [links['reality'], links['websocket']]
            if phase == 'upgraded':
                assert links['hysteria2'].startswith('hysteria2://')
                assert subscription[2] == links['hysteria2']
        if phase == 'upgraded':
            assert settings == {**state['settings'], 'hysteria2_port': 443, 'xray_version': '26.10.10'}
            newest = create('created-after-upgrade')
            state['users'].append(newest)
            before_pid = subprocess.check_output(['systemctl', 'show', 'xray-gateway-core', '-p', 'MainPID', '--value'])
            api('/api/users/' + newest['id'], 'PUT', {'name': 'created-after-upgrade', 'enabled': False})
            deadline = time.monotonic() + 20
            while subprocess.check_output(['systemctl', 'show', 'xray-gateway-core', '-p', 'MainPID', '--value']) == before_pid:
                assert time.monotonic() < deadline, 'Controller could not revoke the capability-bearing core'
                time.sleep(.5)
            api('/api/users/' + newest['id'], 'PUT', {'name': 'created-after-upgrade', 'enabled': True})
            # The source credential and existing firewall restrictions stay in place.
            assert Path('/etc/xray-gateway/hysteria-tls/privkey.pem').stat().st_mode & 0o777 == 0o640
        else:
            assert phase == 'rolled-back'
            assert settings == state['settings']
            assert __import__('hashlib').sha256(Path('/usr/local/lib/xray-gateway/xray').read_bytes()).hexdigest() == state['core_sha256']
            assert not Path('/etc/xray-gateway/hysteria-tls').exists()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.bind(('0.0.0.0', 443))
            assert subprocess.run(['iptables', '-w', '-C', 'XG_IN', '-p', 'udp', '--dport', '443', '-j', 'ACCEPT'], capture_output=True).returncode != 0
    fd = os.open(STATE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(state, stream)
    print('Upgrade acceptance phase passed: ' + phase)


if __name__ == '__main__':
    main()
