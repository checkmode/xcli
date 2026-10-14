#!/usr/bin/env python3
"""Install or expand country pools while retaining original paths, exits and users."""
import argparse
import copy
import fcntl
import http.client
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import time

from residential import private_write, replace, run

REGISTRY = [
    ('US', '美国', '北美', 'residential-11', 10110, 10120),
    ('JP', '日本', '亚洲', 'residential-12', 10111, 10121),
    ('SG', '新加坡', '亚洲', 'residential-13', 10112, 10122),
    ('ZZ', '全球', '全球', 'residential-14', 10113, 10123),
    ('HK', '香港', '亚洲', 'residential-15', 10200, 10300),
    ('TW', '台湾', '亚洲', 'residential-16', 10201, 10301),
    ('KR', '韩国', '亚洲', 'residential-17', 10202, 10302),
    ('TH', '泰国', '亚洲', 'residential-18', 10203, 10303),
    ('MY', '马来西亚', '亚洲', 'residential-19', 10204, 10304),
    ('IN', '印度', '亚洲', 'residential-20', 10205, 10305),
    ('CA', '加拿大', '北美', 'residential-21', 10206, 10306),
    ('GB', '英国', '欧洲', 'residential-22', 10207, 10307),
    ('DE', '德国', '欧洲', 'residential-23', 10208, 10308),
    ('FR', '法国', '欧洲', 'residential-24', 10209, 10309),
    ('NL', '荷兰', '欧洲', 'residential-25', 10210, 10310),
    ('AU', '澳大利亚', '大洋洲', 'residential-26', 10211, 10311),
]
REGIONS = [(row[0], row[1]) for row in REGISTRY]
SERVICE = 'xray-gateway-webshare'
LOCATIONS = Path('/etc/nginx/xcli-webshare-locations.conf')
FILES = {
    'settings.json': Path('/etc/xray-gateway/settings.json'),
    'core.json': Path('/etc/xray-gateway/core.json'),
    'nginx.conf': Path('/etc/nginx/nginx.conf'),
    'firewall.sh': Path('/opt/xray-gateway/deploy/firewall.sh'),
    'locations.conf': LOCATIONS,
    'webshare.py': Path('/opt/xray-gateway/scripts/webshare.py'),
    'webshare.service': Path('/etc/systemd/system/xray-gateway-webshare.service'),
}
ALLOW = ['-d', '127.0.0.1/32', '-p', 'tcp', '-m', 'multiport', '--dports', '10120:10123,10300:10311', '-j', 'RETURN']

LEGACY_ALLOW = ['-d', '127.0.0.1/32', '-p', 'tcp', '-m', 'multiport', '--dports', '10120,10121,10122,10123', '-j', 'RETURN']

def configure(settings, core, nginx, firewall, expand=False):
    settings, core = copy.deepcopy(settings), copy.deepcopy(core)
    exits = settings.setdefault('residential_exits', [])
    if len(exits) > 40 or (any(e.get('dynamic') for e in exits) and not expand):
        raise ValueError('Dynamic entrances already exist; use expand')
    if not re.fullmatch(r'/connect/[A-Za-z0-9_-]+', settings['ws_path']):
        raise ValueError('Unexpected existing WebSocket path')
    tags = {item['tag'] for item in core['inbounds']} | {item['tag'] for item in core['outbounds']}
    ports = {item.get('port') for item in core['inbounds']}
    rules = core['routing']['rules']
    # Existing generic routing must not consume the new entrances before their own rules.
    for rule in rules:
        if not rule.get('inboundTag') and not (rule.get('ip') and rule.get('outboundTag') == 'blocked'):
            raise ValueError('Custom catch-all routing requires review before installation')
    locations, added = [], []
    for country, label, group, tag, port, upstream in REGISTRY:
        path = settings['ws_path'] + '/' + tag
        previous = next((e for e in exits if e['tag'] == tag), None)
        if previous:
            if not expand or not previous.get('dynamic') or previous['country'] != country or previous['port'] != port or previous['ws_path'] != path:
                raise ValueError('Existing dynamic entrance differs from the supported registry')
        elif tag in tags or tag + '-exit' in tags or port in ports:
            raise ValueError('Reserved dynamic tag or port is already in use')
        if not previous:
            exits.append({'tag': tag, 'label': '动态住宅 · ' + label, 'country': country,
                'exit_ip': '', 'ws_path': path, 'port': port, 'dynamic': True})
            core['inbounds'].append({'tag': tag, 'listen': '127.0.0.1', 'port': port, 'protocol': 'vless',
                'settings': {'clients': [], 'decryption': 'none'},
                'streamSettings': {'network': 'ws', 'wsSettings': {'path': path}}})
            core['outbounds'].append({'tag': tag + '-exit', 'protocol': 'socks',
                'settings': {'servers': [{'address': '127.0.0.1', 'port': upstream}]}})
            added.append(tag)
        locations.append(f'''location = {path} {{
    proxy_pass http://127.0.0.1:{port};
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $host;
    proxy_read_timeout 600s;
    proxy_send_timeout 600s;
    proxy_buffering off;
}}''')
    if not added:
        raise ValueError('All country entrances are already installed')
    if len(exits) > 40:
        raise ValueError('Too many fixed and dynamic entrances')
    rules.append({'type': 'field', 'inboundTag': added, 'network': 'udp', 'outboundTag': 'blocked'})
    rules.extend({'type': 'field', 'inboundTag': [tag], 'network': 'tcp', 'outboundTag': tag + '-exit'} for tag in added)
    marker = 'location = ' + settings['ws_path'] + ' {'
    if nginx.count(marker) != 1 or nginx.count(str(LOCATIONS)) != (1 if expand else 0):
        raise ValueError('Cannot uniquely identify the TLS WebSocket location')
    if not expand:
        nginx = nginx.replace(marker, 'include ' + str(LOCATIONS) + ';\n        ' + marker, 1)
    marker = '    for net in '
    old_line = '    iptables -w -A XG_OUT ' + ' '.join(LEGACY_ALLOW) + '\n'
    if expand:
        if firewall.count(old_line) != 1:
            raise ValueError('Expected original four-country firewall rule')
        firewall = firewall.replace(old_line, '', 1)
    if firewall.count(marker) != 1 or '10120:10123,10300:10311' in firewall:
        raise ValueError('Unexpected existing firewall layout')
    firewall = firewall.replace(marker, '    iptables -w -A XG_OUT ' + ' '.join(ALLOW) + '\n' + marker, 1)
    return settings, core, nginx, firewall, '\n'.join(locations) + '\n'


def preflight():
    return json.loads(run('/usr/local/lib/xray-gateway/panel-current', '--secret-key',
        '/etc/xray-gateway/security.key', '--monitor-config', '/etc/xcli-monitor/monitor.json', '--preflight'))


def wait_ready(since):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        try:
            state = preflight()
            report = json.loads(Path('/var/lib/xray-gateway-monitor/report.json').read_text())
            if state['database_integrity'] == 'ok' and state['pending_additions'] == state['pending_revocations'] == 0 and report['updated'] >= since and report['status'] == 'healthy':
                for port in [row[4] for row in REGISTRY]:
                    with socket.create_connection(('127.0.0.1', port), timeout=1):
                        pass
                for port in [row[5] for row in REGISTRY]:
                    with socket.create_connection(('127.0.0.1', port), timeout=1) as conn:
                        conn.sendall(b'\x05\x01\x00')
                        if conn.recv(2) != b'\x05\x00':
                            raise ValueError('SOCKS listener not ready')
                return
        except (OSError, ValueError, KeyError, RuntimeError):
            pass
        time.sleep(2)
    raise RuntimeError('Existing exits or new loopback listeners did not become healthy')


def rollback(backup):
    manifest = json.loads((backup / 'manifest.json').read_text())
    for name, allowed in manifest['allowed_sha256'].items():
        if hashlib.sha256(FILES[name].read_bytes()).hexdigest() not in allowed:
            raise ValueError('Configuration changed after installation; review before rollback: ' + name)
    subprocess.run(['systemctl', 'stop', SERVICE], capture_output=True)
    if 'webshare.service' not in manifest['existing']:
        subprocess.run(['systemctl', 'disable', SERVICE], capture_output=True)
    run('systemctl', 'stop', 'xray-gateway-monitor', 'xray-gateway-panel')
    for name, path in FILES.items():
        if name in manifest['existing']:
            if path.exists():
                replace(path, (backup / name).read_bytes(), backup / name)
            else:
                info = (backup / name).stat()
                private_write(path, (backup / name).read_bytes(), info.st_mode & 0o777, (info.st_uid, info.st_gid))
        else:
            path.unlink(missing_ok=True)
    subprocess.run(['iptables', '-w', '-D', 'XG_OUT', *manifest.get('installed_allow', ALLOW)], capture_output=True)
    if manifest.get('expanded'):
        if subprocess.run(['iptables', '-w', '-C', 'XG_OUT', *LEGACY_ALLOW], capture_output=True).returncode:
            run('iptables', '-w', '-I', 'XG_OUT', '1', *LEGACY_ALLOW)
    run('systemctl', 'daemon-reload')
    if 'webshare.service' in manifest['existing']:
        run('systemctl', 'start', SERVICE)
    run('nginx', '-t')
    run('systemctl', 'restart', 'xray-gateway-core')
    run('systemctl', 'start', 'xray-gateway-panel')
    run('systemctl', 'reload', 'nginx')
    run('systemctl', 'start', 'xray-gateway-monitor')
    print('Dynamic entrances removed; original routes, current users and traffic retained. Encrypted pool state retained.')


def install(args):
    if args.backup.parent != Path('/root') or args.backup.exists():
        raise ValueError('Use a new backup directory directly under /root')
    expanding = args.action == 'expand'
    present = [FILES[name].exists() for name in ('locations.conf', 'webshare.py', 'webshare.service')]
    if (not expanding and any(present)) or (expanding and not all(present)):
        raise ValueError('Use install for a new pool or expand for an existing four-country pool')
    for service in ('xray-gateway-core', 'xray-gateway-panel', 'xray-gateway-monitor', 'nginx'):
        run('systemctl', 'is-active', '--quiet', service)
    import cryptography.hazmat.primitives.ciphers.aead  # Fail before changing state if dependency is missing.
    connection = http.client.HTTPConnection('127.0.0.1', 8080, timeout=3)
    try:
        connection.request('GET', '/api/webshare')
        if connection.getresponse().status != 401:
            raise ValueError('Update the management panel before installing the pool')
    finally:
        connection.close()
    state = preflight()
    if state['database_integrity'] != 'ok' or state['pending_additions'] or state['pending_revocations']:
        raise ValueError('Existing core account synchronization is not settled')
    for port in [p for row in (REGISTRY[4:] if expanding else REGISTRY) for p in row[4:6]]:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', port))
    old = {name: path.read_bytes() for name, path in FILES.items() if path.exists()}
    if any(path.is_symlink() for path in FILES.values()):
        raise ValueError('Customized file symlinks require review')
    settings, core, nginx, firewall, locations = configure(json.loads(old['settings.json']), json.loads(old['core.json']), old['nginx.conf'].decode(), old['firewall.sh'].decode(), expand=expanding)
    args.backup.mkdir(mode=0o700)
    for name in old:
        shutil.copy2(FILES[name], args.backup / name)
        info = FILES[name].stat()
        os.chown(args.backup / name, info.st_uid, info.st_gid)
    generated = {'settings.json': json.dumps(settings).encode(), 'core.json': json.dumps(core).encode(),
                 'nginx.conf': nginx.encode(), 'firewall.sh': firewall.encode()}
    allowed = {name: [hashlib.sha256(old[name]).hexdigest(), hashlib.sha256(value).hexdigest()] for name, value in generated.items()}
    private_write(args.backup / 'manifest.json', json.dumps({'existing': list(old), 'allowed_sha256': allowed, 'expanded': expanding, 'installed_allow': ALLOW}))
    for helper in ('webshare-pool.py', 'residential.py'):
        shutil.copy2(args.source / 'deploy' / helper, args.backup / helper)
    private_write(args.backup / 'rollback.sh', '#!/bin/sh\nset -eu\nexec python3 "$(dirname "$0")/webshare-pool.py" rollback "$(dirname "$0")"\n', 0o700)
    with sqlite3.connect('/var/lib/xray-gateway/gateway.sqlite') as db, sqlite3.connect(args.backup / 'gateway.sqlite') as snapshot:
        db.backup(snapshot)
    (args.backup / 'gateway.sqlite').chmod(0o600)
    private_write(args.backup / 'core.candidate.json', json.dumps(core))
    private_write(args.backup / 'locations.candidate.conf', locations)
    private_write(args.backup / 'nginx.candidate.conf', nginx.replace(str(LOCATIONS), str(args.backup / 'locations.candidate.conf')))
    run('/usr/local/lib/xray-gateway/xray', 'run', '-test', '-config', args.backup / 'core.candidate.json')
    run('nginx', '-t', '-c', args.backup / 'nginx.candidate.conf')
    run('sh', '-n', FILES['firewall.sh'])
    owner = pwd.getpwnam('xgateway')
    directory = Path('/var/lib/xray-gateway/webshare')
    directory.mkdir(mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    os.chown(directory, owner.pw_uid, owner.pw_gid)
    try:
        private_write(FILES['webshare.py'], (args.source / 'scripts/webshare.py').read_bytes(), 0o644)
        private_write(FILES['webshare.service'], (args.source / 'deploy/xray-gateway-webshare.service').read_bytes(), 0o644)
        replace(FILES['firewall.sh'], firewall)
        run('iptables', '-w', '-I', 'XG_OUT', '1', *ALLOW)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', SERVICE)
        run('systemctl', 'stop', 'xray-gateway-monitor', 'xray-gateway-panel')
        replace(FILES['settings.json'], json.dumps(settings))
        replace(FILES['core.json'], json.dumps(core))
        run('systemctl', 'restart', SERVICE)
        if expanding:
            run('iptables', '-w', '-D', 'XG_OUT', *LEGACY_ALLOW)
        private_write(LOCATIONS, locations, 0o644)
        replace(FILES['nginx.conf'], nginx)
        run('nginx', '-t')
        since = int(time.time())
        run('systemctl', 'restart', 'xray-gateway-core')
        run('systemctl', 'start', 'xray-gateway-panel')
        run('systemctl', 'reload', 'nginx')
        time.sleep(6)
        run('systemctl', 'start', 'xray-gateway-monitor')
        wait_ready(since)
    except Exception:
        rollback(args.backup)
        raise
    print(json.dumps({'dynamic_entrances': len(REGISTRY), 'countries': [row[0] for row in REGISTRY],
        'existing_exits_preserved': True, 'api_key_required': True, 'rollback': str(args.backup / 'rollback.sh')}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for action in ('install', 'expand'):
        add = sub.add_parser(action)
        add.add_argument('--source', type=Path, required=True)
        add.add_argument('--backup', type=Path, required=True)
    sub.add_parser('rollback').add_argument('backup', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run with sudo')
    try:
        with open('/run/lock/xcli-update.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            rollback(args.backup) if args.action == 'rollback' else install(args)
    except Exception as error:
        # No provider keys or core JSON may be printed.
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
