#!/usr/bin/env python3
"""Add fixed TCP residential exits to an existing gateway without sharing upstream credentials."""
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import time

FILES = {
    'settings.json': Path('/etc/xray-gateway/settings.json'),
    'core.json': Path('/etc/xray-gateway/core.json'),
    'monitor.json': Path('/etc/xcli-monitor/monitor.json'),
    'nginx.conf': Path('/etc/nginx/nginx.conf'),
    'probe.py': Path('/opt/xray-gateway/scripts/probe.py'),
}
LOCATIONS = Path('/etc/nginx/xcli-residential-locations.conf')
PRIVATE_POOL = Path('/etc/xray-gateway/residential-proxies.json')
SERVICES = ['xray-gateway-panel', 'xray-gateway-core', 'xray-gateway-monitor']
COUNTRIES = {'JP': '日本', 'SG': '新加坡', 'US': '美国', 'ZZ': '未知地区'}


def private_write(path, value, mode=0o600, owner=None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(value.encode() if isinstance(value, str) else value)
        stream.flush()
        os.fsync(stream.fileno())
    if owner:
        os.chown(path, *owner)


def replace(path, value, original=None, mode=None):
    info = (original or path).stat()
    temporary = path.with_name(path.name + '.next-' + str(os.getpid()))
    try:
        private_write(temporary, value, mode if mode is not None else info.st_mode & 0o777, (info.st_uid, info.st_gid))
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def configure(settings, core, monitor, nginx, pool):
    """Pure generation: preserve original identities and block rules; add isolated WS routes."""
    settings, core, monitor = copy.deepcopy(settings), copy.deepcopy(core), copy.deepcopy(monitor)
    if settings.get('residential_exits') or any(x.get('tag', '').startswith('residential-') for x in core['inbounds']):
        raise ValueError('Residential exits already configured; refusing to replace them')
    if {x['tag'] for x in core['inbounds']} != {'reality', 'websocket', 'hysteria2'}:
        raise ValueError('Requires the standard three-inbound deployment')
    if not re.fullmatch(r'/connect/[A-Za-z0-9_-]+', settings['ws_path']):
        raise ValueError('Unexpected WebSocket path')
    proxies = pool.get('proxies')
    if not isinstance(proxies, list) or not 1 <= len(proxies) <= 20:
        raise ValueError('Provide 1..20 residential proxies')
    tags, peers, exits, locations = set(), set(), [], []
    for index, proxy in enumerate(proxies):
        if set(proxy) - {'tag', 'address', 'port', 'username', 'password', 'country'}:
            raise ValueError('Unsupported private proxy field')
        tag = proxy.get('tag')
        address = ipaddress.ip_address(proxy['address'])
        port = proxy['port']
        country = proxy.get('country', 'ZZ')
        if (not isinstance(tag, str) or not re.fullmatch(r'residential-[0-9]{2}', tag) or tag in tags or
            address.version != 4 or not address.is_global or address.is_multicast or
            type(port) is not int or not 1 <= port <= 65535 or (str(address), port) in peers or
            not isinstance(country, str) or not re.fullmatch(r'[A-Z]{2}', country)):
            raise ValueError('Invalid or duplicate proxy endpoint metadata')
        for field in ('username', 'password'):
            if not isinstance(proxy.get(field), str) or not 1 <= len(proxy[field].encode()) <= 255:
                raise ValueError('Invalid proxy authentication field')
        tags.add(tag)
        peers.add((str(address), port))
        local_port = 10100 + index
        path = settings['ws_path'] + '/' + tag
        label = '住宅' + tag[-2:] + ' · ' + COUNTRIES.get(country, country)
        exits.append({'tag': tag, 'label': label, 'exit_ip': str(address), 'country': country, 'ws_path': path, 'port': local_port})
        core['inbounds'].append({'tag': tag, 'listen': '127.0.0.1', 'port': local_port, 'protocol': 'vless',
            'settings': {'clients': [], 'decryption': 'none'},
            'streamSettings': {'network': 'ws', 'wsSettings': {'path': path}}})
        core['outbounds'].append({'tag': tag + '-exit', 'protocol': 'socks', 'settings': {'servers': [
            {'address': str(address), 'port': port, 'users': [{'user': proxy['username'], 'pass': proxy['password']}]}]}})
        locations.append(f'''location = {path} {{
    proxy_pass http://127.0.0.1:{local_port};
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_set_header Host $host;
    proxy_read_timeout 600s;
    proxy_send_timeout 600s;
    proxy_buffering off;
}}''')
    rules = core['routing']['rules']
    if any(rule.get('outboundTag') != 'blocked' or not rule.get('ip') for rule in rules):
        raise ValueError('Unexpected pre-existing routing rules; review before adding exits')
    rules.append({'type': 'field', 'inboundTag': sorted(tags), 'network': 'udp', 'outboundTag': 'blocked'})
    rules.extend({'type': 'field', 'inboundTag': [entry['tag']], 'network': 'tcp', 'outboundTag': entry['tag'] + '-exit'} for entry in exits)
    marker = 'location = ' + settings['ws_path'] + ' {'
    if nginx.count(marker) != 1 or str(LOCATIONS) in nginx:
        raise ValueError('Could not identify the existing TLS WebSocket location')
    nginx = nginx.replace(marker, 'include ' + str(LOCATIONS) + ';\n        ' + marker, 1)
    settings['residential_exits'] = exits
    monitor['residential_exits'] = exits
    return settings, core, monitor, nginx, '\n'.join(locations) + '\n'


def run(*args, timeout=90):
    result = subprocess.run(list(map(str, args)), capture_output=True, timeout=timeout)
    if result.returncode:
        # Keep upstream credentials and configuration excerpts out of tool/chat output.
        raise RuntimeError(str(args[0]) + ' failed during residential deployment')
    return result.stdout


def wait_ready(expected_tags, since):
    deadline = time.monotonic() + 100
    while time.monotonic() < deadline:
        try:
            report = json.loads(Path('/var/lib/xray-gateway-monitor/report.json').read_text())
            if report['updated'] >= since and {r['transport'] for r in report['checks']} == expected_tags:
                if report['status'] != 'healthy':
                    raise RuntimeError('A public node verification failed; reverting configuration')
                return
        except (OSError, KeyError, ValueError):
            pass
        time.sleep(1)
    raise RuntimeError('Fresh verification for every node did not arrive')


def rollback(backup):
    for name, path in FILES.items():
        if name == 'probe.py' and Path('/opt/xcli/current').is_symlink():
            continue
        replace(path, (backup / name).read_bytes(), backup / name)
    LOCATIONS.unlink(missing_ok=True)
    PRIVATE_POOL.unlink(missing_ok=True)
    run('systemctl', 'stop', 'xray-gateway-monitor')
    since = int(time.time())
    run('systemctl', 'restart', 'xray-gateway-core')
    run('systemctl', 'restart', 'xray-gateway-panel')
    run('nginx', '-t')
    run('systemctl', 'reload', 'nginx')
    time.sleep(6)
    run('systemctl', 'start', 'xray-gateway-monitor')
    wait_ready({'reality', 'websocket', 'hysteria2'}, since)
    print('Previous three-node configuration restored and healthy; current database and accumulated traffic retained.')


def install(args):
    managed = Path('/opt/xcli/current').is_symlink()
    if managed and FILES['probe.py'].read_bytes() != (args.source / 'scripts/probe.py').read_bytes():
        raise ValueError('先通过 update.sh 发布匹配的完整应用版本，再调整住宅入口配置')
    allowed = [Path('/var/backups/xcli/configuration')] + ([] if managed else [Path('/root')])
    if args.backup.parent not in allowed or args.backup.exists() or LOCATIONS.exists() or PRIVATE_POOL.exists():
        raise ValueError('Use a new /var/backups/xcli/configuration backup directory; existing configuration cannot be replaced')
    if args.pool.stat().st_mode & 0o077:
        raise ValueError('Private proxy input must have mode 0600')
    ready = time.monotonic() + 20
    while time.monotonic() < ready:
        if all(subprocess.run(['systemctl', 'is-active', '--quiet', service], capture_output=True).returncode == 0 for service in SERVICES + ['nginx']):
            break
        time.sleep(1)
    else:
        raise ValueError('Existing services did not become active; deployment stopped')
    old = {name: path.read_bytes() for name, path in FILES.items()}
    if any(path.is_symlink() for path in FILES.values()):
        raise ValueError('Deployment files must be regular files; review customized links first')
    pool = json.loads(args.pool.read_text())
    configured = configure(json.loads(old['settings.json']), json.loads(old['core.json']), json.loads(old['monitor.json']), old['nginx.conf'].decode(), pool)
    new_settings, new_core, new_monitor, nginx, locations = configured
    for entry in new_settings['residential_exits']:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', entry['port']))
    args.backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.backup.mkdir(mode=0o700)
    for name, path in FILES.items():
        shutil.copy2(path, args.backup / name)
        info = path.stat()
        os.chown(args.backup / name, info.st_uid, info.st_gid)
    with sqlite3.connect('/var/lib/xray-gateway/gateway.sqlite') as db, sqlite3.connect(args.backup / 'gateway.sqlite') as snapshot:
        db.backup(snapshot)
    (args.backup / 'gateway.sqlite').chmod(0o600)
    for name, value in [('core.candidate.json', new_core), ('settings.candidate.json', new_settings), ('monitor.candidate.json', new_monitor)]:
        private_write(args.backup / name, json.dumps(value))
    private_write(args.backup / 'locations.candidate.conf', locations)
    private_write(args.backup / 'nginx.candidate.conf', nginx.replace(str(LOCATIONS), str(args.backup / 'locations.candidate.conf')))
    shutil.copy2(Path(__file__), args.backup / 'residential.py')
    private_write(args.backup / 'rollback.sh', '#!/bin/sh\nset -eu\nexec python3 "$(dirname "$0")/residential.py" rollback "$(dirname "$0")"\n', 0o700)
    probe = args.source / 'scripts/probe.py'
    if 'def residential_exit(' not in probe.read_text():
        raise ValueError('Candidate source lacks residential probe support')
    ready = time.monotonic() + 20
    while True:
        try:
            preflight = run('/usr/local/lib/xray-gateway/panel-current', '--secret-key', '/etc/xray-gateway/security.key',
                            '--monitor-config', '/etc/xcli-monitor/monitor.json', '--preflight')
        except RuntimeError:
            if time.monotonic() >= ready:
                raise
            time.sleep(1)
            continue
        state = json.loads(preflight)
        if state['database_integrity'] != 'ok' or not (state['pending_additions'] or state['pending_revocations']) or time.monotonic() >= ready:
            break
        time.sleep(1)
    private_write(args.backup / 'preflight.json', preflight)
    if state['database_integrity'] != 'ok' or state['pending_additions'] or state['pending_revocations']:
        raise ValueError('Existing core accounts have pending changes; wait for synchronization first')
    for command in [('/usr/local/lib/xray-gateway/xray', 'run', '-test', '-config', args.backup / 'core.candidate.json'),
                    ('nginx', '-t', '-c', args.backup / 'nginx.candidate.conf')]:
        result = subprocess.run(list(map(str, command)), capture_output=True, timeout=30)
        private_write(args.backup / ('xray-check.log' if command[0].endswith('xray') else 'nginx-check.log'), result.stdout + result.stderr)
        if result.returncode:
            raise ValueError('Candidate syntax verification failed; active configuration retained')
    try:
        run('systemctl', 'stop', 'xray-gateway-monitor', 'xray-gateway-panel')
        for name, value in [('settings.json', new_settings), ('core.json', new_core), ('monitor.json', new_monitor)]:
            replace(FILES[name], json.dumps(value), args.backup / name)
        private_write(LOCATIONS, locations, 0o644)
        private_write(PRIVATE_POOL, json.dumps(pool))
        replace(FILES['nginx.conf'], nginx, args.backup / 'nginx.conf')
        if not managed:
            replace(FILES['probe.py'], probe.read_bytes(), args.backup / 'probe.py')
        since = int(time.time())
        run('systemctl', 'restart', 'xray-gateway-core')
        run('systemctl', 'start', 'xray-gateway-panel')
        run('nginx', '-t')
        run('systemctl', 'reload', 'nginx')
        # Initial account synchronization occurs before the first public probes.
        time.sleep(6)
        run('systemctl', 'start', 'xray-gateway-monitor')
        wait_ready({e['tag'] for e in new_settings['residential_exits']} | {'reality', 'websocket', 'hysteria2'}, since)
    except Exception:
        rollback(args.backup)
        raise
    print(json.dumps({'residential_exits': len(new_settings['residential_exits']), 'subscription_nodes': 3 + len(new_settings['residential_exits']), 'public_port': 443, 'verification': 'all nodes healthy', 'rollback': str(args.backup / 'rollback.sh')}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    add = sub.add_parser('install')
    add.add_argument('--source', type=Path, required=True)
    add.add_argument('--pool', type=Path, required=True)
    add.add_argument('--backup', type=Path, required=True)
    revert = sub.add_parser('rollback')
    revert.add_argument('backup', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run with sudo')
    try:
        install(args) if args.action == 'install' else rollback(args.backup)
    except Exception as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
