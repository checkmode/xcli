#!/usr/bin/env python3
"""Exercise optional pool installation and rollback on disposable CI only."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

SOURCE = Path(__file__).resolve().parents[2]


def run(*args):
    return subprocess.check_output(list(map(str, args)), stderr=subprocess.STDOUT)


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.geteuid() != 0:
        raise SystemExit('Only run as root on a disposable GitHub Actions machine')
    root = Path('/root/xcli-webshare-ci')
    original = {name: Path('/etc/xray-gateway', name).read_bytes() for name in ('settings.json', 'core.json')}
    nginx_pid = run('systemctl', 'show', 'nginx', '-p', 'MainPID', '--value')
    run('python3', SOURCE / 'cpp/tests/migration_state.py', 'save', '/root/xcli-webshare-before.json')
    run('python3', SOURCE / 'deploy/webshare-pool.py', 'install', '--source', SOURCE, '--backup', root)
    try:
        settings = json.loads(Path('/etc/xray-gateway/settings.json').read_text())
        entries = [e for e in settings['residential_exits'] if e.get('dynamic')]
        assert [e['country'] for e in entries] == ['US', 'JP', 'SG', 'ZZ']
        report = json.loads(Path('/var/lib/xray-gateway/webshare/report.json').read_text())
        assert not report['enabled'] and report['status'] == 'unconfigured'
        assert nginx_pid == run('systemctl', 'show', 'nginx', '-p', 'MainPID', '--value')
        for port in range(10120, 10124):
            with socket.create_connection(('127.0.0.1', port), timeout=2) as client:
                client.sendall(b'\x05\x01\x00')
                assert client.recv(2) == b'\x05\x00'
                client.sendall(b'\x05\x01\x00\x01\x08\x08\x08\x08\x01\xbb')
                assert client.recv(10)[1] != 0, 'Unconfigured pool must never connect directly'
    finally:
        run('bash', root / 'rollback.sh')
    for name, value in original.items():
        assert Path('/etc/xray-gateway', name).read_bytes() == value
    run('python3', SOURCE / 'cpp/tests/migration_state.py', 'verify', '/root/xcli-webshare-before.json')
    assert not Path('/etc/nginx/xcli-webshare-locations.conf').exists()
    assert not Path('/etc/systemd/system/xray-gateway-webshare.service').exists()
    assert nginx_pid == run('systemctl', 'show', 'nginx', '-p', 'MainPID', '--value')
    print('Webshare installation, disabled-pool rejection, preservation and rollback passed')


if __name__ == '__main__':
    main()
