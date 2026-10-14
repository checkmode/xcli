#!/usr/bin/env python3
"""Real update/rollback checks on disposable CI servers, without printing secrets."""
import hashlib
import pathlib
import subprocess
import urllib.error
import urllib.request


def main():
    base = pathlib.Path('/usr/local/lib/xray-gateway')
    release = (base / 'panel-current').resolve().parent
    assert (release / 'revision.txt').read_text().strip()
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with client.open('http://127.0.0.1:8080/runtime.js', timeout=5) as response:
        served = response.read()
        assert hashlib.sha256(served).digest() == hashlib.sha256((release / 'static/runtime.js').read_bytes()).digest()
    for path in ('runtime', 'diagnostics'):
        try:
            client.open('http://127.0.0.1:8080/api/' + path, timeout=5)
        except urllib.error.HTTPError as error:
            assert error.code == 401
        else:
            raise AssertionError('Runtime endpoint must require authentication')
    backups = sorted(pathlib.Path('/root').glob('xcli-update-*'), key=lambda path: path.stat().st_mtime)
    backup = backups[-1]
    subprocess.run(['bash', str(backup / 'rollback.sh')], check=True)
    assert str((base / 'panel-current').resolve()) == (backup / 'previous-target.txt').read_text().strip()
    subprocess.run(['python3', 'cpp/tests/migration_state.py', 'verify', '/root/xcli-before-update.json'], check=True)
    after = subprocess.check_output(['systemctl', 'show', 'xray-gateway-core', 'xray-gateway-monitor', 'nginx',
                                     '-p', 'Id', '-p', 'MainPID', '-p', 'NRestarts'])
    assert after == (backup / 'processes-before.txt').read_bytes()
    print('Real panel update, static files, authenticated routes and rollback verified; data-plane processes retained.')


if __name__ == '__main__':
    main()
