#!/usr/bin/env python3
"""Real managed update/rollback checks on disposable CI, without exposing credentials."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import release


def main():
    manager = release.Manager()
    status = manager.status()
    assert status['panel_matches_current'] and status['component_hashes_verified']
    current = manager.current.resolve()
    previous = manager.previous.resolve()
    assert current != previous
    assert release.validate_manifest(current)['provenance']['revision'] == os.environ['GITHUB_SHA']
    assert (Path('/opt/xray-gateway') / 'scripts').is_symlink()
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with client.open('http://127.0.0.1:8080/static/runtime.js', timeout=5) as response:
        assert hashlib.sha256(response.read()).hexdigest() == release.digest(current / 'static/runtime.js')
    for path in ('runtime', 'diagnostics'):
        try:
            client.open('http://127.0.0.1:8080/api/' + path, timeout=5)
        except urllib.error.HTTPError as error:
            assert error.code == 401
        else:
            raise AssertionError('Management endpoints must require authentication')
    records = [json.loads(p.read_text()) for p in manager.backups.glob('*/transaction.json')]
    record = next(v for v in reversed(sorted(records, key=lambda x: x['created_at']))
                  if v['target'] == str(current) and v['kind'] == 'activate' and v['phase'] == 'committed')
    for unit, pid in record['retained_pids'].items():
        assert manager.host.pid(unit) == pid
    subprocess.run(['bash', 'update.sh', '--yes', '--rollback'], check=True)
    assert manager.current.resolve() == previous
    subprocess.run(['python3', 'cpp/tests/migration_state.py', 'verify', '/root/xcli-before-update.json'], check=True)
    subprocess.run(['xcli-release', 'activate', current.name], check=True)
    assert manager.current.resolve() == current
    for unit, pid in record['retained_pids'].items():
        assert manager.host.pid(unit) == pid
    assert not manager.journal.exists()
    subprocess.run(['xcli-admin', 'status'], check=True)
    release.validate_manifest(current)  # Maintenance must not write bytecode into the release.
    print('One-click update, rollback, reactivation, static assets, authentication and retained processes passed.')


if __name__ == '__main__':
    main()
