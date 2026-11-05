"""Small loopback C++ versus Node+Rust comparison using synthetic state.

Run only against the supplied test binaries. No production files are read.
All child processes inherit the caller's scheduling priority and CPU affinity.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import tempfile
import time
import uuid

from test_panel_auth_compat import free_port


ORIGIN = 'https://testserver'
REQUESTS = 40
WORKERS = 2


def request(port, path, method='GET', body=None, cookie='', csrf=''):
    headers = {'Origin': ORIGIN, 'Content-Type': 'application/json'}
    if cookie:
        headers['Cookie'] = cookie
    if csrf:
        headers['X-CSRF-Token'] = csrf
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        return response.status, dict((key.lower(), value) for key, value in response.getheaders()), response.read()
    finally:
        conn.close()


def ready(process, port):
    for _ in range(200):
        if process.poll() is not None:
            raise RuntimeError('fixture process stopped at startup')
        try:
            if request(port, '/healthz')[0] == 200:
                return
        except OSError:
            time.sleep(.05)
    raise RuntimeError('fixture process did not become ready')


def stop(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise RuntimeError('fixture process did not stop gracefully')


def metrics(process):
    stat = Path(f'/proc/{process.pid}/stat').read_text().rsplit(')', 1)[1].split()
    ticks = int(stat[11]) + int(stat[12])
    status = Path(f'/proc/{process.pid}/status').read_text().splitlines()
    rss = next(int(line.split()[1]) for line in status if line.startswith('VmRSS:'))
    return ticks / os.sysconf('SC_CLK_TCK'), rss


def sample(port, path, cookie, expected_hash, processes):
    before = sum(metrics(process)[0] for process in processes)

    def one(_):
        started = time.perf_counter_ns()
        status, _, body = request(port, path, cookie=cookie)
        elapsed = (time.perf_counter_ns() - started) / 1_000_000
        if status != 200 or hashlib.sha256(body).digest() != expected_hash:
            raise RuntimeError('fixture response changed during measurement')
        return elapsed

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        latencies = list(executor.map(one, range(REQUESTS)))
    elapsed = time.perf_counter() - started
    after = [metrics(process) for process in processes]
    return {'latencies': latencies, 'seconds': elapsed,
            'cpu_seconds': sum(item[0] for item in after) - before,
            'rss_kib': sum(item[1] for item in after)}


def report(samples):
    latencies = sorted(value for sample in samples for value in sample['latencies'])
    return {'requests': len(latencies), 'p50_ms': round(latencies[len(latencies) // 2], 3),
            'p95_ms': round(latencies[math.ceil(len(latencies) * .95) - 1], 3),
            'requests_per_second': round(len(latencies) / sum(item['seconds'] for item in samples), 1),
            'cpu_ms_per_request': round(sum(item['cpu_seconds'] for item in samples) * 1000 / len(latencies), 3),
            'observed_rss_kib': max(item['rss_kib'] for item in samples)}


def main():
    parser = argparse.ArgumentParser()
    for name in ('legacy', 'panel', 'node', 'gateway'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--order', choices=('abba', 'baab'), default='abba')
    args = parser.parse_args()
    if any(not path.is_file() for path in (args.legacy, args.panel, args.node, args.gateway)):
        raise RuntimeError('test executable is missing')
    if hasattr(os, 'sched_getaffinity'):
        cpus = os.sched_getaffinity(0)
        os.sched_setaffinity(0, {min(cpus)})
    with tempfile.TemporaryDirectory(prefix='xcli-http-bench-') as folder:
        root = Path(folder)
        state = root / 'legacy'; state.mkdir()
        new_state = root / 'rust'; new_state.mkdir()
        key = root / 'key'; key.write_bytes(bytes(range(32))); key.chmod(0o600)
        settings = root / 'settings.json'
        settings.write_text(json.dumps({'origin': ORIGIN, 'domain': 'testserver', 'public_ip': '203.0.113.2',
            'reality_sni': 'www.bing.com', 'reality_public': 'p' * 43, 'short_id': '0123456789abcdef',
            'ws_path': '/connect/test', 'hysteria2_port': 443}))
        with closing(sqlite3.connect(state / 'gateway.sqlite')) as db:
            db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)')
            db.execute('INSERT INTO admin VALUES(1,?)', ('000102030405060708090a0b0c0d0e0f:'
                       'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf',))
            db.commit()
        old_port, core_port, web_port = free_port(), free_port(), free_port()
        def old():
            return subprocess.Popen([str(args.legacy), '--state', str(state), '--settings', str(settings), '--static', str(root),
                '--secret-key', str(key), '--port', str(old_port), '--offline', '--no-auto-backup'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        initial = old(); legacy = panel = gateway = None
        try:
            ready(initial, old_port)
            status, headers, data = request(old_port, '/api/login', 'POST',
                json.dumps({'username': 'admin', 'password': 'fixture-password'}).encode())
            if status != 200:
                raise RuntimeError('fixture login failed')
            cookie = headers['set-cookie'].split(';', 1)[0]
            csrf = json.loads(data)['csrf']
            status, _, data = request(old_port, '/api/users', 'POST', json.dumps({'name': 'benchmark-user'}).encode(), cookie, csrf)
            if status != 200:
                raise RuntimeError('fixture user creation failed')
            user_id = json.loads(data)['id']
            status, _, _ = request(old_port, '/api/users/' + user_id + '/rule-template', 'POST',
                                    json.dumps({'template_id': 'independent'}).encode(), cookie, csrf)
            if status != 200:
                raise RuntimeError('fixture rule assignment failed')
            with closing(sqlite3.connect(state / 'gateway.sqlite')) as db:
                token = db.execute('SELECT token FROM users WHERE id=?', (user_id,)).fetchone()[0]
                stamp = int(time.time())
                for index in range(19):
                    db.execute('INSERT INTO users(id,name,uuid,token,enabled,quota,expires,upload,download,created,deleted) VALUES(?,?,?,?,1,0,0,0,0,?,0)',
                               (uuid.uuid4().hex, f'fixture-{index}', str(uuid.uuid4()), secrets.token_urlsafe(32), stamp))
                db.commit()
            stop(initial); initial = None
            with closing(sqlite3.connect(state / 'gateway.sqlite')) as source, closing(sqlite3.connect(new_state / 'gateway.sqlite')) as target:
                source.backup(target)
            legacy = old(); ready(legacy, old_port)
            panel = subprocess.Popen([str(args.panel), '--experimental', '--db', str(new_state / 'gateway.sqlite'),
                '--secret-key', str(key), '--settings', str(settings), '--origin', ORIGIN, '--port', str(core_port)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ready(panel, core_port)
            gateway = subprocess.Popen([str(args.node), str(args.gateway)], env=dict(os.environ,
                XCLI_CORE_PORT=str(core_port), XCLI_WEB_PORT=str(web_port)), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            ready(gateway, web_port)
            endpoints = {'links': ('/api/users/' + user_id + '/links', cookie),
                         'clash': ('/s/' + token + '/clash.yaml', '')}
            order = ('legacy', 'new', 'new', 'legacy') if args.order == 'abba' else ('new', 'legacy', 'legacy', 'new')
            output = {'scope': 'loopback synthetic; C++ versus Node+Rust; one CPU; two concurrent requests',
                      'users_in_database': 20, 'round_order': ','.join(order), 'rounds_per_version': 2,
                      'requests_per_round': REQUESTS, 'endpoints': {}}
            for label, (path, authentication) in endpoints.items():
                old_status, _, old_body = request(old_port, path, cookie=authentication)
                new_status, _, new_body = request(web_port, path, cookie=authentication)
                if old_status != 200 or new_status != 200:
                    raise RuntimeError(f'{label}: fixture comparison returned {old_status} and {new_status}')
                same = json.loads(old_body) == json.loads(new_body) if label == 'links' else old_body == new_body
                if not same:
                    raise RuntimeError('fixture output does not match between versions')
                old_hash, new_hash = hashlib.sha256(old_body).digest(), hashlib.sha256(new_body).digest()
                for _ in range(8):
                    request(old_port, path, cookie=authentication)
                    request(web_port, path, cookie=authentication)
                measurements = {'legacy': [], 'new': []}
                for side in order:
                    if side == 'legacy':
                        measurements[side].append(sample(old_port, path, authentication, old_hash, [legacy]))
                    else:
                        measurements[side].append(sample(web_port, path, authentication, new_hash, [panel, gateway]))
                output['endpoints'][label] = {'legacy': report(measurements['legacy']), 'new': report(measurements['new'])}
            print(json.dumps(output, ensure_ascii=False, indent=2))
        finally:
            for process in (gateway, panel, legacy, initial):
                stop(process)


if __name__ == '__main__':
    main()
