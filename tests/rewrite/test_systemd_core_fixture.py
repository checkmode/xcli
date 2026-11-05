"""Verify core synchronization and accounting under real temporary systemd units."""
from contextlib import suppress
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import threading
import time
import unittest

FIXTURE = os.environ.get('XCLI_TEST_SYSTEMD_FIXTURE', '')
XRAY = os.environ.get('XCLI_TEST_XRAY', '')
CGROUP = Path('/sys/fs/cgroup/system.slice/xcli-core.service/cgroup.procs')


def request(path, method='GET', body=None, cookie='', csrf=''):
    headers = {'Origin': 'https://testserver', 'Content-Type': 'application/json'}
    if cookie: headers['Cookie'] = cookie
    if csrf: headers['X-CSRF-Token'] = csrf
    conn = http.client.HTTPConnection('127.0.0.1', 18080, timeout=4)
    try:
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        return response.status, dict((key.lower(), value) for key, value in response.getheaders()), response.read()
    finally:
        conn.close()


def wait_for(test, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        with suppress(OSError, ValueError, json.JSONDecodeError):
            if test(): return True
        time.sleep(.1)
    return False


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@unittest.skipUnless(FIXTURE and XRAY, 'run through run_systemd_core_fixture.sh')
class SystemdCore(unittest.TestCase):
    def test_user_traffic_and_revoke(self):
        root = Path(FIXTURE)
        self.assertTrue(wait_for(lambda: request('/internal/ready')[0] == 200), 'panel core not synchronized')
        status, headers, body = request('/api/login', 'POST',
            json.dumps({'username': 'admin', 'password': 'fixture-password-123'}).encode())
        self.assertEqual(status, 200)
        cookie, csrf = headers['set-cookie'].split(';', 1)[0], json.loads(body)['csrf']
        status, _, body = request('/api/users', 'POST', json.dumps({'name': 'fixture'}).encode(), cookie, csrf)
        self.assertEqual(status, 200)
        user = json.loads(body)['id']
        with sqlite3.connect(root / 'gateway.sqlite') as db:
            identity = db.execute('SELECT uuid FROM users WHERE id=?', (user,)).fetchone()[0]
        def user_ready():
            result = subprocess.run([XRAY, 'api', 'inbounduser', '--server=127.0.0.1:10085', '-tag=websocket',
                                     '--timeout=1'], capture_output=True, timeout=3)
            return result.returncode == 0 and identity.encode() in result.stdout
        self.assertTrue(wait_for(user_ready), 'core did not receive the new user')
        data = b'systemd-fixture' * 4096
        class Origin(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                self.send_response(200); self.send_header('Content-Length', str(len(data))); self.end_headers()
                self.wfile.write(data)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        socks = port()
        cfg = {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1', 'port': socks,
            'protocol': 'socks', 'settings': {'auth': 'noauth'}}], 'outbounds': [{'protocol': 'vless',
            'settings': {'vnext': [{'address': '127.0.0.1', 'port': 10080,
                                      'users': [{'id': identity, 'encryption': 'none'}]}]},
            'streamSettings': {'network': 'ws', 'wsSettings': {'path': '/fixture'}}}]}
        config = root / 'client.json'; config.write_text(json.dumps(cfg))
        client = subprocess.Popen([XRAY, 'run', '-config', str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            def listening():
                with socket.create_connection(('127.0.0.1', socks), timeout=1): return True
            self.assertTrue(wait_for(listening, 8))
            result = subprocess.run(['curl', '-fsS', '--noproxy', '', '--proxy', f'socks5h://127.0.0.1:{socks}',
                                     '--max-time', '6', f'http://127.0.0.1:{server.server_port}/'], capture_output=True, timeout=8)
            self.assertEqual(result.returncode, 0); self.assertEqual(result.stdout, data)
            def usage():
                with sqlite3.connect(root / 'gateway.sqlite') as db:
                    return db.execute('SELECT download FROM users WHERE id=?', (user,)).fetchone()[0]
            self.assertTrue(wait_for(lambda: usage() >= len(data)), 'traffic was not persisted')
            old_pid = CGROUP.read_text().strip()
            self.assertEqual(request('/api/users/' + user, 'DELETE', cookie=cookie, csrf=csrf)[0], 200)
            self.assertTrue(wait_for(lambda: CGROUP.exists() and CGROUP.read_text().strip() not in ('', old_pid)),
                            'systemd did not restart the core after revocation')
            self.assertTrue(wait_for(lambda: request('/internal/ready')[0] == 200), 'panel did not resynchronize')
            self.assertGreaterEqual(usage(), len(data))
        finally:
            client.terminate(); client.wait(timeout=10)
            server.shutdown(); server.server_close(); thread.join(timeout=3)


if __name__ == '__main__':
    unittest.main(verbosity=2)
