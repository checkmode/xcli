"""Compare Rust input rules to the real C++ endpoint using synthetic users."""
import http.client
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest

from test_panel_auth_compat import free_port

PANEL = os.environ.get('XCLI_LEGACY_PANEL', '')
DRIVER = os.environ.get('XCLI_USER_INPUT_DRIVER', '')


@unittest.skipUnless(PANEL and DRIVER and Path(PANEL).is_file() and Path(DRIVER).is_file(),
                     'set XCLI_LEGACY_PANEL and XCLI_USER_INPUT_DRIVER for user comparison')
class PanelUsersCompatibility(unittest.TestCase):
    def test_validation_and_persisted_values_match(self):
        with tempfile.TemporaryDirectory(prefix='xcli-users-compat-') as folder:
            root = Path(folder)
            state = root / 'state'
            state.mkdir()
            settings = root / 'settings.json'
            settings.write_text(json.dumps({'origin':'https://testserver', 'domain':'testserver', 'public_ip':'203.0.113.2',
                'reality_sni':'example.com', 'reality_public':'p'*43, 'short_id':'aabbccdd', 'ws_path':'/connect/test'}))
            key_file = root / 'security.key'
            key_file.write_bytes(bytes(range(32)))
            key_file.chmod(0o600)
            encoded = ('000102030405060708090a0b0c0d0e0f:'
                       'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf')
            db = sqlite3.connect(state / 'gateway.sqlite')
            db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)')
            db.execute('INSERT INTO admin VALUES(1,?)', (encoded,))
            db.commit()
            db.close()
            port = free_port()
            panel = subprocess.Popen([PANEL, '--state', str(state), '--settings', str(settings), '--static', str(root),
                '--secret-key', str(key_file), '--port', str(port), '--offline', '--no-auto-backup'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            driver = None
            def request(path, method='GET', body=None, cookie='', csrf=''):
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
                headers = {'Origin':'https://testserver', 'Content-Type':'application/json'}
                if cookie: headers['Cookie'] = cookie
                if csrf: headers['X-CSRF-Token'] = csrf
                try:
                    conn.request(method, path, body=json.dumps(body, ensure_ascii=False).encode() if body is not None else None, headers=headers)
                    response = conn.getresponse()
                    return response.status, dict((k.lower(), v) for k, v in response.getheaders()), json.loads(response.read())
                finally:
                    conn.close()
            try:
                for _ in range(100):
                    if panel.poll() is not None: self.fail('disposable legacy panel stopped')
                    try:
                        if request('/healthz')[0] == 200: break
                    except OSError: time.sleep(.05)
                else: self.fail('disposable legacy panel did not become ready')
                status, headers, body = request('/api/login', 'POST', {'username':'admin', 'password':'fixture-password'})
                self.assertEqual(status, 200)
                cookie, csrf = headers['set-cookie'].split(';', 1)[0], body['csrf']
                driver = subprocess.Popen([DRIVER], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, text=True, bufsize=1)
                fixtures = [
                    {'name':'Alice'}, {'name':'\u2003 测试 \u3000', 'enabled':False, 'quota':123, 'expires':4102444800},
                    {'name':'\u001cAlice\u001f'}, {'name':'\ufeffAlice\ufeff'}, {'name':'甲' * 60},
                    {'name':'valid', 'quota':10000000000000000}, {'name':'valid', 'expires':0},
                    {}, {'name':''}, {'name':'   '}, {'name':'a\nb'}, {'name':'甲' * 61}, {'name':123},
                    {'name':'valid', 'enabled':1}, {'name':'valid', 'enabled':None}, {'name':'valid', 'extra':1},
                    {'name':'valid', 'quota':-1}, {'name':'valid', 'quota':1.0}, {'name':'valid', 'quota':10000000000000001},
                    {'name':'valid', 'quota':None}, {'name':'valid', 'expires':4102444801}, {'name':'valid', 'expires':True},
                ]
                for fixture in fixtures:
                    with self.subTest(input=fixture):
                        driver.stdin.write(json.dumps(fixture, ensure_ascii=False) + '\n')
                        driver.stdin.flush()
                        result = json.loads(driver.stdout.readline())
                        status, _, body = request('/api/users', 'POST', fixture, cookie, csrf)
                        self.assertEqual(status == 200, result['ok'])
                        if not result['ok']:
                            self.assertEqual(status, 422)
                            continue
                        db = sqlite3.connect(state / 'gateway.sqlite')
                        try:
                            row = db.execute('SELECT name,enabled,quota,expires FROM users WHERE id=?', (body['id'],)).fetchone()
                        finally:
                            db.close()
                        value = result['value']
                        self.assertEqual(row, (value['name'], int(value['enabled']), value['quota'], value['expires']))
            finally:
                if driver is not None:
                    driver.stdin.close()
                    driver.wait(timeout=10)
                    driver.stdout.close()
                panel.terminate()
                try: panel.wait(timeout=15)
                except subprocess.TimeoutExpired: panel.kill(); panel.wait(timeout=5)
