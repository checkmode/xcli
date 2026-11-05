"""Compare read-only legacy and Rust diagnostics with synthetic credentials."""
import base64
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

from test_panel_http_integration import PANEL, free_port, request, stop, wait_ready

LEGACY = os.environ.get('XCLI_LEGACY_PANEL', '')


@unittest.skipUnless(PANEL and LEGACY and Path(PANEL).is_file() and Path(LEGACY).is_file(),
                     'set XCLI_PANEL_SERVICE and XCLI_LEGACY_PANEL')
class SubscriptionDiagnosticsCompatibility(unittest.TestCase):
    def test_generated_diagnostics_match_without_exposing_credentials_or_changing_profiles(self):
        with tempfile.TemporaryDirectory(prefix='xcli-diagnostic-compat-') as folder:
            root = Path(folder)
            state = root / 'legacy'
            state.mkdir()
            key = root / 'security.key'
            key.write_bytes(bytes(range(32)))
            key.chmod(0o600)
            settings = root / 'settings.json'
            settings.write_text(json.dumps({'origin': 'https://testserver', 'domain': 'testserver',
                'public_ip': '203.0.113.2', 'reality_sni': 'example.com', 'reality_public': 'p' * 43,
                'short_id': 'aabbccdd', 'ws_path': '/connect/test', 'hysteria2_port': 443}))
            db_path = state / 'gateway.sqlite'
            with closing(sqlite3.connect(db_path)) as db:
                db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)')
                db.execute('INSERT INTO admin VALUES(1,?)', ('000102030405060708090a0b0c0d0e0f:'
                    'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf',))
                db.commit()
            old_port, new_port = free_port(), free_port()
            old = subprocess.Popen([LEGACY, '--state', str(state), '--settings', str(settings), '--static', str(root),
                '--secret-key', str(key), '--port', str(old_port), '--offline', '--no-auto-backup'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            new = None
            try:
                wait_ready(old, old_port)
                status, headers, login = request(old_port, '/api/login', 'POST',
                    json.dumps({'username': 'admin', 'password': 'fixture-password'}).encode())
                self.assertEqual(status, 200)
                cookie = headers['set-cookie'].split(';', 1)[0]
                csrf = json.loads(login)['csrf']
                users = []
                for name in ('synthetic-standard', 'synthetic-independent', 'synthetic-disabled'):
                    status, _, body = request(old_port, '/api/users', 'POST', json.dumps({'name': name}).encode(), cookie, csrf)
                    self.assertEqual(status, 200)
                    users.append(json.loads(body)['id'])
                status, _, _ = request(old_port, '/api/users/' + users[1] + '/rule-template', 'POST',
                    json.dumps({'template_id': 'independent'}).encode(), cookie, csrf)
                self.assertEqual(status, 200)
                status, _, _ = request(old_port, '/api/users/' + users[2], 'PUT',
                    json.dumps({'name': 'synthetic-disabled', 'enabled': False}).encode(), cookie, csrf)
                self.assertEqual(status, 200)
                with closing(sqlite3.connect(db_path)) as db:
                    credentials = {row[0]: (row[1], row[2]) for row in db.execute('SELECT id,uuid,token FROM users')}
                    with closing(sqlite3.connect(root / 'new.sqlite')) as target:
                        db.backup(target)
                new = subprocess.Popen([PANEL, '--experimental', '--db', str(root / 'new.sqlite'),
                    '--secret-key', str(key), '--settings', str(settings), '--origin', 'https://testserver',
                    '--port', str(new_port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                wait_ready(new, new_port)
                self.assertEqual(request(new_port, '/api/users/' + users[0] + '/subscription-diagnostics')[0], 401)
                self.assertEqual(request(new_port, '/api/users/' + '0' * 32 + '/subscription-diagnostics', cookie=cookie)[0], 404)
                for index, uid in enumerate(users):
                    uuid, token = credentials[uid]
                    endpoint = '/api/users/' + uid + '/subscription-diagnostics'
                    paths = ['/s/' + token + suffix for suffix in ('', '/clash.yaml', '/shadowrocket.conf')]
                    before = [request(new_port, path) for path in paths]
                    old_status, _, old_data = request(old_port, endpoint, cookie=cookie)
                    new_status, _, new_data = request(new_port, endpoint, cookie=cookie)
                    self.assertEqual((old_status, new_status), (200, 200))
                    previous, current = json.loads(old_data), json.loads(new_data)
                    self.assertIsInstance(current.pop('generated_at'), int)
                    previous.pop('generated_at')
                    self.assertEqual(previous, current)
                    self.assertEqual(current['last_fetch'], 'unknown')
                    self.assertEqual(current['client_enabled'], 'unknown')
                    self.assertNotIn(uuid.encode(), new_data)
                    self.assertNotIn(token.encode(), new_data)
                    self.assertEqual(before, [request(new_port, path) for path in paths])
                    if index == 2:
                        self.assertEqual(current['user_status'], 'disabled')
                        self.assertTrue(all(item['status'] == 'inactive' for item in current['formats'].values()))
                    else:
                        nodes = current['formats']['nodes']
                        self.assertEqual(nodes['sha256'], hashlib.sha256(before[0][2]).hexdigest())
                        self.assertEqual(nodes['node_count'], len(base64.b64decode(before[0][2]).splitlines()))
                        mobile = current['formats']['shadowrocket']
                        if index == 0:
                            self.assertEqual(mobile['status'], 'unavailable')
                        else:
                            self.assertEqual(current['template']['name'], '独立服务分组')
                            self.assertIn('独立 · Google', current['formats']['clash']['groups'])
                            self.assertIn('XCLI-独立 · Google', mobile['groups'])
                            self.assertEqual(mobile['sha256'], hashlib.sha256(before[2][2]).hexdigest())
            finally:
                stop(new)
                stop(old)
