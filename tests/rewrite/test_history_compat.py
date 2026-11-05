"""Compare legacy and Rust history HTTP responses using synthetic databases."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest

from test_panel_http_integration import PANEL, free_port, request, stop, wait_ready

LEGACY = os.environ.get('XCLI_LEGACY_PANEL', '')


@unittest.skipUnless(PANEL and LEGACY and Path(PANEL).is_file() and Path(LEGACY).is_file(),
                     'set XCLI_PANEL_SERVICE and XCLI_LEGACY_PANEL')
class HistoryCompatibility(unittest.TestCase):
    def test_history_ranges_match_legacy_and_require_a_session(self):
        with tempfile.TemporaryDirectory(prefix='xcli-history-compat-') as folder:
            root = Path(folder)
            old_state = root / 'old'
            old_state.mkdir()
            key = root / 'security.key'
            key.write_bytes(bytes(range(32)))
            key.chmod(0o600)
            settings = root / 'settings.json'
            settings.write_text(json.dumps({'origin': 'https://testserver', 'domain': 'testserver',
                'public_ip': '203.0.113.2', 'reality_sni': 'example.com', 'reality_public': 'p' * 43,
                'short_id': 'aabbccdd', 'ws_path': '/connect/test', 'hysteria2_port': 443}))
            old_db = old_state / 'gateway.sqlite'
            with closing(sqlite3.connect(old_db)) as db:
                db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)')
                db.execute('INSERT INTO admin VALUES(1,?)', ('000102030405060708090a0b0c0d0e0f:'
                    'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf',))
                db.commit()
            old_port = free_port()
            old = subprocess.Popen([LEGACY, '--state', str(old_state), '--settings', str(settings),
                '--static', str(root), '--secret-key', str(key), '--port', str(old_port), '--offline', '--no-auto-backup'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            new = None
            try:
                wait_ready(old, old_port)
                status, headers, login = request(old_port, '/api/login', 'POST',
                    json.dumps({'username': 'admin', 'password': 'fixture-password'}).encode())
                self.assertEqual(status, 200)
                cookie = headers['set-cookie'].split(';', 1)[0]
                csrf = json.loads(login)['csrf']
                config = {'enabled': False, 'url': 'https://receiver.example.net/hook?secret=synthetic-only',
                          'bearer': 'synthetic-bearer', 'signing_secret': 'synthetic-signing-secret',
                          'current_password': 'fixture-password'}
                self.assertEqual(request(old_port, '/api/notifications', 'PUT', json.dumps(config).encode(), cookie, csrf)[0], 200)
                status, _, created = request(old_port, '/api/users', 'POST', json.dumps({'name':'activity-fixture'}).encode(), cookie, csrf)
                self.assertEqual(status, 200)
                user_id = json.loads(created)['id']
                now = int(time.time())
                with closing(sqlite3.connect(old_db)) as db:
                    for index in range(35):
                        db.execute('INSERT INTO events(ts,action,detail) VALUES(?,?,?)',
                                   (now-index,'fixture_event',f'entry-{index}'))
                    for tag, last, sampled, upload, download in [
                        ('websocket', now-10, now-5, 500, 250), ('reality', now-150, now-5, 5, 10),
                        ('hysteria2', 0, now-5, 0, 0), ('vmess', now-10, now-120, 200, 300),
                    ]:
                        db.execute('INSERT INTO device_activity VALUES(?,?,?,?,?,?,?)',
                            (user_id,tag,last,sampled,upload,download,5))
                    for offset, up, down in [(180, 100, 200), (120, 300, 400), (60, 50, 75)]:
                        db.execute('INSERT OR REPLACE INTO traffic_history VALUES(?,?,?)',
                                   ((now-offset)//60*60, up, down))
                    for offset, tag, status, https, udp in [(180, 'reality', 'healthy', 10, 20),
                        (120, 'reality', 'failed', None, 30), (60, 'reality', 'unknown', None, None),
                        (120, 'websocket', 'healthy', 40, 50), (60, 'hysteria2', 'failed', None, None)]:
                        db.execute('INSERT OR REPLACE INTO probe_history VALUES(?,?,?,?,?)',
                                   (now-offset, tag, status, https, udp))
                    db.commit()
                    with closing(sqlite3.connect(root / 'new.sqlite')) as target:
                        db.backup(target)
                new_port = free_port()
                new = subprocess.Popen([PANEL, '--experimental', '--db', str(root / 'new.sqlite'),
                    '--secret-key', str(key), '--settings', str(settings), '--origin', 'https://testserver',
                    '--port', str(new_port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                wait_ready(new, new_port)
                self.assertEqual(request(new_port, '/api/activity')[0], 401)
                old_status, _, overview = request(old_port, '/api/overview', cookie=cookie)
                new_status, _, activity = request(new_port, '/api/activity', cookie=cookie)
                self.assertEqual((old_status, new_status), (200, 200))
                self.assertEqual(json.loads(overview)['activity'], json.loads(activity)['activity'])
                self.assertEqual(json.loads(activity)['scope'], 'local')
                self.assertEqual(request(new_port, '/api/events')[0], 401)
                events_status, _, events = request(new_port, '/api/events', cookie=cookie)
                self.assertEqual(events_status, 200)
                self.assertEqual(json.loads(overview)['events'], json.loads(events)['events'])
                self.assertEqual(len(json.loads(events)['events']), 30)
                self.assertEqual(json.loads(events)['events'][0]['detail'], 'entry-34')
                self.assertEqual(request(new_port, '/api/history')[0], 401)
                for range_ in ('1h', '24h', '7d', '30d'):
                    for _ in range(5):
                        old_status, _, old_data = request(old_port, '/api/history?range='+range_, cookie=cookie)
                        new_status, _, new_data = request(new_port, '/api/history?range='+range_, cookie=cookie)
                        previous, current = json.loads(old_data), json.loads(new_data)
                        if previous.get('end') == current.get('end'):
                            break
                    self.assertEqual((old_status, new_status), (200, 200))
                    self.assertEqual(previous, current)
                self.assertEqual(request(new_port, '/api/history?range=invalid', cookie=cookie)[0], 422)
                self.assertEqual(request(new_port, '/api/notifications')[0], 401)
                old_status, _, old_data = request(old_port, '/api/notifications', cookie=cookie)
                new_status, _, new_data = request(new_port, '/api/notifications', cookie=cookie)
                self.assertEqual((old_status, new_status), (200, 200))
                previous, current = json.loads(old_data), json.loads(new_data)
                self.assertFalse(current.pop('delivery_active'))
                self.assertEqual(previous, current)
                self.assertNotIn(b'synthetic-only', new_data)
                self.assertNotIn(b'synthetic-bearer', new_data)
                self.assertNotIn(b'synthetic-signing-secret', new_data)
                cases = [
                    ({'current_password': 'incorrect'}, csrf, 403),
                    ({'current_password': 'fixture-password', 'url': 'https://127.0.0.1/'}, csrf, 422),
                    ({'current_password': 'fixture-password', 'failures': 0}, csrf, 422),
                    ({'current_password': 'fixture-password', 'signing_secret': 'short'}, csrf, 422),
                    ({'current_password': 'fixture-password'}, 'wrong-csrf', 403),
                    ({'current_password': 'fixture-password', 'enabled': False,
                      'url': 'https://new.example.net/new?token=synthetic-second', 'failures': 4}, csrf, 200),
                    ({'current_password': 'fixture-password', 'clear_auth': True}, csrf, 200),
                ]
                for body, token, expected in cases:
                    payload = json.dumps(body).encode()
                    old_status, _, _ = request(old_port, '/api/notifications', 'PUT', payload, cookie, token)
                    new_status, _, _ = request(new_port, '/api/notifications', 'PUT', payload, cookie, token)
                    self.assertEqual((old_status, new_status), (expected, expected))
                    previous = json.loads(request(old_port, '/api/notifications', cookie=cookie)[2])
                    current = json.loads(request(new_port, '/api/notifications', cookie=cookie)[2])
                    current.pop('delivery_active')
                    self.assertEqual(previous, current)
            finally:
                stop(new)
                stop(old)
