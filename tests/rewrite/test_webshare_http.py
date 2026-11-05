"""Test authenticated residential controls and journal recovery with synthetic data."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest

from test_panel_http_integration import PANEL, WEB, free_port, request, stop, wait_ready


@unittest.skipUnless(PANEL and Path(PANEL).is_file(), 'set experimental panel path')
class WebshareHttpIntegration(unittest.TestCase):
    def test_authenticated_controls_recover_an_interrupted_audit(self):
        with tempfile.TemporaryDirectory(prefix='xcli-webshare-http-') as folder:
            root = Path(folder)
            key_file = root / 'security.key'
            key_file.write_bytes(bytes(range(32)))
            key_file.chmod(0o600)
            db_file = root / 'gateway.sqlite'
            with closing(sqlite3.connect(db_file)) as db:
                db.executescript('''
                    CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL);
                    CREATE TABLE sessions(hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
                    CREATE TABLE mfa(id INTEGER PRIMARY KEY,enabled INTEGER NOT NULL,secret TEXT NOT NULL,last_step INTEGER NOT NULL);
                    CREATE TABLE mfa_sessions(hash TEXT PRIMARY KEY);
                    CREATE TABLE recovery_codes(hash TEXT PRIMARY KEY,used INTEGER NOT NULL DEFAULT 0);
                    CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
                    CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                    CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL,uuid TEXT NOT NULL UNIQUE,
                        token TEXT NOT NULL UNIQUE,enabled INTEGER NOT NULL DEFAULT 1,quota INTEGER NOT NULL DEFAULT 0,
                        expires INTEGER NOT NULL DEFAULT 0,upload INTEGER NOT NULL DEFAULT 0,download INTEGER NOT NULL DEFAULT 0,
                        created INTEGER NOT NULL,deleted INTEGER NOT NULL DEFAULT 0);
                    INSERT INTO admin VALUES(1,'000102030405060708090a0b0c0d0e0f:afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf');
                    INSERT INTO mfa VALUES(1,0,'',-1);
                ''')
                db.commit()
            settings = root / 'settings.json'
            settings.write_text(json.dumps({'origin': 'https://testserver', 'domain': 'testserver',
                'residential_exits': [{'dynamic': True, 'country': 'US', 'tag': 'residential-11', 'port': 10110}]}))
            panel_port = free_port()
            panel = subprocess.Popen([PANEL, '--experimental', '--db', str(db_file), '--secret-key', str(key_file),
                '--settings', str(settings), '--origin', 'https://testserver', '--port', str(panel_port)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            gateway = None
            try:
                wait_ready(panel, panel_port)
                port = panel_port
                if WEB:
                    self.assertTrue(Path(WEB).is_file())
                    port = free_port()
                    gateway = subprocess.Popen(['node', WEB], env=dict(os.environ, XCLI_CORE_PORT=str(panel_port),
                        XCLI_WEB_PORT=str(port)), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    wait_ready(gateway, port)
                self.assertEqual(request(port, '/api/webshare')[0], 401)
                login = json.dumps({'username': 'admin', 'password': 'fixture-password', 'code': ''}).encode()
                status, headers, data = request(port, '/api/login', 'POST', login)
                self.assertEqual(status, 200)
                cookie = headers['set-cookie'].split(';', 1)[0]
                csrf = json.loads(data)['csrf']
                status, _, data = request(port, '/api/webshare', cookie=cookie)
                self.assertEqual(status, 200)
                self.assertTrue(json.loads(data)['installed'])
                secret = 'synthetic-api-key-for-test'
                body = json.dumps({'api_key': secret}).encode()
                self.assertEqual(request(port, '/api/webshare', 'PUT', body, cookie, 'wrong')[0], 403)
                self.assertEqual(request(port, '/api/webshare', 'PUT', body, cookie, csrf, origin='https://evil.example')[0], 403)
                self.assertEqual(request(port, '/api/webshare', 'PUT', b'{"api_key":"short"}', cookie, csrf)[0], 422)
                self.assertEqual(request(port, '/api/webshare', 'PUT', body, cookie, csrf)[0], 200)
                encrypted = (root / 'webshare/config.xgb').read_bytes()
                self.assertTrue(encrypted.startswith(b'XGB1'))
                self.assertNotIn(secret.encode(), encrypted)
                report = {'updated': int(time.time()), 'plans': [{'id': 17, 'eligible': True, 'label': 'fixture'}]}
                (root / 'webshare/report.json').write_text(json.dumps(report))
                selected = json.dumps({'plan_id': 17, 'enabled': True}).encode()
                self.assertEqual(request(port, '/api/webshare', 'PUT', selected, cookie, csrf)[0], 200)
                action = json.dumps({'action': 'rotate', 'country': 'US'}).encode()
                self.assertEqual(request(port, '/api/webshare/action', 'POST', action, cookie, csrf)[0], 200)
                with closing(sqlite3.connect(db_file)) as db:
                    before = db.execute("SELECT COUNT(*) FROM events WHERE action='webshare_configured'").fetchone()[0]
                    self.assertEqual(before, 2)
                    db.execute("CREATE TRIGGER reject_webshare BEFORE INSERT ON events WHEN NEW.action='webshare_configured' BEGIN SELECT RAISE(ABORT,'fixture'); END")
                    db.commit()
                new_body = json.dumps({'api_key': 'another-synthetic-api-key'}).encode()
                self.assertEqual(request(port, '/api/webshare', 'PUT', new_body, cookie, csrf)[0], 503)
                self.assertTrue((root / 'webshare/pending.xgb').exists())
                self.assertEqual(request(port, '/api/webshare', cookie=cookie)[0], 503)
                with closing(sqlite3.connect(db_file)) as db:
                    db.execute('DROP TRIGGER reject_webshare')
                    db.commit()
                status, _, data = request(port, '/api/webshare', cookie=cookie)
                self.assertEqual(status, 200)
                self.assertTrue(json.loads(data)['key_saved'])
                self.assertNotIn(b'another-synthetic-api-key', data)
                self.assertFalse((root / 'webshare/pending.xgb').exists())
                self.assertEqual(request(port, '/api/webshare', cookie=cookie)[0], 200)
                with closing(sqlite3.connect(db_file)) as db:
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE action='webshare_configured'").fetchone()[0], before + 1)
                    self.assertFalse(any(secret in str(row) for row in db.execute('SELECT action,detail FROM events')))
            finally:
                stop(gateway)
                stop(panel)
