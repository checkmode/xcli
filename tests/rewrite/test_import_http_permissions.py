"""Exercise the experimental import report across a real privilege boundary."""
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


UID = int(os.environ.get('XCLI_TEST_REPORT_UID', '0'))
GID = int(os.environ.get('XCLI_TEST_REPORT_GID', '0'))


@unittest.skipUnless(os.geteuid() == 0 and UID and GID and PANEL and Path(PANEL).is_file(),
                     'requires root, an unprivileged fixture account and the experimental panel')
class ImportHttpPermissions(unittest.TestCase):
    def test_admin_only_filtered_report_rejects_unsafe_and_stale_sources(self):
        with tempfile.TemporaryDirectory(prefix='xcli-import-http-', dir='/run') as folder:
            root = Path(folder)
            root.chmod(0o755)
            private = root / 'panel'
            private.mkdir(mode=0o700)
            os.chown(private, UID, GID)
            key = private / 'security.key'
            key.write_bytes(bytes(range(32)))
            key.chmod(0o600)
            os.chown(key, UID, GID)
            settings = private / 'settings.json'
            settings.write_text(json.dumps({'origin': 'https://testserver', 'domain': 'testserver',
                                            'residential_exits': []}))
            os.chown(settings, UID, GID)
            inbox = private / 'proxy-import'
            inbox.mkdir(mode=0o700)
            os.chown(inbox, UID, GID)
            db_file = private / 'gateway.sqlite'
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
            os.chown(db_file, UID, GID)
            reports = root / 'reports'
            reports.mkdir(mode=0o750)
            os.chown(reports, 0, GID)
            report = reports / 'report.json'
            stamp = int(time.time())
            raw = {'schema': 1, 'id': 'a' * 32, 'status': 'ready', 'updated': stamp,
                   'expires': stamp + 120, 'rows': [{'tag': 'residential-27', 'exit_ip': '8.8.8.8',
                   'label': 'fixture', 'password': 'synthetic-secret', 'ws_path': '/synthetic-secret'}],
                   'password': 'synthetic-secret'}

            def write_report():
                report.write_text(json.dumps(raw))
                os.chown(report, 0, GID)
                report.chmod(0o640)

            write_report()
            port = free_port()
            panel = subprocess.Popen(
                [PANEL, '--experimental', '--db', str(db_file), '--secret-key', str(key),
                 '--origin', 'https://testserver', '--port', str(port), '--settings', str(settings),
                 '--experimental-import-report-dir', str(reports),
                 '--experimental-import-report-gid', str(GID), '--experimental-import-inbox', str(inbox)],
                user=UID, group=GID, extra_groups=[], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                wait_ready(panel, port)
                self.assertEqual(request(port, '/api/proxy-import')[0], 401)
                body = json.dumps({'username': 'admin', 'password': 'fixture-password', 'code': ''}).encode()
                status, headers, login_data = request(port, '/api/login', 'POST', body)
                self.assertEqual(status, 200)
                cookie = headers['set-cookie'].split(';', 1)[0]
                csrf = json.loads(login_data)['csrf']
                status, _, data = request(port, '/api/proxy-import', cookie=cookie)
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(data)['rows'][0]['tag'], 'residential-27')
                self.assertNotIn(b'synthetic-secret', data)
                preview = json.dumps({'action': 'preview', 'protocol': 'socks', 'label': 'fixture',
                                      'text': '1.1.1.1:80:fixture:synthetic-password'}).encode()
                self.assertEqual(request(port, '/api/proxy-import', 'POST', preview)[0], 401)
                self.assertEqual(request(port, '/api/proxy-import', 'POST', preview, cookie, 'wrong')[0], 403)
                self.assertEqual(request(port, '/api/proxy-import', 'POST', preview, cookie, csrf,
                                         origin='https://evil.example')[0], 403)
                apply = json.dumps({'action': 'apply', 'preview_id': 'a' * 32}).encode()
                self.assertEqual(request(port, '/api/proxy-import', 'POST', apply, cookie, csrf)[0], 409)
                self.assertFalse((inbox / 'request.xgb').exists())
                invalid = json.dumps({'action': 'preview', 'protocol': 'socks', 'label': 'fixture',
                                      'text': '127.0.0.1:80:user:password'}).encode()
                self.assertEqual(request(port, '/api/proxy-import', 'POST', invalid, cookie, csrf)[0], 422)
                status, _, data = request(port, '/api/proxy-import', 'POST', preview, cookie, csrf)
                self.assertEqual(status, 202)
                self.assertTrue(json.loads(data)['pending'])
                self.assertNotIn(b'synthetic-password', data)
                encrypted = (inbox / 'request.xgb').read_bytes()
                self.assertTrue(encrypted.startswith(b'XGB1'))
                self.assertNotIn(b'synthetic-password', encrypted)
                self.assertEqual(request(port, '/api/proxy-import', 'POST', preview, cookie, csrf)[0], 409)
                with closing(sqlite3.connect(db_file)) as db:
                    events = db.execute("SELECT action,detail FROM events WHERE action='proxy_import_requested'").fetchall()
                    self.assertEqual(len(events), 1)
                    self.assertNotIn('synthetic-password', str(events))
                for updated in (stamp - 120, stamp + 120):
                    raw['updated'] = updated
                    write_report()
                    self.assertEqual(json.loads(request(port, '/api/proxy-import', cookie=cookie)[2])['status'], 'unavailable')
                    self.assertEqual(request(port, '/api/proxy-import', 'POST', preview, cookie, csrf)[0], 503)
                    self.assertEqual((inbox / 'request.xgb').read_bytes(), encrypted)
                raw['updated'] = stamp
                raw['expires'] = stamp
                write_report()
                expired = json.loads(request(port, '/api/proxy-import', cookie=cookie)[2])
                self.assertEqual(expired['status'], 'expired')
                self.assertNotIn('rows', expired)
                raw['expires'] = stamp + 120
                write_report()
                report.chmod(0o660)
                self.assertEqual(json.loads(request(port, '/api/proxy-import', cookie=cookie)[2])['status'], 'unavailable')
                report.chmod(0o640)
                root.chmod(0o777)
                self.assertEqual(json.loads(request(port, '/api/proxy-import', cookie=cookie)[2])['status'], 'unavailable')
                root.chmod(0o755)
                report.unlink()
                report.symlink_to(key)
                self.assertEqual(json.loads(request(port, '/api/proxy-import', cookie=cookie)[2])['status'], 'unavailable')
            finally:
                stop(panel)


if __name__ == '__main__':
    unittest.main()
