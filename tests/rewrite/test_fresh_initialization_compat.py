"""Start both panel versions from a newly initialized synthetic database."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

from test_node_service_integration import port
from test_panel_http_integration import request, stop, wait_ready

OLD = os.environ.get('XCLI_LEGACY_PANEL', '')
NEW = os.environ.get('XCLI_PANEL_SERVICE', '')
PROVISION = os.environ.get('XCLI_PROVISION_FIXTURE', '')
INIT_CLI = os.environ.get('XCLI_PANEL_INIT_CLI', '')


@unittest.skipUnless(OLD and NEW and PROVISION and all(Path(p).is_file() for p in (OLD, NEW, PROVISION)),
                     'set legacy panel, experimental panel and isolated provision fixture')
class FreshInitializationCompatibility(unittest.TestCase):
    def test_both_panels_accept_fresh_database_without_schema_changes(self):
        with tempfile.TemporaryDirectory(prefix='xcli-fresh-compat-') as folder:
            root = Path(folder)
            state = root / 'state'
            state.mkdir()
            database = state / 'gateway.sqlite'
            init_args = ([INIT_CLI, '--experimental', '--database', str(database)] if INIT_CLI else [PROVISION, str(database)])
            subprocess.run(init_args, input=b'fixture-password-123\n' if INIT_CLI else None, check=True, timeout=15)
            key = root / 'key'
            key.write_bytes(bytes(range(32)))
            key.chmod(0o600)
            settings = root / 'settings.json'
            settings.write_text(json.dumps({'origin': 'https://testserver', 'domain': 'testserver',
                'public_ip': '203.0.113.2', 'reality_sni': 'www.bing.com', 'reality_public': 'p'*43,
                'short_id': '0123456789abcdef', 'ws_path': '/connect/test'}))

            def schema():
                with sqlite3.connect(database) as db:
                    return db.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name").fetchall()

            original = schema()
            for implementation in ('rust', 'legacy'):
                listen = port()
                if implementation == 'rust':
                    args = [NEW, '--experimental', '--db', str(database), '--secret-key', str(key),
                            '--origin', 'https://testserver', '--port', str(listen)]
                else:
                    args = [OLD, '--state', str(state), '--settings', str(settings), '--static', str(root),
                            '--secret-key', str(key), '--port', str(listen), '--offline', '--no-auto-backup']
                panel = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    wait_ready(panel, listen)
                    body = json.dumps({'username': 'admin', 'password': 'fixture-password-123', 'code': ''}).encode()
                    status, _, data = request(listen, '/api/login', 'POST', body)
                    self.assertEqual(status, 200)
                    self.assertEqual(json.loads(data)['username'], 'admin')
                    self.assertEqual(schema(), original, f'{implementation} changed the fresh schema')
                finally:
                    stop(panel)
            with sqlite3.connect(database) as db:
                self.assertEqual(db.execute('PRAGMA quick_check').fetchone(), ('ok',))
                self.assertEqual(db.execute('SELECT count(*) FROM users').fetchone(), (0,))
            existing = subprocess.run(init_args, input=b'fixture-password-123\n' if INIT_CLI else None,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            self.assertNotEqual(existing.returncode, 0, 'fixture overwrote an existing database')
            self.assertEqual(schema(), original)
            if INIT_CLI:
                invalid = state/'invalid.sqlite'
                result = subprocess.run([INIT_CLI, '--experimental', '--database', str(invalid)],
                                        input=b'short\n', capture_output=True, timeout=15)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(invalid.exists())
