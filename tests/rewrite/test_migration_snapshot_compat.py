"""Compare detached synthetic legacy SQLite snapshots, never production state."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

OLD = os.environ.get('XCLI_LEGACY_TRAFFIC_DRIVER', '')
NEW = os.environ.get('XCLI_MIGRATION_DRIVER', '')


@unittest.skipUnless(OLD and NEW and Path(OLD).is_file() and Path(NEW).is_file(),
                     'set XCLI_LEGACY_TRAFFIC_DRIVER and XCLI_MIGRATION_DRIVER')
class SnapshotCompatibility(unittest.TestCase):
    def test_legacy_full_schema_copies_and_sensitive_data_changes(self):
        with tempfile.TemporaryDirectory(prefix='xcli-migration-compat-') as folder:
            root = Path(folder)
            state = root / 'legacy-state'
            settings = root / 'settings.json'
            settings.write_text(json.dumps({'origin': 'https://testserver', 'domain': 'testserver',
                'public_ip': '203.0.113.2', 'reality_sni': 'example.com', 'reality_public': 'p' * 43,
                'short_id': 'aabbccdd', 'ws_path': '/connect/test'}))
            process = subprocess.Popen([OLD, str(state), str(settings)], stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            try:
                self.assertEqual(json.loads(process.stdout.readline()), {'ready': True})
            finally:
                process.stdin.close()
                self.assertEqual(process.wait(timeout=15), 0)
                process.stdout.close()
            source = sqlite3.connect(state / 'gateway.sqlite')
            source.execute("INSERT INTO admin VALUES(1,'fixture-password-hash')")
            source.execute("UPDATE mfa SET secret='fixture-mfa-secret', enabled=1 WHERE id=1")
            source.execute("INSERT INTO recovery_codes VALUES('fixture-recovery-hash',0)")
            source.execute("INSERT INTO metadata VALUES('remote_nodes_v1','synthetic-node-registration')")
            source.execute("INSERT INTO metadata VALUES('rule_templates_v1','synthetic-template')")
            source.execute("UPDATE users SET upload=100,download=200")
            source.commit()
            before = root / 'before.sqlite'
            after = root / 'after.sqlite'
            for path in (before, after):
                target = sqlite3.connect(path)
                source.backup(target)
                target.close()
            source.close()

            def compare():
                return subprocess.check_output([NEW, str(before), str(after)], text=True, timeout=15).strip()

            self.assertRegex(compare(), r'^ok [0-9]+ 1$')
            with sqlite3.connect(after) as db:
                db.execute('UPDATE users SET upload=101,download=201')
            self.assertRegex(compare(), r'^ok [0-9]+ 1$')
            with sqlite3.connect(after) as db:
                db.execute('UPDATE users SET upload=99')
            self.assertEqual(compare(), 'error UsageDecreased')
            with sqlite3.connect(after) as db:
                db.execute('UPDATE users SET upload=100')
                db.execute("UPDATE metadata SET value='changed' WHERE key='remote_nodes_v1'")
            self.assertEqual(compare(), 'error DataChanged')
            with sqlite3.connect(after) as db:
                db.execute("UPDATE metadata SET value='synthetic-node-registration' WHERE key='remote_nodes_v1'")
                db.execute('ALTER TABLE users ADD COLUMN unwanted TEXT')
            self.assertEqual(compare(), 'error SchemaChanged')
