"""Compare isolated Rust and legacy Python ledgers, including persisted SQLite state.

Run with XCLI_LEDGER_DRIVER pointing to the built ledger_driver example.
Neither implementation may use a live node database in this test.
"""
import json
import os
from contextlib import closing
from pathlib import Path
import random
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from node_ledger import Ledger, LedgerError

USER_A = 'a' * 32
USER_B = 'b' * 32


def counter(user, direction, value, tag='reality'):
    return {'name': f'user>>>{user}.01234567@{tag}>>>traffic>>>{direction}', 'value': value}


class RustLedger:
    def __init__(self, path):
        self.process = subprocess.Popen([os.environ['XCLI_LEDGER_DRIVER'], str(path)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

    def call(self, operation):
        self.process.stdin.write(json.dumps(operation) + '\n')
        self.process.stdin.flush()
        reply = self.process.stdout.readline()
        if not reply:
            raise RuntimeError('Rust ledger driver stopped unexpectedly')
        return json.loads(reply)

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=10)
        self.process.stdout.close()
        self.process.stderr.close()
        if self.process.returncode:
            raise RuntimeError('Rust ledger driver exited unsuccessfully')


def python_call(ledger, operation):
    try:
        if operation['op'] == 'record':
            result = ledger.record(operation['generation'], operation['counters'])
        elif operation['op'] == 'pending':
            result = ledger.pending(operation['limit'])
        else:
            result = ledger.acknowledge(operation['entries'])
        return {'ok': True, 'value': result}
    except (LedgerError, sqlite3.Error, ValueError, OverflowError):
        return {'ok': False}


def database_snapshot(path):
    with closing(sqlite3.connect(path)) as db:
        return {table: db.execute('SELECT * FROM ' + table + ' ORDER BY 1').fetchall()
                for table in ('node_totals', 'node_counters', 'node_meta')}


class LedgerCompatibility(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_path = Path(self.tmp.name) / 'legacy.sqlite'
        self.new_path = Path(self.tmp.name) / 'rust.sqlite'
        self.old = Ledger(self.old_path)
        self.new = RustLedger(self.new_path)

    def tearDown(self):
        if self.old:
            self.old.close()
        if self.new:
            self.new.close()
        self.tmp.cleanup()

    def compare(self, operation):
        old = python_call(self.old, operation)
        new = self.new.call(operation)
        self.assertEqual(old, new, operation)
        self.assertEqual(database_snapshot(self.old_path), database_snapshot(self.new_path), operation)
        return old

    def test_generation_replay_acknowledgement_and_atomic_failures(self):
        operations = [
            {'op': 'record', 'generation': 'one', 'counters': [counter(USER_A, 'uplink', '80'), counter(USER_B, 'downlink', 15)]},
            {'op': 'pending', 'limit': 100},
            {'op': 'acknowledge', 'entries': [{'id': USER_A, 'upload': 80, 'download': 0}]},
            {'op': 'record', 'generation': 'one', 'counters': [counter(USER_A, 'uplink', 80)]},
            {'op': 'record', 'generation': 'one', 'counters': [counter(USER_B, 'uplink', 23), counter(USER_A, 'uplink', 79)]},
            {'op': 'record', 'generation': 'one', 'counters': [counter(USER_A, 'uplink', 81), counter(USER_A, 'uplink', 82)]},
            {'op': 'acknowledge', 'entries': [{'id': USER_B, 'upload': 0, 'download': 15}, {'id': USER_A, 'upload': 81, 'download': 0}]},
            {'op': 'record', 'generation': 'two', 'counters': [counter(USER_A, 'uplink', 5), counter(USER_B, 'downlink', '1')]},
            {'op': 'acknowledge', 'entries': [{'id': USER_A, 'upload': 80, 'download': 0}, {'id': USER_B, 'upload': 0, 'download': 16}]},
            {'op': 'pending', 'limit': 1},
            {'op': 'acknowledge', 'entries': [{'id': USER_A, 'upload': 79, 'download': 0}]},
            {'op': 'pending', 'limit': 100},
        ]
        for op in operations:
            self.compare(op)

    def test_value_validation_unknown_counters_and_overflow(self):
        values = [None, -1, True, 0.1, '01', '-1', '9223372036854775808', '', {}, []]
        for value in values:
            self.compare({'op': 'record', 'generation': 'one', 'counters': [counter(USER_A, 'uplink', value)]})
        self.compare({'op': 'record', 'generation': 'one', 'counters': [{'name': 'unrelated', 'value': False}]})
        self.compare({'op': 'record', 'generation': 'one', 'counters': [{'name': counter(USER_A, 'uplink', 0)['name']}]})
        self.compare({'op': 'record', 'generation': 'one', 'counters': [counter(USER_A, 'uplink', 2**63 - 1)]})
        self.compare({'op': 'record', 'generation': 'two', 'counters': [counter(USER_A, 'uplink', 1)]})
        self.compare({'op': 'pending', 'limit': 0})
        self.compare({'op': 'pending', 'limit': 501})

    def test_seeded_cumulative_updates_and_legacy_database_interop(self):
        rng = random.Random(4201)
        values = {USER_A: 0, USER_B: 0}
        for _ in range(60):
            user = rng.choice([USER_A, USER_B]); values[user] += rng.randrange(0, 50)
            self.compare({'op': 'record', 'generation': 'one', 'counters': [counter(user, 'uplink', values[user])]})
            if rng.randrange(4) == 0:
                self.compare({'op': 'acknowledge', 'entries': [{'id': user, 'upload': values[user], 'download': 0}]})
        expected = self.compare({'op': 'pending', 'limit': 100})['value']
        self.old.close(); self.old = None
        self.new.close(); self.new = None
        # Each implementation must read the other implementation's persisted schema and progress.
        legacy_read = Ledger(self.new_path)
        self.assertEqual(legacy_read.pending(), expected)
        legacy_read.close()
        rust_read = RustLedger(self.old_path)
        self.assertEqual(rust_read.call({'op': 'pending', 'limit': 100})['value'], expected)
        rust_read.close()


if __name__ == '__main__':
    unittest.main()
