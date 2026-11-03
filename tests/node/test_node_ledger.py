import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from node_ledger import Ledger, LedgerError, MAX_COUNTER

UID = 'a' * 32
NAME = 'user>>>' + UID + '.12345678@reality>>>traffic>>>uplink'

class NodeLedgerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'state.sqlite'
        self.ledger = Ledger(self.path)

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    def sample(self, generation, value):
        self.ledger.record(generation, [{'name': NAME, 'value': value}])

    def test_cumulative_reports_survive_retries_restarts_and_core_generation(self):
        self.sample('core1', 100)
        self.sample('core1', '150')
        report = [{'id': UID, 'upload': 150, 'download': 0}]
        self.assertEqual(self.ledger.pending(), report)
        self.ledger.close()
        self.ledger = Ledger(self.path)
        self.assertEqual(self.ledger.pending(), report)
        self.sample('core2', 20)
        self.ledger.acknowledge(report)
        self.assertEqual(self.ledger.pending(), [{'id': UID, 'upload': 170, 'download': 0}])
        self.ledger.acknowledge(self.ledger.pending())
        self.assertEqual(self.ledger.pending(), [])

    def test_invalid_or_decreasing_counters_are_atomic(self):
        self.sample('core1', 100)
        with self.assertRaises(LedgerError):
            self.ledger.record('core1', [{'name': NAME, 'value': 101}, {'name': NAME, 'value': 102}])
        with self.assertRaises(LedgerError):
            self.sample('core1', 99)
        self.assertEqual(self.ledger.pending()[0]['upload'], 100)
        with self.assertRaises(LedgerError):
            self.sample('core2', MAX_COUNTER)
        self.assertEqual(self.ledger.pending()[0]['upload'], 100)

    def test_untrusted_ack_cannot_discard_unreported_traffic(self):
        self.sample('core1', 10)
        with self.assertRaises(LedgerError):
            self.ledger.acknowledge([{'id': UID, 'upload': 11, 'download': 0}])
        self.assertEqual(self.ledger.pending()[0]['upload'], 10)
        self.sample('core1', 15)
        self.ledger.acknowledge([{'id': UID, 'upload': 10, 'download': 0}])
        self.assertEqual(self.ledger.pending()[0]['upload'], 15)

if __name__ == '__main__':
    unittest.main()
