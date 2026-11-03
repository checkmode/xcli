import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from node_agent import AgentError, NodeAgent, desired_users, panel_url
from node_ledger import Ledger

NODE = 'a' * 32
TOKEN = 'Z' * 43
USER = 'b' * 32
CREDENTIAL = str(uuid.uuid4())
REVISION = 'c' * 64


class FakeCore:
    def __init__(self):
        self.process = None
        self.generation = ''
        self.users = {}
        self.stats = []
        self.restarts = 0
    def start(self):
        self.process = object()
        self.generation = 'core-' + str(self.restarts)
    def counters(self): return list(self.stats)
    def apply(self, users):
        if set(self.users) - set(users):
            self.restarts += 1
            self.generation = 'core-' + str(self.restarts)
            self.stats = []
        self.users = dict(users)
    def stop(self):
        self.process = None
        self.users = {}


class AgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = Ledger(Path(self.temp.name) / 'node.sqlite')
        self.core = FakeCore()
        self.now = 100
        self.requests = []
        self.desired = [{'id': USER, 'uuid': CREDENTIAL, 'expires': 0}]
        def sender(origin, node_id, token, payload):
            self.requests.append(payload)
            return {'revision': REVISION, 'users': self.desired, 'lease_seconds': 30,
                    'issued_at': int(time.time()), 'ack': payload['counters']}
        self.agent = NodeAgent(NODE, TOKEN, 'https://panel.example.com', self.ledger, self.core,
                               sender=sender, monotonic=lambda: self.now)

    def tearDown(self):
        self.ledger.close()
        self.temp.cleanup()

    def test_selected_users_added_and_accounting_acknowledged(self):
        self.agent.synchronize()
        self.assertEqual(set(self.core.users), {USER})
        name = 'user>>>' + USER + '.' + CREDENTIAL[:8] + '@websocket>>>traffic>>>uplink'
        self.core.stats = [{'name': name, 'value': '80'}]
        self.agent.synchronize()
        self.assertEqual(self.requests[-1]['counters'], [{'id': USER, 'upload': 80, 'download': 0}])
        self.assertEqual(self.ledger.pending(), [])
        self.agent.synchronize()
        self.assertEqual(self.requests[-1]['counters'], [])

    def test_expired_lease_revokes_all_users(self):
        self.agent.synchronize()
        self.now += 31
        self.agent.check_lease()
        self.assertEqual(self.core.users, {})
        self.assertEqual(self.core.restarts, 1)
        self.assertEqual(self.agent.revision, '')

    def test_removed_user_is_revoked(self):
        self.agent.synchronize()
        self.desired = []
        self.agent.synchronize()
        self.assertEqual(self.core.users, {})
        self.assertEqual(self.core.restarts, 1)

    def test_watchdog_thread_can_sample_the_shared_ledger(self):
        self.agent.synchronize()
        errors = []
        def tick():
            try: self.agent.check_lease()
            except Exception as error: errors.append(error)
        thread = threading.Thread(target=tick)
        thread.start(); thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(set(self.core.users), {USER})

    def test_response_expired_in_transit_does_not_extend_access(self):
        def sender(_origin, _id, _token, payload):
            return {'revision': REVISION, 'users': self.desired, 'lease_seconds': 10,
                    'issued_at': int(time.time()) - 11, 'ack': payload['counters']}
        self.agent.sender = sender
        with self.assertRaises(AgentError): self.agent.synchronize()
        self.assertEqual(self.core.users, {})

    def test_stalled_sync_cannot_hold_an_expired_lease(self):
        class Process:
            terminated = False
            def poll(self): return None
            def terminate(self): self.terminated = True
        process = Process()
        self.core.process = process
        self.agent.lease_until = 99
        with self.agent.lock:
            thread = threading.Thread(target=self.agent.watchdog_tick)
            thread.start(); thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(process.terminated)

    def test_malformed_or_stale_response_cannot_authorize(self):
        invalid = {'revision': REVISION, 'users': self.desired, 'lease_seconds': 30,
                   'issued_at': int(time.time()) - 120, 'ack': []}
        with self.assertRaises(AgentError): desired_users(invalid)
        invalid['issued_at'] = int(time.time())
        invalid['users'] = self.desired * 2
        with self.assertRaises(AgentError): desired_users(invalid)
        invalid['users'] = [{'id': USER, 'uuid': CREDENTIAL, 'expires': 0, 'command': 'ignored'}]
        with self.assertRaises(AgentError): desired_users(invalid)

    def test_non_https_panel_and_redirects_are_rejected(self):
        for value in ('http://example.com', 'https://user:pass@example.com', 'https://example.com/path',
                      'https://example.com/#secret', 'https://example.com/?q=x'):
            with self.subTest(value=value), self.assertRaises(AgentError): panel_url(value)
        self.assertEqual(panel_url('https://example.com:443/'), 'https://example.com:443')

if __name__ == '__main__':
    unittest.main()
