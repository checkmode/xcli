"""Compare node grant validation with the legacy Python node agent."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import node_agent

UID = 'a' * 32
UUID = '01234567-89ab-cdef-0123-456789abcdef'


def legacy(response, pending, now):
    try:
        with patch.object(node_agent.time, 'time', return_value=now):
            users = node_agent.desired_users(response)
        if response['ack'] != pending:
            raise node_agent.AgentError('Acknowledgement mismatch')
        remaining = response['lease_seconds'] - max(0, now - response['issued_at'])
        if remaining <= 0:
            raise node_agent.AgentError('Expired in transit')
        return {'ok': True, 'users': users, 'remaining': remaining}
    except (node_agent.AgentError, ValueError, TypeError, KeyError):
        return {'ok': False}


class ProtocolCompatibility(unittest.TestCase):
    def test_grant_validation_and_remaining_lease(self):
        original = {'revision': 'f' * 64, 'users': [{'id': UID, 'uuid': UUID, 'expires': 0}],
                    'lease_seconds': 30, 'issued_at': 1000, 'ack': []}
        variants = []
        def variant(key, value):
            result = copy.deepcopy(original)
            result[key] = value
            variants.append((result, [], 1005.0))
        variants.append((original, [], 1005.0))
        variant('lease_seconds', 9)
        variant('lease_seconds', True)
        variant('lease_seconds', 61)
        variant('issued_at', 969)
        variant('revision', 'z' * 64)
        variant('users', [{'id': UID, 'uuid': UUID.upper(), 'expires': 0}])
        variant('users', [{'id': UID, 'uuid': UUID, 'expires': 0, 'extra': 1}])
        variant('users', [{'id': UID, 'uuid': UUID, 'expires': 0}] * 2)
        variant('users', [{'id': UID, 'uuid': UUID, 'expires': 1005}])
        variants.append((original, [{'id': UID, 'upload': 1, 'download': 0}], 1005.0))
        expired = copy.deepcopy(original); expired['lease_seconds'] = 10
        variants.append((expired, [], 1010.0))
        driver = subprocess.Popen([os.environ['XCLI_PROTOCOL_DRIVER']], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        try:
            for response, pending, now in variants:
                driver.stdin.write(json.dumps({'response': response, 'pending': pending, 'now': now}) + '\n')
                driver.stdin.flush()
                line = driver.stdout.readline()
                self.assertTrue(line, 'Rust test driver exited early')
                self.assertEqual(json.loads(line), legacy(response, pending, now), response)
        finally:
            driver.stdin.close(); driver.wait(timeout=10)
            driver.stdout.close(); driver.stderr.close()
            self.assertEqual(driver.returncode, 0)


if __name__ == '__main__':
    unittest.main()
