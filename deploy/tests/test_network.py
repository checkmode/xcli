"""Exercise tuning transactions against a fake kernel; no host settings are changed."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import network


class NetworkTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        root = Path(self.work.name)
        for name in ('STATE', 'PROFILE', 'MODULES', 'SERVICE'):
            path = root / name / ('network-before.json' if name == 'STATE' else name.lower())
            path.parent.mkdir()
            patcher = patch.object(network, name, path)
            patcher.start();self.addCleanup(patcher.stop)
        self.original = {'net.ipv4.tcp_congestion_control': 'cubic', 'net.core.default_qdisc': 'fq_codel',
                         'net.core.rmem_max': '33554432', 'net.core.wmem_max': '4194304'}
        self.values = dict(self.original)
        self.queue = {'kind': 'pfifo_fast', 'root': True, 'options': {}}
        self.fail_queue = False
        patcher = patch.object(network, 'run', side_effect=self.command)
        patcher.start();self.addCleanup(patcher.stop)

    def command(self, *args, check=True):
        args = list(map(str, args))
        if args[:3] == ['ip', '-j', '-4']:
            return '[{"dev":"eth0"}]'
        if args[:2] == ['sysctl', '-n']:
            return 'reno cubic bbr' if args[2].endswith('available_congestion_control') else self.values[args[2]]
        if args[:2] == ['sysctl', '-w']:
            key, value = args[2].split('=', 1);self.values[key] = value
        if args[:3] == ['tc', '-j', 'qdisc']:
            return json.dumps([self.queue])
        if args[:3] == ['tc', 'qdisc', 'replace']:
            if self.fail_queue and args[-1] == 'fq':
                raise RuntimeError('injected qdisc failure')
            self.queue = {'kind': args[6], 'root': True, 'options': {}}
        return ''

    def test_roundtrip_preserves_larger_buffers_and_original_algorithm(self):
        network.apply('eth0')
        self.assertEqual(self.values['net.core.rmem_max'], '33554432')
        self.assertEqual(self.values['net.core.wmem_max'], str(network.MIB16))
        self.assertEqual(self.values['net.ipv4.tcp_congestion_control'], 'bbr')
        self.assertEqual(self.queue['kind'], 'fq')
        self.assertEqual(network.STATE.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            network.apply('eth0')
        network.restore()
        self.assertEqual(self.values, self.original)
        self.assertEqual(self.queue['kind'], 'pfifo_fast')
        self.assertFalse(network.STATE.exists())
        self.assertFalse(network.PROFILE.exists())

    def test_apply_failure_restores_partial_sysctl_changes(self):
        self.fail_queue = True
        with self.assertRaises(RuntimeError):
            network.apply('eth0')
        self.assertEqual(self.values, self.original)
        self.assertFalse(network.STATE.exists())

    def test_external_file_edit_is_never_overwritten_on_restore(self):
        network.apply('eth0')
        network.PROFILE.write_text('# changed by administrator\n')
        with self.assertRaises(ValueError):
            network.restore()
        self.assertTrue(network.STATE.exists())
        self.assertEqual(network.PROFILE.read_text(), '# changed by administrator\n')

    def test_complex_queue_is_not_replaced(self):
        self.queue = {'kind': 'mq', 'root': True, 'options': {}}
        network.apply('eth0')
        self.assertEqual(self.queue['kind'], 'mq')
        network.restore()
        self.assertEqual(self.queue['kind'], 'mq')

    def test_fq_codel_options_can_be_restored(self):
        args = network.restore_queue({'kind': 'fq_codel', 'options': {'limit': 10240, 'flows': 1024,
            'target': 4999, 'interval': 99999, 'memory_limit': 33554432, 'ecn': True}})
        self.assertIn('4999us', args)
        self.assertIn('ecn', args)
        self.assertIsNone(network.restore_queue({'kind': 'fq_codel', 'options': {'unrecognized': 1}}))


if __name__ == '__main__':
    unittest.main()
