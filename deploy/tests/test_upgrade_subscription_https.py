import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import subscription_https as policy
import upgrade_subscription_https as upgrade


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); root = Path(self.temp.name)
        self.core = root / 'core.json'; self.settings = root / 'settings.json'; self.firewall = root / 'firewall.sh'
        self.backups = root / 'backups'; self.lock = root / 'lock'
        config = {'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'blocked', 'protocol': 'blackhole'}],
                  'routing': {'rules': [{'type': 'field', 'ip': ['127.0.0.0/8', '8.8.4.4/32'], 'outboundTag': 'blocked'}]}}
        self.core.write_text(json.dumps(policy.core_candidate(config, '8.8.4.4', 'a' * 32)))
        self.settings.write_text(json.dumps({'public_ip': '8.8.4.4'}))
        self.firewall.write_text('#!/bin/sh\n    iptables -w -A XG_OUT -m addrtype --dst-type LOCAL -j REJECT\n'
                                 '    for net in 127.0.0.0/8 8.8.4.4/32; do iptables -w -A XG_OUT -d "$net" -j REJECT; done\n')
        self.calls = []; self.inserted = False; self.fail_restart = False
        self.patches = [patch.object(upgrade, 'CORE', self.core), patch.object(upgrade, 'SETTINGS', self.settings),
                        patch.object(upgrade, 'FIREWALL', self.firewall), patch.object(upgrade, 'BACKUPS', self.backups),
                        patch.object(upgrade, 'LOCK', str(self.lock)), patch.object(upgrade.os, 'geteuid', return_value=0),
                        patch.object(upgrade.os, 'chown'), patch.object(upgrade, 'run', side_effect=self.fake_run)]
        for p in self.patches: p.start()

    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.temp.cleanup()

    def fake_run(self, *args):
        self.calls.append(args)
        if args[:4] == ('iptables', '-w', '-S', 'XG_OUT'):
            return ('-N XG_OUT\n' + ('-A XG_OUT -d 8.8.4.4/32 -p tcp -m tcp --dport 443 -j RETURN\n' if self.inserted else '') +
                    '-A XG_OUT -m addrtype --dst-type LOCAL -j REJECT\n')
        if args[:4] == ('iptables', '-w', '-I', 'XG_OUT'): self.inserted = True
        if args[:4] == ('iptables', '-w', '-D', 'XG_OUT'): self.inserted = False
        if args[:2] == ('systemctl', 'restart') and self.fail_restart:
            self.fail_restart = False
            raise RuntimeError('simulated failure')
        return ''

    def test_dry_run_and_apply_are_scoped_and_idempotent(self):
        old = self.core.read_bytes(), self.firewall.read_bytes()
        self.assertEqual(upgrade.main()['status'], 'ready')
        self.assertEqual((self.core.read_bytes(), self.firewall.read_bytes()), old)
        result = upgrade.main(True)
        self.assertEqual(result['status'], 'applied')
        rules = json.loads(self.core.read_text())['routing']['rules']
        self.assertEqual(rules[0], policy.all_users_rule_for('8.8.4.4'))
        self.assertEqual(len(rules), 2)
        self.assertLess(self.firewall.read_text().index('--dport 443'), self.firewall.read_text().index('--dst-type LOCAL'))
        self.assertTrue(self.inserted)
        self.assertEqual(upgrade.main(True)['status'], 'unchanged')

    def test_restart_failure_restores_files_and_runtime_rule(self):
        before = self.core.read_bytes(), self.firewall.read_bytes()
        self.fail_restart = True
        with self.assertRaisesRegex(RuntimeError, '已恢复原配置'): upgrade.main(True)
        self.assertEqual((self.core.read_bytes(), self.firewall.read_bytes()), before)
        self.assertFalse(self.inserted)


if __name__ == '__main__': unittest.main()
