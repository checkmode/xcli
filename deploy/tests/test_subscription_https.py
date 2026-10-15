import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import subscription_https as s


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.user = 'a' * 32
        self.core = {'inbounds': [{'tag': 'unchanged'}],
                     'outbounds': [{'tag': 'direct', 'protocol': 'freedom'},
                                   {'tag': 'blocked', 'protocol': 'blackhole'}],
                     'routing': {'domainStrategy': 'IPOnDemand', 'rules': [
                         {'type': 'field', 'ip': ['127.0.0.0/8', '8.8.4.4/32'],
                          'outboundTag': 'blocked'}]}}

    def test_original_config_and_block_stay_intact(self):
        before = copy.deepcopy(self.core)
        result = s.core_candidate(self.core, '8.8.4.4', self.user)
        self.assertEqual(self.core, before)
        rule = result['routing']['rules'].pop(0)
        self.assertEqual(result, before)
        self.assertEqual(rule['ip'], ['8.8.4.4/32'])
        self.assertEqual((rule['network'], rule['port']), ('tcp', '443'))
        self.assertEqual(len(rule['user']), 1)

    def test_missing_or_conflicting_policy_fails_closed(self):
        result = s.core_candidate(self.core, '8.8.4.4', self.user)
        with self.assertRaises(ValueError):
            s.core_candidate(result, '8.8.4.4', self.user)
        for mutation in ('self-block', 'direct'):
            value = copy.deepcopy(self.core)
            if mutation == 'self-block':
                value['routing']['rules'] = []
            else:
                value['outbounds'] = []
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                s.core_candidate(value, '8.8.4.4', self.user)

    def test_private_addresses_and_injection_rejected(self):
        for address, user in [('127.0.0.1', self.user), ('8.8.4.4;id', self.user),
                              ('8.8.4.4', '.*'), ('::1', self.user), ('224.0.0.1', self.user)]:
            with self.subTest(address=address), self.assertRaises(ValueError):
                s.rule_for(address, user)

    def test_firewall_preserves_existing_text_and_rejects_ambiguity(self):
        source = '#!/bin/sh\n    for net in 10.0.0.0/8 8.8.4.4/32; do iptables -w -A XG_OUT -d "$net" -j REJECT; done\n'
        result = s.firewall_candidate(source, '8.8.4.4')
        self.assertEqual(''.join(line for line in result.splitlines(keepends=True)
                                 if '--dport 443' not in line), source)
        for bad in (source + source, '#!/bin/sh\n', result):
            with self.assertRaises(ValueError):
                s.firewall_candidate(bad, '8.8.4.4')
        with self.assertRaises(ValueError):
            s.firewall_candidate(source, '224.0.0.1')


if __name__ == '__main__':
    unittest.main()
