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

    def test_all_users_migrates_scoped_rule_without_touching_other_routes(self):
        old = s.core_candidate(self.core, '8.8.4.4', self.user)
        before = copy.deepcopy(old)
        new = s.all_users_candidate(old, '8.8.4.4')
        self.assertEqual(old, before)
        self.assertEqual(new['routing']['rules'], [s.all_users_rule_for('8.8.4.4')] + self.core['routing']['rules'])
        self.assertEqual(s.all_users_candidate(new, '8.8.4.4'), new)
        for bad in ({'ip': ['0.0.0.0/0']}, {'user': ['regexp:.*']}, {'port': '1-65535'}, {'network': 'tcp,udp'}):
            broken = copy.deepcopy(new); broken['routing']['rules'][0].update(bad)
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                s.all_users_candidate(broken, '8.8.4.4')
        broken = copy.deepcopy(old); broken['routing']['rules'][0]['port'] = '1-65535'
        with self.assertRaises(ValueError): s.all_users_candidate(broken, '8.8.4.4')
        settings = {'public_ip': '8.8.4.4'}
        self.assertTrue(s.is_bootstrap_rule(new['routing']['rules'][0], settings, new))
        for bad in ({'ip': ['0.0.0.0/0']}, {'user': ['regexp:.*']}, {'port': '1-65535'}):
            altered = copy.deepcopy(new['routing']['rules'][0]); altered.update(bad)
            self.assertFalse(s.is_bootstrap_rule(altered, settings, new))

    def test_custom_public_port_stays_scoped_to_self_address(self):
        result = s.core_candidate(self.core, '8.8.4.4', self.user, 1443)
        self.assertEqual(result['routing']['rules'][0]['port'], '1443')
        self.assertEqual(result['routing']['rules'][0]['ip'], ['8.8.4.4/32'])
        source = '#!/bin/sh\n    for net in 10.0.0.0/8 8.8.4.4/32; do iptables -w -A XG_OUT -d "$net" -j REJECT; done\n'
        self.assertIn('--dport 1443 -j RETURN', s.firewall_candidate(source, '8.8.4.4', 1443))

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

    def test_exception_precedes_local_address_reject(self):
        source = ('#!/bin/sh\n'
                  '    iptables -w -A XG_OUT -m addrtype --dst-type LOCAL -j REJECT\n'
                  '    for net in 10.0.0.0/8 8.8.4.4/32; do iptables -w -A XG_OUT -d "$net" -j REJECT; done\n')
        result = s.firewall_candidate(source, '8.8.4.4')
        self.assertLess(result.index('--dport 443 -j RETURN'), result.index('--dst-type LOCAL'))
        with self.assertRaises(ValueError):
            s.firewall_candidate(source.replace('    for net',
                '    iptables -w -A XG_OUT -m addrtype --dst-type LOCAL -j REJECT\n    for net'), '8.8.4.4')
        self.assertEqual(s.all_users_firewall_candidate(result, '8.8.4.4'), result)
        command = '    iptables -w -A XG_OUT -d 8.8.4.4/32 -p tcp --dport 443 -j RETURN\n'
        late = source.replace('    for net', command + '    for net')
        self.assertEqual(s.all_users_firewall_candidate(late, '8.8.4.4'), result)
        with self.assertRaises(ValueError): s.all_users_firewall_candidate(result + command, '8.8.4.4')


if __name__ == '__main__':
    unittest.main()
