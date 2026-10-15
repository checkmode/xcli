import copy
import json
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / 'scripts'))
try:
    import yaml
    import sync_ww_clash as s
except ImportError:
    s = None


@unittest.skipIf(s is None or not shutil.which('node'), 'PyYAML and Node are required')
class SyncTests(unittest.TestCase):
    def fixture(self, root):
        config = root / 'config'
        (config / 'profiles').mkdir(parents=True)
        (config / 'profiles.yaml').write_text('current: selected\nitems:\n- uid: selected\n  file: subscription.yaml\n  option: {merge: m, rules: r, script: s}\n- {uid: m, file: m.yaml}\n- {uid: r, file: r.yaml}\n- {uid: s, file: s.js}\n')
        (config / 'profiles/m.yaml').write_text('custom: retained\n')
        (config / 'profiles/r.yaml').write_text('prepend: ["DOMAIN,custom.example,DIRECT"]\nappend: []\n')
        (config / 'profiles/s.js').write_text('function main(config, profileName) { return config; }')
        subscription = {'rules': ['GEOSITE,cn,DIRECT', 'GEOSITE,cn,DIRECT', 'MATCH,PROXY'],
                        'dns': {'nameserver': ['https://dns.example/dns-query'], 'nameserver-policy': {'geosite:cn': ['https://cn.example/dns-query']}},
                        'proxies': [{'name': 'test', 'type': 'direct'}], 'proxy-groups': [{'name': 'PROXY', 'type': 'select', 'proxies': ['test']}]}
        (config / 'profiles/subscription.yaml').write_text(yaml.safe_dump(subscription, sort_keys=False))
        (config / 'verge.yaml').write_text('system_proxy_bypass: "localhost,*.local,custom.example,*.corp.example.com,corp.example.com,10.40.0.0/16"\n')
        (root / 'zprofile').write_text('fixture')
        policy = {'suffixes': ['corp.example.com'], 'exact': [], 'networks': ['10.40.0.0/16'],
                  'dns': {'corp.example.com': '127.0.0.1:10053'},
                  'system_bypass': ['*.corp.example.com', 'corp.example.com', '10.40.0.0/16']}
        return config, policy, subscription

    def prepare(self, root, config, policy, **kwargs):
        with patch.object(s.local_network_policy, 'load', return_value=policy):
            s.prepare(config, root / 'out', root / 'zprofile', **kwargs)
        return yaml.safe_load((root / 'out/candidate.yaml').read_text())

    def test_subscription_refresh_inherits_new_dns_nodes_and_rules(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            config, policy, subscription = self.fixture(root)
            self.prepare(root, config, policy)
            script = (root / 'out/script.js').read_text()
            subscription['dns']['nameserver'] = ['https://updated.example/dns-query']
            subscription['dns']['nameserver-policy']['geosite:cn'] = ['https://updated-cn.example/dns-query']
            subscription['dns']['fake-ip-filter'] = ['+.upstream.example']
            subscription['proxies'].append({'name': 'new-node', 'type': 'direct'})
            subscription['rules'].insert(0, 'DOMAIN,new.example,PROXY')
            subscription['rules'].append('DOMAIN-SUFFIX,corp.example.com,DIRECT')
            value = s.run_script(script, subscription)
            self.assertEqual(value['dns']['nameserver'], subscription['dns']['nameserver'])
            self.assertEqual(value['dns']['nameserver-policy']['geosite:cn'], subscription['dns']['nameserver-policy']['geosite:cn'])
            self.assertEqual(value['proxies'], subscription['proxies'])
            self.assertEqual(value['proxy-groups'], subscription['proxy-groups'])
            self.assertEqual(value['rules'].count('GEOSITE,cn,DIRECT'), 1)
            self.assertEqual(value['rules'].count('DOMAIN-SUFFIX,corp.example.com,DIRECT'), 1)
            self.assertLess(value['rules'].index('DOMAIN,new.example,PROXY'), value['rules'].index('MATCH,PROXY'))
            self.assertEqual(next(iter(value['dns']['nameserver-policy'])), '+.corp.example.com')
            self.assertIn('+.upstream.example', value['dns']['fake-ip-filter'])
            self.assertEqual(s.run_script(script, value), value)

    def test_migration_removes_only_known_copies_and_preserves_custom(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            config, policy, subscription = self.fixture(root)
            dns = copy.deepcopy(subscription['dns'])
            dns['nameserver-policy']['+.corp.example.com'] = ['127.0.0.1:10053']
            dns['fake-ip-filter'] = ['+.corp.example.com', '+.custom.example']
            dns['direct-nameserver-follow-policy'] = True
            (config / 'profiles/m.yaml').write_text(yaml.safe_dump({'dns': dns, 'custom': 'retained'}))
            (config / 'profiles/r.yaml').write_text(yaml.safe_dump({'prepend': s.local_network_policy.rules(policy) + subscription['rules'] + ['DOMAIN,custom.example,DIRECT']}))
            legacy = root / 'legacy.json'
            legacy.write_text(json.dumps(policy))
            self.prepare(root, config, policy, legacy_policy=legacy)
            merge = yaml.safe_load((root / 'out/merge.yaml').read_text())
            self.assertEqual(merge, {'custom': 'retained', 'dns': {'fake-ip-filter': ['+.custom.example']}})
            self.assertEqual(yaml.safe_load((root / 'out/rules.yaml').read_text())['prepend'], ['DOMAIN,custom.example,DIRECT'])
            self.assertNotIn('https://dns.example', (root / 'out/script.js').read_text())

    def test_removed_policy_disappears_but_upstream_and_bypass_baseline_survive(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            config, policy, subscription = self.fixture(root)
            legacy = root / 'legacy.json'
            legacy.write_text(json.dumps(policy))
            self.prepare(root, config, policy, legacy_policy=legacy)
            s.apply(root / 'out')
            empty = {'suffixes': [], 'exact': [], 'networks': [], 'dns': {}, 'system_bypass': []}
            value = self.prepare(root, config, empty)
            self.assertEqual(value['dns'], subscription['dns'])
            self.assertNotIn('DOMAIN-SUFFIX,corp.example.com,DIRECT', value['rules'])
            self.assertNotIn('IP-CIDR,10.40.0.0/16,DIRECT,no-resolve', value['rules'])
            bypass = (root / 'out/bypass.txt').read_text().split(',')
            self.assertEqual(bypass, ['localhost', '*.local', 'custom.example'])
            # If the subscription independently owns the same rule, it must survive.
            subscription['rules'].insert(0, 'DOMAIN-SUFFIX,corp.example.com,DIRECT')
            self.assertIn('DOMAIN-SUFFIX,corp.example.com,DIRECT', s.run_script((root / 'out/script.js').read_text(), subscription)['rules'])

    def test_covered_networks_and_domains_follow_fresh_subscription(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            config, policy, subscription = self.fixture(root)
            self.prepare(root, config, policy)
            script = (root / 'out/script.js').read_text()
            narrow = 'IP-CIDR,10.40.0.0/16,DIRECT,no-resolve'
            local_domain = 'DOMAIN-SUFFIX,corp.example.com,DIRECT'
            subscription['rules'] = ['DOMAIN,unrelated.example,DIRECT',
                                     'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
                                     'DOMAIN-SUFFIX,example.com,DIRECT', 'MATCH,PROXY']
            result = s.run_script(script, subscription)
            self.assertNotIn(narrow, result['rules'])
            self.assertNotIn(local_domain, result['rules'])
            # Losing upstream coverage restores the original local intent.
            subscription['rules'] = ['MATCH,PROXY']
            result = s.run_script(script, subscription)
            self.assertIn(narrow, result['rules'])
            self.assertIn(local_domain, result['rules'])
            # A preceding conflicting rule must not steal local traffic.
            subscription['rules'] = ['DOMAIN,service.example,PROXY',
                                     'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve', 'MATCH,PROXY']
            self.assertIn(narrow, s.run_script(script, subscription)['rules'])
            # Resolution behavior, unknown rule sets and subnet boundaries matter.
            for prefix in [['GEOSITE,cn,DIRECT', 'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve'],
                           ['IP-CIDR,10.0.0.0/8,DIRECT'],
                           ['IP-CIDR,10.41.0.0/16,DIRECT,no-resolve']]:
                subscription['rules'] = prefix + ['MATCH,PROXY']
                self.assertIn(narrow, s.run_script(script, subscription)['rules'])
            subscription['rules'] = ['DOMAIN-SUFFIX,notexample.com,DIRECT', 'MATCH,PROXY']
            self.assertIn(local_domain, s.run_script(script, subscription)['rules'])

    def test_conflicting_actions_keep_order(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            config, policy, subscription = self.fixture(root)
            self.prepare(root, config, policy)
            subscription['rules'].insert(0, 'DOMAIN-SUFFIX,corp.example.com,PROXY')
            result = s.run_script((root / 'out/script.js').read_text(), subscription)
            self.assertEqual(result['rules'][0], 'DOMAIN-SUFFIX,corp.example.com,DIRECT')
            self.assertIn('DOMAIN-SUFFIX,corp.example.com,PROXY', result['rules'])

    def test_apply_refuses_changed_inputs_or_candidate_without_partial_writes(self):
        for target in ['profiles/m.yaml', 'profiles.yaml', 'profiles/subscription.yaml', 'verge.yaml', '../out/script.js']:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as d:
                root = pathlib.Path(d)
                config, policy, _ = self.fixture(root)
                self.prepare(root, config, policy)
                original = (config / 'profiles/r.yaml').read_bytes()
                path = config / target
                path.write_text(path.read_text() + '\n# changed\n')
                with self.assertRaises(ValueError):
                    s.apply(root / 'out')
                self.assertEqual((config / 'profiles/r.yaml').read_bytes(), original)

    def test_user_script_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            config, policy, _ = self.fixture(root)
            (config / 'profiles/s.js').write_text('function main(config) { config.mode="direct"; return config; }')
            with self.assertRaises(ValueError):
                self.prepare(root, config, policy)

    def test_incompatible_upstream_fake_ip_mode_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            config, policy, subscription = self.fixture(root)
            self.prepare(root, config, policy)
            subscription['dns']['fake-ip-filter-mode'] = 'whitelist'
            with self.assertRaises(ValueError):
                s.run_script((root / 'out/script.js').read_text(), subscription)


if __name__ == '__main__':
    unittest.main()
