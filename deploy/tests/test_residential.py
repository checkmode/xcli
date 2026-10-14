"""Credential boundaries, preservation and fail-closed routing generation."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE / 'deploy'))
import residential
import provision
spec = importlib.util.spec_from_file_location('residential_probe', SOURCE / 'scripts/probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ResidentialTests(unittest.TestCase):
    def setUp(self):
        self.settings = provision.settings_for('panel.example.com', '8.8.4.4', 'www.bing.com',
            'PrivateKey: ' + 'a' * 43 + '\nPassword: ' + 'b' * 43)
        self.core = provision.core_config(self.settings)
        self.monitor = provision.monitor_config(self.settings)
        self.nginx = provision.render_nginx(SOURCE, self.settings, '/test/cert.pem', '/test/key.pem')
        self.pool = {'proxies': [{'tag': 'residential-01', 'address': '1.1.1.1', 'port': 1080,
                                'username': 'fixture-user', 'password': 'private-fixture-password', 'country': 'US'}]}

    def generate(self):
        return residential.configure(self.settings, self.core, self.monitor, self.nginx, self.pool)

    def test_existing_identities_preserved_and_credentials_never_public(self):
        settings, core, monitor, nginx, locations = self.generate()
        self.assertNotIn('private-fixture-password', json.dumps(settings) + json.dumps(monitor) + nginx + locations)
        self.assertIn('private-fixture-password', json.dumps(core))
        self.assertEqual(core['inbounds'][:3], self.core['inbounds'])
        self.assertEqual(core['outbounds'][:2], self.core['outbounds'])
        self.assertEqual(core['routing']['rules'][0], self.core['routing']['rules'][0])
        self.assertEqual(core['routing']['rules'][1]['network'], 'udp')
        self.assertEqual(core['routing']['rules'][1]['outboundTag'], 'blocked')
        self.assertEqual(core['routing']['rules'][2]['outboundTag'], 'residential-01-exit')
        self.assertEqual(core['inbounds'][-1]['listen'], '127.0.0.1')
        self.assertIn('proxy_pass http://127.0.0.1:10100;', locations)
        for key, value in self.settings.items():
            self.assertEqual(settings[key], value)
        self.assertNotIn('residential_exits', self.settings)

    def test_unsafe_inputs_duplicates_and_existing_routes_are_rejected(self):
        for value in ('127.0.0.1', '169.254.169.254', '10.0.0.1', '224.0.0.1', '::1'):
            self.pool['proxies'][0]['address'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.generate()
        self.pool['proxies'][0]['address'] = '1.1.1.1'
        self.pool['proxies'].append(copy.deepcopy(self.pool['proxies'][0]))
        with self.assertRaises(ValueError):
            self.generate()
        self.pool['proxies'].pop()
        self.core['routing']['rules'].append({'type': 'field', 'network': 'tcp', 'outboundTag': 'direct'})
        with self.assertRaises(ValueError):
            self.generate()

    def test_residential_probe_checks_fixed_exit_and_doh_without_claiming_udp(self):
        settings, _, monitor, _, _ = self.generate()
        good = subprocess.CompletedProcess([], 0, stdout=b'ip=1.1.1.1\nloc=US\n', stderr=b'')
        with patch.object(probe.subprocess, 'run', return_value=good), patch.object(probe, 'doh_dns', return_value=12), patch.object(probe, 'udp_dns') as udp:
            result = probe.check(monitor, 'residential-01', 12345)
            self.assertEqual(result['status'], 'healthy')
            self.assertFalse(result['udp_supported'])
            self.assertIsNone(result['udp_ms'])
            self.assertEqual(result['doh_ms'], 12)
            udp.assert_not_called()
        bad = subprocess.CompletedProcess([], 0, stdout=b'ip=8.8.4.4\n', stderr=b'')
        with patch.object(probe.subprocess, 'run', return_value=bad), patch.object(probe, 'doh_dns', return_value=12):
            self.assertEqual(probe.check(monitor, 'residential-01', 12345)['status'], 'failed')
        cfg = probe.client_config(monitor, 'residential-01', 12345)
        self.assertEqual(cfg['outbounds'][0]['streamSettings']['wsSettings']['path'], settings['residential_exits'][0]['ws_path'])


if __name__ == '__main__':
    unittest.main()
