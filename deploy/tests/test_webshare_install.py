"""Generation must retain existing routes, credentials, and private-network deny rules."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE / 'deploy'))
import provision
import residential
spec = importlib.util.spec_from_file_location('webshare_install', SOURCE / 'deploy/webshare-pool.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class WebshareInstallTest(unittest.TestCase):
    def setUp(self):
        self.settings = provision.settings_for('panel.example.com', '8.8.4.4', 'www.bing.com',
            'PrivateKey: ' + 'a' * 43 + '\nPassword: ' + 'b' * 43)
        self.core = provision.core_config(self.settings)
        self.monitor = provision.monitor_config(self.settings)
        self.nginx = provision.render_nginx(SOURCE, self.settings, '/test/cert.pem', '/test/key.pem')
        self.firewall = (SOURCE / 'deploy/firewall.sh').read_text()

    def check_preservation(self, settings, core, nginx):
        count = len(installer.REGISTRY)
        before = copy.deepcopy((settings, core))
        new_settings, new_core, new_nginx, firewall, locations = installer.configure(settings, core, nginx, self.firewall)
        self.assertEqual((settings, core), before)
        self.assertEqual(new_core['inbounds'][:-count], core['inbounds'])
        self.assertEqual(new_core['outbounds'][:-count], core['outbounds'])
        self.assertEqual(new_core['routing']['rules'][:-(count+1)], core['routing']['rules'])
        self.assertEqual(new_settings['residential_exits'][:-count], settings.get('residential_exits', []))
        self.assertEqual([e['country'] for e in new_settings['residential_exits'][-count:]], [row[0] for row in installer.REGISTRY])
        self.assertEqual([e['port'] for e in new_settings['residential_exits'][-count:]], [row[4] for row in installer.REGISTRY])
        self.assertTrue(all(e['dynamic'] and not e['exit_ip'] for e in new_settings['residential_exits'][-count:]))
        self.assertEqual(new_core['routing']['rules'][-(count+1)]['network'], 'udp')
        self.assertEqual(new_core['routing']['rules'][-(count+1)]['outboundTag'], 'blocked')
        self.assertIn(str(installer.LOCATIONS), new_nginx)
        self.assertEqual(locations.count('location = '), count)
        self.assertLess(firewall.index('10120:10123,10300:10311'), firewall.index('for net in'))
        self.assertIn('-d 127.0.0.1/32 -p tcp -m multiport --dports 10120:10123,10300:10311 -j RETURN', firewall)
        with self.assertRaises(ValueError):
            installer.configure(new_settings, new_core, new_nginx, firewall)

    def test_fresh_three_node_deployment(self):
        self.check_preservation(self.settings, self.core, self.nginx)

    def test_existing_ten_residential_exits(self):
        pool = {'proxies': [{'tag': 'residential-%02d' % (i + 1), 'address': '8.8.4.' + str(i + 1),
            'port': 1080, 'username': 'testuser', 'password': 'testpassword', 'country': 'US'} for i in range(10)]}
        settings, core, _, nginx, _ = residential.configure(self.settings, self.core, self.monitor, self.nginx, pool)
        self.check_preservation(settings, core, nginx)

    def test_expand_preserves_four_existing_entrances_and_rejects_reinstall(self):
        with patch.object(installer, 'REGISTRY', installer.REGISTRY[:4]), patch.object(installer, 'ALLOW', installer.LEGACY_ALLOW):
            old_s, old_c, old_n, old_f, _ = installer.configure(self.settings, self.core, self.nginx, self.firewall)
        s, c, n, f, locations = installer.configure(old_s, old_c, old_n, old_f, expand=True)
        self.assertEqual(s['residential_exits'][:4], old_s['residential_exits'])
        self.assertEqual(c['inbounds'][:-12], old_c['inbounds'])
        self.assertEqual(c['outbounds'][:-12], old_c['outbounds'])
        self.assertEqual(c['routing']['rules'][:-13], old_c['routing']['rules'])
        self.assertEqual(n, old_n)
        self.assertEqual(locations.count('location = '), 16)
        self.assertNotIn('10120,10121,10122,10123', f)
        self.assertIn('10120:10123,10300:10311', f)
        with self.assertRaises(ValueError):
            installer.configure(s, c, n, f, expand=True)

    def test_conflicting_tag_port_and_catchall_refused(self):
        for change in ('tag', 'port', 'rule'):
            core = copy.deepcopy(self.core)
            if change == 'tag':
                core['outbounds'].append({'tag': 'residential-11-exit'})
            elif change == 'port':
                core['inbounds'][0]['port'] = 10110
            else:
                core['routing']['rules'].insert(0, {'type': 'field', 'network': 'tcp', 'outboundTag': 'direct'})
            with self.assertRaises(ValueError):
                installer.configure(self.settings, core, self.nginx, self.firewall)


if __name__ == '__main__':
    unittest.main()
