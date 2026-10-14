"""Generation must retain existing routes, credentials, and private-network deny rules."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest

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
        before = copy.deepcopy((settings, core))
        new_settings, new_core, new_nginx, firewall, locations = installer.configure(settings, core, nginx, self.firewall)
        self.assertEqual((settings, core), before)
        self.assertEqual(new_core['inbounds'][:-4], core['inbounds'])
        self.assertEqual(new_core['outbounds'][:-4], core['outbounds'])
        self.assertEqual(new_core['routing']['rules'][:-5], core['routing']['rules'])
        self.assertEqual(new_settings['residential_exits'][:-4], settings.get('residential_exits', []))
        self.assertEqual([e['country'] for e in new_settings['residential_exits'][-4:]], ['US', 'JP', 'SG', 'ZZ'])
        self.assertEqual([e['port'] for e in new_settings['residential_exits'][-4:]], list(range(10110, 10114)))
        self.assertTrue(all(e['dynamic'] and not e['exit_ip'] for e in new_settings['residential_exits'][-4:]))
        self.assertEqual(new_core['routing']['rules'][-5]['network'], 'udp')
        self.assertEqual(new_core['routing']['rules'][-5]['outboundTag'], 'blocked')
        self.assertIn(str(installer.LOCATIONS), new_nginx)
        self.assertEqual(locations.count('location = '), 4)
        self.assertLess(firewall.index('10120,10121,10122,10123'), firewall.index('for net in'))
        self.assertIn('-d 127.0.0.1/32 -p tcp -m multiport --dports 10120,10121,10122,10123 -j RETURN', firewall)
        with self.assertRaises(ValueError):
            installer.configure(new_settings, new_core, new_nginx, firewall)

    def test_fresh_three_node_deployment(self):
        self.check_preservation(self.settings, self.core, self.nginx)

    def test_existing_ten_residential_exits(self):
        pool = {'proxies': [{'tag': 'residential-%02d' % (i + 1), 'address': '8.8.4.' + str(i + 1),
            'port': 1080, 'username': 'testuser', 'password': 'testpassword', 'country': 'US'} for i in range(10)]}
        settings, core, _, nginx, _ = residential.configure(self.settings, self.core, self.monitor, self.nginx, pool)
        self.check_preservation(settings, core, nginx)

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
