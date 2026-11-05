"""Validate generated fresh-install configurations with real Xray and Nginx."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'rewrite/deploy'))
import render

XRAY = os.environ.get('XCLI_TEST_XRAY', '')
NGINX = os.environ.get('XCLI_TEST_NGINX', '')


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@unittest.skipUnless(XRAY and NGINX and Path(XRAY).is_file() and Path(NGINX).is_file(),
                     'set XCLI_TEST_XRAY and XCLI_TEST_NGINX')
class FreshConfiguration(unittest.TestCase):
    def test_panel_and_node_configs_are_accepted_by_real_programs(self):
        with tempfile.TemporaryDirectory(prefix='xcli-render-') as directory:
            root = Path(directory)
            cert, key, bundle = root / 'cert.pem', root / 'key.pem', root / 'bundle.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                            '-subj', '/CN=panel.example.com', '-addext', 'subjectAltName=DNS:panel.example.com',
                            '-keyout', str(key), '-out', str(cert)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            bundle.write_bytes(cert.read_bytes() + b'\n' + key.read_bytes())
            keys = subprocess.check_output([XRAY, 'x25519'], text=True)
            panel = render.panel(ROOT, 'panel.example.com', '8.8.8.8', 'www.bing.com', keys, 443,
                                 ['1.1.1.1'], 1001, 1001, 1002, 1002)
            custom_port = render.panel(ROOT, 'panel.example.com', '8.8.8.8', 'www.bing.com', keys, 19443,
                                       ['1.1.1.1'], 1001, 1001, 1002, 1002)
            panel6 = render.panel(ROOT, 'panel.example.com', '8.8.8.8', 'www.bing.com', keys, 443,
                                  ['1.1.1.1'], 1001, 1001, 1002, 1002, True)
            self.assertIn('return 301 https://panel.example.com:19443$request_uri;', custom_port['nginx'])
            self.assertIn('proxy_read_timeout 120s;', panel['nginx'])
            self.assertIn('listen [::]:443 ipv6only=on;', panel6['nginx'])
            self.assertIn('listen [::]:80 ipv6only=on default_server;', render.acme(ROOT, panel6['settings'], True))
            self.assertIn('ip6tables -w -A XG6_IN', panel6['firewall'])
            self.assertEqual(next(item for item in panel6['core']['inbounds'] if item['tag'] == 'hysteria2')['listen'], '::')
            self.assertEqual(len(panel['settings']['residential_exits']), 16)
            self.assertIn('10120:10123,10300:10311', panel['firewall'])
            self.assertIn('--dports 8080,10085,10080,10443,18080', panel['firewall'])
            node = render.node(ROOT, 'node.example.com', '8.8.4.4', 'www.bing.com', keys, 443,
                               ['1.1.1.1'], 'https://panel.example.com')
            self.assertEqual(panel['worker']['core_unit'], 'xcli-core.service')
            self.assertIn('XCLI_PROBE_UUID=' + panel['monitor']['uuid'], panel['environment'])
            self.assertEqual(node['node']['token'], node['registration']['key'])
            self.assertEqual(node['node']['node_id'], node['registration']['id'])
            self.assertEqual(node['node']['panel'], 'https://panel.example.com')
            for role, config in (('panel', panel), ('panel6', panel6), ('node', node)):
                with self.subTest(role=role):
                    original = '/etc/xcli/hysteria-tls/bundle.pem' if role.startswith('panel') else '/etc/xcli-node/tls/bundle.pem'
                    core = json.dumps(config['core']).replace(original, str(bundle))
                    core_path = root / f'{role}-core.json'
                    core_path.write_text(core)
                    result = subprocess.run([XRAY, 'run', '-test', '-config', str(core_path)],
                                            capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                    locations = root / 'locations.conf'
                    locations.write_text('')
                    nginx = (config['nginx'].replace(original, str(bundle))
                             .replace('/etc/nginx/xcli-import-locations.conf', str(locations))
                             .replace('/etc/nginx/xcli-webshare-locations.conf', str(locations))
                             .replace('/run/nginx.pid', str(root / 'nginx.pid'))
                             .replace('/var/log/nginx/error.log', 'stderr')
                             .replace('listen 443;', f'listen 127.0.0.1:{free_port()};')
                             .replace('listen [::]:443 ipv6only=on;', f'listen [::1]:{free_port()} ipv6only=on;')
                             .replace('listen 80 default_server;', f'listen 127.0.0.1:{free_port()} default_server;')
                             .replace('listen [::]:80 ipv6only=on default_server;', f'listen [::1]:{free_port()} ipv6only=on default_server;')
                             .replace('listen 127.0.0.1:8443 ssl proxy_protocol;',
                                      f'listen 127.0.0.1:{free_port()} ssl proxy_protocol;'))
                    nginx_path = root / f'{role}-nginx.conf'
                    nginx_path.write_text(nginx)
                    result = subprocess.run([NGINX, '-t', '-c', str(nginx_path)],
                                            capture_output=True, text=True, timeout=15)
                    self.assertEqual(result.returncode, 0, result.stderr + result.stdout)


if __name__ == '__main__':
    unittest.main()
