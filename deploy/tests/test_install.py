"""Installer safeguards and generated configuration; no host changes."""
import contextlib
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE / 'deploy'))
import install
import provision


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.settings = provision.settings_for('panel.example.com', '8.8.4.4', 'www.bing.com',
            'PrivateKey: ' + 'a' * 43 + '\nPassword (PublicKey): ' + 'b' * 43)

    def test_domain_rejects_config_injection(self):
        for value in ('a.example.com;quit', 'https://example.com', 'x.example.com/path', '*.example.com',
                      'x..com', '-x.example.com', 'x-.example.com', 'x.com\nlisten 22;', '127.0.0.1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                provision.domain_name(value)
        self.assertEqual(provision.domain_name(' PANEL.Example.COM. '), 'panel.example.com')

    def test_only_public_unicast_ipv4(self):
        for value in ('127.0.0.1', '169.254.169.254', '10.0.0.1', '::1', 'ff00::1',
                      '192.0.2.1', '224.0.0.1', '0.0.0.0', '8.8.8.8;echo x'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                provision.public_ipv4(value)
        self.assertEqual(provision.public_ipv4('1.1.1.1'), '1.1.1.1')

    def test_generated_identities_are_independent(self):
        second = provision.settings_for('panel.example.com', '8.8.4.4', 'www.bing.com',
            'PrivateKey: ' + 'a' * 43 + '\nPassword: ' + 'b' * 43)
        self.assertNotEqual(self.settings['short_id'], second['short_id'])
        self.assertNotEqual(self.settings['ws_path'], second['ws_path'])
        self.assertNotEqual(provision.monitor_config(self.settings)['uuid'], provision.monitor_config(self.settings)['uuid'])
        self.assertNotIn('reality_private', provision.monitor_config(self.settings))

    def test_nginx_routes_both_entries_without_fixed_host_values(self):
        value = provision.render_nginx(SOURCE, self.settings, '/test/fullchain.pem', '/test/privkey.pem')
        self.assertIn('panel.example.com 127.0.0.1:8443', value)
        self.assertIn('www.bing.com 127.0.0.1:10443', value)
        self.assertIn('location = ' + self.settings['ws_path'], value)
        self.assertNotIn('@@', value)
        self.assertNotIn('ssl_certificate', provision.render_nginx(SOURCE, self.settings))
        self.assertIn('acme-challenge', provision.render_nginx(SOURCE, self.settings))
        with self.assertRaises(ValueError):
            provision.render_nginx(SOURCE, self.settings, '/a; bad', '/key')

    def test_core_private_destinations_and_api_binding(self):
        config = provision.core_config(self.settings)
        self.assertEqual(config['api']['listen'], '127.0.0.1:10085')
        self.assertTrue(all(item['listen'] == '127.0.0.1' for item in config['inbounds']))
        blocked = [ipaddress.ip_network(value) for value in config['routing']['rules'][0]['ip']]
        for value in ('8.8.4.4', '169.254.169.254', '10.1.2.3', '192.168.1.1', 'fd00::1', '::1'):
            self.assertTrue(any(ipaddress.ip_address(value) in net for net in blocked))

    def test_firewall_resolver_exceptions_are_port_scoped(self):
        result = provision.render_firewall('8.8.4.4', ['127.0.0.53', '10.0.0.2'])
        for resolver in ('127.0.0.53', '10.0.0.2'):
            matching = [line for line in result.splitlines() if '-d ' + resolver + '/32' in line]
            self.assertEqual(len(matching), 2)
            self.assertTrue(all('--dport 53' in line for line in matching))
        self.assertIn('--dst-type LOCAL -j REJECT', result)
        self.assertIn('8.8.4.4/32', result)
        subprocess.run(['sh', '-n'], input=result.encode(), check=True)
        with self.assertRaises(ipaddress.AddressValueError):
            provision.render_firewall('8.8.4.4', ['127.0.0.53;evil'])

    def test_initial_admin_password_compatible_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            db, credential = root / 'gateway.sqlite', root / 'admin.txt'
            provision.initialize_admin(db, credential, self.settings['domain'])
            values = dict(line.split(': ', 1) for line in credential.read_text().splitlines())
            with contextlib.closing(sqlite3.connect(db)) as connection:
                salt, digest = connection.execute('SELECT password FROM admin').fetchone()[0].split(':')
            computed = hashlib.scrypt(values['Password'].encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1, dklen=32).hex()
            self.assertEqual(digest, computed)
            self.assertEqual(db.stat().st_mode & 0o777, 0o600)
            self.assertEqual(credential.stat().st_mode & 0o777, 0o600)
            before = db.read_bytes(), credential.read_bytes()
            with self.assertRaises(ValueError):
                provision.initialize_admin(db, credential, self.settings['domain'])
            self.assertEqual(before, (db.read_bytes(), credential.read_bytes()))

    def test_private_file_refuses_existing_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory) / 'link'
            target.symlink_to(pathlib.Path(directory) / 'missing')
            with self.assertRaises(FileExistsError):
                provision.private_file(target, 'secret')
            self.assertFalse(target.resolve().exists())


class PreflightTests(unittest.TestCase):
    def test_existing_config_and_dangling_symlink_block_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            nginx = root / 'etc/nginx'
            nginx.parent.mkdir()
            nginx.symlink_to('/missing-install-fixture')
            self.assertEqual(install.existing_paths(root), [str(nginx)])

    def test_occupied_port_is_detected(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            with self.assertRaises(ValueError):
                install.check_ports([listener.getsockname()[1]])

    def test_dns_rejects_multi_address_and_ipv6(self):
        def records(four, six):
            return lambda host, port, family, kind: [(family, kind, 6, '', (value, port)) for value in (four if family == socket.AF_INET else six)]
        for four, six in ((['8.8.4.4', '8.8.8.8'], []), ([], []), (['8.8.4.4'], ['2001:4860::1'])):
            with patch.object(socket, 'getaddrinfo', side_effect=records(four, six)), self.assertRaises(ValueError):
                install.resolve_domain('panel.example.com', '8.8.4.4')
        with patch.object(socket, 'getaddrinfo', side_effect=records(['8.8.4.4'], [])):
            install.resolve_domain('panel.example.com', '8.8.4.4')

    def test_readonly_check_does_not_construct_installer(self):
        with patch.object(install, 'preflight', return_value='x86_64'), \
             patch.object(install, 'prepare_input', return_value=['127.0.0.53']), \
             patch.object(install.platform, 'freedesktop_os_release', return_value={'VERSION_ID': '24.04'}, create=True), \
             patch.object(install, 'Installer') as installer:
            self.assertEqual(install.main(['--check', '--yes', '--domain', 'panel.example.com', '--public-ip', '8.8.4.4']), 0)
            installer.assert_not_called()

    def test_help_available_without_root(self):
        result = subprocess.run(['bash', str(SOURCE / 'install.sh'), '--help'], capture_output=True, check=True)
        self.assertIn(b'--check', result.stdout)


if __name__ == '__main__':
    unittest.main()
