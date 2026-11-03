"""Installer safeguards and generated configuration; no host changes."""
import contextlib
import hashlib
import io
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

    def test_alternate_public_port_reaches_every_generated_component(self):
        settings = provision.settings_for('panel.example.com', '8.8.4.4', 'www.bing.com',
            'PrivateKey: ' + 'a' * 43 + '\nPassword (PublicKey): ' + 'b' * 43, 1443)
        self.assertEqual(settings['origin'], 'https://panel.example.com:1443')
        self.assertEqual(settings['public_port'], 1443)
        self.assertEqual(settings['hysteria2_port'], 1443)
        self.assertEqual(provision.monitor_config(settings)['public_port'], 1443)
        self.assertEqual(next(x for x in provision.core_config(settings)['inbounds'] if x['tag'] == 'hysteria2')['port'], 1443)
        nginx = provision.render_nginx(SOURCE, settings, '/test/fullchain.pem', '/test/privkey.pem')
        self.assertIn('listen 1443; ssl_preread', nginx)
        firewall = provision.render_firewall('8.8.4.4', ['127.0.0.53'], 1443)
        self.assertIn('--dports 80,1443', firewall)
        self.assertIn('-p udp --dport 1443 -j ACCEPT', firewall)
        relayed = provision.settings_for('panel.example.com', '8.8.4.4', 'www.bing.com',
            'PrivateKey: ' + 'a' * 43 + '\nPassword: ' + 'b' * 43, 1443, True)
        self.assertTrue(relayed['node_address_ip'])
        self.assertTrue(provision.monitor_config(relayed)['node_address_ip'])
        for port in (0, 65536, True, '1443'):
            with self.subTest(port=port), self.assertRaises(ValueError):
                provision.settings_for('panel.example.com', '8.8.4.4', 'www.bing.com',
                    'PrivateKey: ' + 'a' * 43 + '\nPassword: ' + 'b' * 43, port)

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
        self.assertTrue(all(item['listen'] == '127.0.0.1' for item in config['inbounds'] if item['tag'] != 'hysteria2'))
        hy2 = next(item for item in config['inbounds'] if item['tag'] == 'hysteria2')
        self.assertEqual(hy2['listen'], '0.0.0.0')
        self.assertEqual(hy2['settings']['clients'], [])
        self.assertEqual(hy2['streamSettings']['network'], 'hysteria')
        self.assertEqual(hy2['streamSettings']['finalmask']['quicParams']['congestion'], 'bbr')
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
        self.assertIn('-p udp --dport 443 -j ACCEPT', result)
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

    def test_coexist_allows_unrelated_nginx_but_not_its_own_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            nginx = root / 'etc/nginx'
            nginx.mkdir(parents=True)
            (nginx / 'nginx.conf').write_text('existing configuration')
            self.assertEqual(install.existing_paths(root, coexist=True), [])
            (nginx / 'xcli.conf').write_text('existing xcli configuration')
            self.assertEqual(install.existing_paths(root, coexist=True), [str(nginx / 'xcli.conf')])

    def test_prebuilt_bundle_must_match_the_requested_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = pathlib.Path(directory) / 'release.tar.gz'
            bundle.write_bytes(b'fixture')
            args = install.arguments(['--coexist', '--public-port', '1443', '--bundle', str(bundle),
                                      '--sha256', 'a' * 64, '--commit', 'b' * 40])
            manifest = {'provenance': {'kind': 'git-build', 'revision': 'c' * 40}}
            with patch.object(install.os, 'geteuid', return_value=0), \
                 patch.object(install.platform, 'system', return_value='Linux'), \
                 patch.object(install.platform, 'machine', return_value='x86_64'), \
                 patch.object(install.platform, 'freedesktop_os_release', return_value={'ID': 'ubuntu', 'VERSION_ID': '26.04'}, create=True), \
                 patch.object(pathlib.Path, 'is_dir', return_value=True), \
                 patch.object(install.release, 'extract_bundle', return_value=manifest), \
                 self.assertRaisesRegex(ValueError, '源码提交'):
                install.preflight(args)

    def test_occupied_udp_port_is_detected(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind(('127.0.0.1', 0))
            with self.assertRaises(ValueError):
                install.check_udp_port(listener.getsockname()[1])

    def test_dns_rejects_multi_address_and_ipv6(self):
        def records(four, six):
            return lambda host, port, family, kind: [(family, kind, 6, '', (value, port)) for value in (four if family == socket.AF_INET else six)]
        for four, six in ((['8.8.4.4', '8.8.8.8'], []), ([], []), (['8.8.4.4'], ['2001:4860::1'])):
            with patch.object(socket, 'getaddrinfo', side_effect=records(four, six)), self.assertRaises(ValueError):
                install.resolve_domain('panel.example.com', '8.8.4.4')
        with patch.object(socket, 'getaddrinfo', side_effect=records(['8.8.4.4'], [])):
            install.resolve_domain('panel.example.com', '8.8.4.4')

    def test_certificate_can_use_the_existing_no_email_practice(self):
        args = install.arguments(['--yes', '--domain', 'panel.example.com', '--public-ip', '8.8.4.4', '--no-email', '--agree-tos'])
        with patch.object(install, 'resolve_domain'), patch.object(pathlib.Path, 'exists', return_value=False), \
             patch.object(pathlib.Path, 'is_symlink', return_value=False), \
             patch.object(pathlib.Path, 'read_text', return_value='nameserver 1.1.1.1\n'):
            self.assertEqual(install.prepare_input(args), ['1.1.1.1'])
        args.email = 'operator@example.com'
        with patch.object(install, 'resolve_domain'), patch.object(pathlib.Path, 'exists', return_value=False), \
             patch.object(pathlib.Path, 'is_symlink', return_value=False), self.assertRaises(ValueError):
            install.prepare_input(args)

    def test_interactive_email_can_be_left_empty(self):
        args = install.arguments(['--domain', 'panel.example.com', '--public-ip', '8.8.4.4', '--no-tune-network'])
        with patch.object(install, 'resolve_domain'), patch.object(pathlib.Path, 'exists', return_value=False), \
             patch.object(pathlib.Path, 'is_symlink', return_value=False), \
             patch.object(pathlib.Path, 'read_text', return_value='nameserver 1.1.1.1\n'), \
             patch.object(install, 'ask', side_effect=['', 'yes']):
            install.prepare_input(args)
        self.assertTrue(args.no_email)

    def test_missing_terminal_gives_check_specific_parameters(self):
        with patch('builtins.open', side_effect=OSError('no controlling tty')), \
             patch.object(sys.stdin, 'isatty', return_value=False):
            with self.assertRaisesRegex(ValueError, '--domain.*--public-ip') as error:
                install.ask('面板域名', check_only=True)
            self.assertNotIn('--email', str(error.exception))
            with self.assertRaisesRegex(ValueError, '--email.*--no-email.*--agree-tos'):
                install.ask('面板域名')

    def test_success_reports_actual_configuration_locations(self):
        instance = object.__new__(install.Installer)
        instance.settings = {'origin': 'https://panel.example.com'}
        instance.nginx_target = pathlib.Path('/etc/nginx/xcli.conf')
        instance.backup = pathlib.Path('/var/backups/xcli/install/example')
        instance.args = install.arguments(['--coexist'])
        with patch.object(instance, 'packages_and_build'), patch.object(instance, 'install_files'), \
             patch.object(instance, 'certificate'), patch.object(instance, 'start_and_verify', return_value=True), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(instance.execute(), 0)
        for path in ('/etc/nginx/xcli.conf', '/etc/xray-gateway/settings.json',
                     '/etc/xray-gateway/core.json', '/var/lib/xray-gateway/gateway.sqlite'):
            self.assertIn(path, out.getvalue())

    def test_dns_relay_requires_the_explicit_relay_address(self):
        args = install.arguments(['--yes', '--domain', 'panel.example.com', '--public-ip', '8.8.4.4',
                                  '--dns-relay-ip', '1.1.1.1', '--no-email', '--agree-tos'])
        with patch.object(install, 'resolve_domain') as resolve, patch.object(pathlib.Path, 'exists', return_value=False), \
             patch.object(pathlib.Path, 'is_symlink', return_value=False), \
             patch.object(pathlib.Path, 'read_text', return_value='nameserver 1.1.1.1\n'):
            install.prepare_input(args)
        resolve.assert_called_once_with('panel.example.com', '1.1.1.1')

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
