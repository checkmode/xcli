import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'deploy'))
sys.path.insert(0, str(ROOT/'scripts'))
import install
import install_cache
import install_node
from node_agent import AgentError, XrayController
from provision import core_config, hysteria_inbound, settings_for


class InstallerTests(unittest.TestCase):
    def test_check_uses_https_panel_saves_answers_and_does_not_construct_installer(self):
        args = install.arguments(['--check', '--yes', '--domain', 'node.example.com', '--public-ip', '8.8.8.8',
                                  '--panel', 'https://panel.example.com'])
        with patch.object(install, 'preflight', return_value='x86_64'), patch.object(install, 'resolve_domain'), \
             patch.object(install, 'prepare_input', return_value=['127.0.0.53']) as prepare, \
             patch.object(install, 'save_checked_answers') as save, \
             patch.object(install_node, 'NodeInstaller') as installer:
            with patch.object(install_node, 'node_preflight', return_value='x86_64'):
                with patch.object(install, 'arguments', return_value=args):
                    with patch.object(install_node.platform, 'freedesktop_os_release', return_value={'VERSION_ID': '24.04'}, create=True):
                        self.assertEqual(install_node.main([]), 0)
            prepare.assert_called_once_with(args, role='node')
            installer.assert_not_called()
            save.assert_called_once_with(args, 'node')
        self.assertEqual(args.panel, 'https://panel.example.com')

    def test_node_rejects_untrusted_panel_origins_and_unsupported_modes(self):
        for value in ('http://panel.example.com', 'https://user:pass@panel.example.com', 'https://panel.example.com/path'):
            with self.subTest(value=value), self.assertRaises(AgentError): install_node.panel_origin(value)
        args = install.arguments(['--coexist'])
        with self.assertRaises(ValueError): install_node.node_preflight(args)

    def test_generated_node_routing_has_no_panel_api(self):
        keys = 'PrivateKey: '+('A'*43)+'\nPassword (PublicKey): '+('B'*43)
        settings = settings_for('node.example.com', '8.8.8.8', 'www.bing.com', keys)
        full = install_node.nginx_config(ROOT, settings, True)
        acme = install_node.nginx_config(ROOT, settings, False)
        self.assertIn(settings['ws_path'], full)
        self.assertIn('127.0.0.1:10443', full)
        self.assertIn('return 404', full)
        self.assertNotIn('127.0.0.1:8080', full)
        self.assertNotIn('@@', full)
        self.assertNotIn('@@', acme)
        core = core_config(settings)
        core['inbounds'][-1] = hysteria_inbound(443, '/etc/xcli-node/tls/fullchain.pem', '/etc/xcli-node/tls/privkey.pem')
        self.assertEqual(core['api']['listen'], '127.0.0.1:10085')
        self.assertEqual({x['tag'] for x in core['inbounds']}, {'reality', 'websocket', 'hysteria2'})
        self.assertTrue(all(not x['settings'].get('clients') for x in core['inbounds']))

    def test_help_exposes_the_two_roles(self):
        text = subprocess.check_output(['bash', str(ROOT/'install.sh'), '--help'], text=True)
        self.assertIn('--role panel|node', text)
        self.assertIn('--panel HTTPS_URL', text)

    def test_node_check_caches_panel_and_node_addresses_for_interactive_install(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(install_cache, 'CACHE_PATH', Path(directory)/'cache'/'answers.json'), \
             patch.object(install_node, 'node_preflight', return_value='x86_64'), \
             patch.object(install, 'resolve_domain'), \
             patch.object(install.Path, 'read_text', return_value='nameserver 1.1.1.1\n'), \
             patch.object(install_node.platform, 'freedesktop_os_release', return_value={'VERSION_ID': '24.04'}, create=True):
            self.assertEqual(install_node.main(['--check', '--yes', '--panel', 'https://panel.example.com',
                '--domain', 'node.example.com', '--public-ip', '8.8.4.4']), 0)
            args = install.arguments(['--no-email', '--agree-tos'])
            install.use_cached_answers(args, 'node')
            prompts = []
            def answer(label, default=None, **_kwargs):
                prompts.append((label, default))
                return default or ''
            with patch.object(install, 'ask', side_effect=answer):
                install_node.node_input(args)
            self.assertEqual((args.panel, args.domain, args.public_ip),
                             ('https://panel.example.com', 'node.example.com', '8.8.4.4'))
            self.assertEqual([default for _, default in prompts],
                             ['https://panel.example.com', 'node.example.com', '8.8.4.4'])


if __name__ == '__main__': unittest.main()
