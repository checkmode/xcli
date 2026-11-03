"""Installer defaults survive checks without storing private material."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import install
import install_cache


class InstallCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root/'cache'/'answers.json'
        self.override = patch.object(install_cache, 'CACHE_PATH', self.path)
        self.override.start()

    def tearDown(self):
        self.override.stop()
        self.temp.cleanup()

    def test_profiles_are_separate_restricted_and_contain_no_key_material(self):
        key = self.root/'private.pem'
        key.write_text('fixture private key contents')
        install_cache.save('panel', {'domain': 'panel.example.com', 'private_key': str(key), 'no_email': True})
        install_cache.save('node', {'domain': 'node.example.com', 'panel': 'https://panel.example.com'})
        result = install_cache.load()
        self.assertEqual(result['last_role'], 'node')
        self.assertEqual(result['panel']['domain'], 'panel.example.com')
        self.assertEqual(result['node']['domain'], 'node.example.com')
        self.assertNotIn('fixture private key contents', self.path.read_text())
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)

    def test_symlinks_and_insecure_files_are_rejected_without_overwrite(self):
        self.path.parent.mkdir(mode=0o700)
        target = self.root/'unrelated'
        self.path.symlink_to(target)
        with self.assertRaises(OSError): install_cache.save('panel', {'domain': 'panel.example.com'})
        self.assertFalse(target.exists())
        self.path.unlink()
        self.path.write_text('{"version": 1}')
        self.path.chmod(0o644)
        with self.assertRaises(ValueError): install_cache.load()
        with self.assertRaises(ValueError): install_cache.save('panel', {'domain': 'panel.example.com'})
        self.assertEqual(self.path.read_text(), '{"version": 1}')

    def test_interactive_defaults_and_explicit_flags_take_precedence(self):
        install_cache.save('panel', {'domain': 'cached.example.com', 'public_ip': '8.8.4.4',
            'public_port': 1443, 'reality_sni': 'www.cached.example.com', 'coexist': True,
            'tune_network': True, 'certificate': '/old/cert', 'private_key': '/old/key'})
        args = install.arguments(['--public-port', '2443', '--no-coexist', '--certificate', '/new/cert'])
        install.use_cached_answers(args, 'panel')
        self.assertEqual(args.input_defaults['domain'], 'cached.example.com')
        self.assertIsNone(args.domain)  # The prompt still displays and confirms the cached default.
        self.assertEqual(args.public_port, 2443)
        self.assertFalse(args.coexist)
        self.assertEqual(args.reality_sni, 'www.cached.example.com')
        self.assertTrue(args.tune_network)
        self.assertEqual(args.certificate, Path('/new/cert'))
        self.assertIsNone(args.private_key)  # Never mix one explicit file with a cached pair.
        unattended = install.arguments(['--yes'])
        install.use_cached_answers(unattended, 'panel')
        self.assertEqual(unattended.public_port, 443)
        self.assertEqual(unattended.input_defaults, {})
        ignored = install.arguments(['--no-cache'])
        install.use_cached_answers(ignored, 'panel')
        self.assertEqual(ignored.input_defaults, {})

    def test_check_caches_entered_inputs_and_install_prompts_with_defaults(self):
        check = install.arguments(['--check', '--public-ip', '8.8.4.4', '--email', 'operator@example.com',
                                   '--reality-sni', 'www.example.net'])
        with patch.object(install, 'resolve_domain'), \
             patch.object(install.Path, 'read_text', return_value='nameserver 1.1.1.1\n'), \
             patch.object(install.Path, 'exists', return_value=False), \
             patch.object(install.Path, 'is_symlink', return_value=False), \
             patch.object(install, 'ask', return_value='panel.example.com'):
            install.prepare_input(check)
        install.save_checked_answers(check, 'panel')
        saved = json.loads(self.path.read_text())['panel']
        self.assertNotIn('agree_tos', saved)
        self.assertNotIn('yes', saved)
        args = install.arguments([])
        install.use_cached_answers(args, 'panel')
        prompts = []
        def answer(label, default=None, **kwargs):
            prompts.append((label, default))
            return 'yes' if '服务条款' in label else default or ''
        with patch.object(install, 'resolve_domain'), \
             patch.object(install.Path, 'read_text', return_value='nameserver 1.1.1.1\n'), \
             patch.object(install.Path, 'exists', return_value=False), \
             patch.object(install.Path, 'is_symlink', return_value=False), \
             patch.object(install, 'ask', side_effect=answer):
            install.prepare_input(args)
        self.assertEqual(args.domain, 'panel.example.com')
        self.assertEqual(args.public_ip, '8.8.4.4')
        self.assertEqual(args.email, 'operator@example.com')
        self.assertEqual(args.reality_sni, 'www.example.net')
        self.assertTrue(any(default == 'panel.example.com' for _, default in prompts))
        self.assertTrue(any(default == '8.8.4.4' for _, default in prompts))
        self.assertTrue(any(default == 'operator@example.com' for _, default in prompts))
        self.assertTrue(any('服务条款' in label for label, _ in prompts))

    def test_failed_dns_check_keeps_valid_inputs_for_retry(self):
        with patch.object(install, 'preflight', return_value='x86_64'), \
             patch.object(install, 'resolve_domain', side_effect=ValueError('DNS not ready')):
            with self.assertRaisesRegex(ValueError, 'DNS not ready'):
                install.main(['--check', '--yes', '--domain', 'panel.example.com', '--public-ip', '8.8.4.4'])
        saved = install_cache.load()['panel']
        self.assertEqual(saved['domain'], 'panel.example.com')
        self.assertEqual(saved['public_ip'], '8.8.4.4')

    def test_failed_node_origin_never_caches_url_credentials(self):
        args = install.arguments(['--check', '--domain', 'node.example.com', '--public-ip', '8.8.4.4',
                                  '--panel', 'https://name:secret@panel.example.com'])
        install.save_partial_answers_on_failure(args, 'node')
        self.assertFalse(self.path.exists())

    def test_repeated_check_preserves_email_only_for_the_same_domain(self):
        install_cache.save('panel', {'domain': 'panel.example.com', 'email': 'operator@example.com'})
        args = install.arguments(['--check', '--yes', '--domain', 'panel.example.com', '--public-ip', '8.8.4.4'])
        install.save_checked_answers(args, 'panel')
        self.assertEqual(install_cache.load()['panel']['email'], 'operator@example.com')
        args.domain = 'another.example.com'
        install.save_checked_answers(args, 'panel')
        self.assertNotIn('email', install_cache.load()['panel'])

    def test_no_cache_does_not_write_a_check_file(self):
        args = install.arguments(['--check', '--no-cache', '--domain', 'panel.example.com', '--public-ip', '8.8.4.4'])
        install.save_checked_answers(args, 'panel')
        self.assertFalse(self.path.exists())

    def test_changed_domain_does_not_use_cached_certificate(self):
        install_cache.save('panel', {'domain': 'old.example.com', 'public_ip': '8.8.4.4',
                                    'certificate': '/old/cert', 'private_key': '/old/key'})
        args = install.arguments(['--domain', 'new.example.com', '--no-email', '--agree-tos'])
        install.use_cached_answers(args, 'panel')
        with patch.object(install, 'resolve_domain'), \
             patch.object(install.Path, 'read_text', return_value='nameserver 1.1.1.1\n'), \
             patch.object(install.Path, 'exists', return_value=False), \
             patch.object(install.Path, 'is_symlink', return_value=False), \
             patch.object(install, 'ask', return_value='8.8.4.4'):
            install.prepare_input(args)
        self.assertIsNone(args.certificate)
        self.assertIsNone(args.private_key)

    def test_shell_reads_role_and_coexist_from_the_same_protected_cache(self):
        install_cache.save('panel', {'domain': 'panel.example.com', 'coexist': True})
        install_cache.save('node', {'domain': 'node.example.com'})
        shell = (Path(__file__).resolve().parents[2]/'install.sh').read_text().split('\nmain() {', 1)[0]
        shell = shell.replace('/root/.cache/xcli-install/answers.json', str(self.path))
        output = subprocess.check_output(['bash', '-c', shell+'\ncache_field role\ncache_field coexist panel\n'], text=True)
        self.assertEqual(output.splitlines(), ['node', 'true'])
        self.path.chmod(0o644)
        output = subprocess.check_output(['bash', '-c', shell+'\ncache_field role\n'], text=True)
        self.assertEqual(output, '')


if __name__ == '__main__': unittest.main()
