"""The installer enables IPv6 only when its DNS address belongs to the host."""
import json
import importlib.util
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'rewrite/deploy'))
import dualstack
spec = importlib.util.spec_from_file_location('rewrite_installer_test', ROOT / 'rewrite/deploy/install-experimental.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class DualStackDomain(unittest.TestCase):
    def test_legacy_cache_keeps_domain_without_enabling_unsupported_options(self):
        args = installer.install.arguments([])
        def cached(value, _role):
            value.input_defaults = {'domain':'panel.example.com'}
            value.coexist = True
            value.tune_network = True
            value.dns_relay_ip = '8.8.8.8'
            value.bundle = Path('/old-release')
            value.sha256 = 'old-hash'
        with patch.object(installer.install, 'use_cached_answers', side_effect=cached):
            installer.use_rewrite_answers(args, 'panel')
        self.assertEqual(args.input_defaults['domain'], 'panel.example.com')
        self.assertFalse(args.coexist); self.assertFalse(args.tune_network)
        self.assertIsNone(args.dns_relay_ip); self.assertIsNone(args.bundle); self.assertIsNone(args.sha256)

    def test_ipv4_only_and_matching_ipv6(self):
        def dns(_domain, _port, family, _kind):
            if family == socket.AF_INET:
                return [(None, None, None, None, ('8.8.8.8', 443))]
            return [(None, None, None, None, ('2001:db8::1', 443, 0, 0))]
        interfaces = [{'addr_info':[{'family':'inet6','local':'2001:db8::1','flags':[]}]}]
        with patch('dualstack.socket.getaddrinfo', side_effect=dns), \
             patch('dualstack.subprocess.check_output', return_value=json.dumps(interfaces).encode()):
            self.assertTrue(dualstack.resolve_domain('panel.example.com', '8.8.8.8'))
        with patch('dualstack.socket.getaddrinfo', side_effect=lambda d,p,f,k:
                   dns(d,p,f,k) if f == socket.AF_INET else []):
            self.assertFalse(dualstack.resolve_domain('panel.example.com', '8.8.8.8'))

    def test_rejects_dns_pointing_to_another_server(self):
        def dns(_domain, _port, family, _kind):
            return [(None, None, None, None, ('8.8.8.8', 443) if family == socket.AF_INET
                    else ('2001:db8::2', 443, 0, 0))]
        interfaces = [{'addr_info':[{'family':'inet6','local':'2001:db8::1','flags':[]}]}]
        with patch('dualstack.socket.getaddrinfo', side_effect=dns), \
             patch('dualstack.subprocess.check_output', return_value=json.dumps(interfaces).encode()):
            with self.assertRaisesRegex(ValueError, 'AAAA'):
                dualstack.resolve_domain('panel.example.com', '8.8.8.8')


if __name__ == '__main__':
    unittest.main()
