"""Safety tests for the opt-in Hysteria listener migration."""
import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('brutal', ROOT / 'rewrite/deploy/enable-hysteria-brutal.py')
brutal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(brutal)


def fixture():
    settings = {'domain': 'panel.example', 'hysteria2_port': 443, 'unrelated': {'keep': True}}
    core = {'inbounds': [{'tag': 'hysteria2', 'listen': '0.0.0.0', 'port': 443,
                          'protocol': 'hysteria', 'settings': {'version': 2, 'clients': []},
                          'streamSettings': {'network': 'hysteria', 'security': 'tls',
                                             'tlsSettings': {'certificates': []},
                                             'finalmask': {'quicParams': {'congestion': 'bbr'}}}}],
            'outbounds': [{'tag': 'direct', 'protocol': 'freedom'}],
            'routing': {'rules': [{'outboundTag': 'direct'}]}}
    monitor = {'hysteria2_port': 443, 'uuid': 'synthetic-private-value'}
    firewall = b'#!/bin/sh\n    iptables -w -A XG_IN -p udp --dport 443 -j ACCEPT\n# retain\n'
    return tuple(json.dumps(value).encode() for value in (settings, core, monitor)) + (firewall,)


class CandidateTests(unittest.TestCase):
    def test_adds_separate_entry_and_preserves_existing_values(self):
        settings, core, monitor, firewall = fixture()
        candidate = brutal.build_candidates(settings, core, monitor, firewall, 8443)
        new_settings, new_core, new_monitor = (json.loads(candidate[name]) for name in ('settings', 'core', 'monitor'))
        self.assertEqual(new_settings, {**json.loads(settings), brutal.KEY: 8443})
        self.assertEqual(new_monitor, {**json.loads(monitor), brutal.KEY: 8443})
        self.assertEqual(new_core['inbounds'][0], json.loads(core)['inbounds'][0])
        self.assertEqual(new_core['routing'], json.loads(core)['routing'])
        self.assertEqual(new_core['outbounds'], json.loads(core)['outbounds'])
        fast = new_core['inbounds'][1]
        self.assertEqual((fast['tag'], fast['port']), (brutal.TAG, 8443))
        self.assertEqual(fast['settings']['clients'], [])
        self.assertEqual(fast['streamSettings']['finalmask']['quicParams'],
                         {'congestion': 'force-brutal', 'brutalUp': '40 mbps'})
        self.assertIn(b'--dport 443 -j ACCEPT', candidate['firewall'])
        self.assertIn(b'--dport 8443 -j ACCEPT', candidate['firewall'])
        self.assertTrue(candidate['firewall'].endswith(b'# retain\n'))
        self.assertIsNone(brutal.build_candidates(candidate['settings'], candidate['core'],
                                                  candidate['monitor'], candidate['firewall'], 8443))
        custom_settings = json.loads(candidate['settings'])
        custom_settings['hysteria2_brutal_mbps'] = 60
        custom_core = json.loads(candidate['core'])
        custom_core['inbounds'][1]['streamSettings']['finalmask']['quicParams']['brutalUp'] = '60 mbps'
        self.assertIsNone(brutal.build_candidates(json.dumps(custom_settings).encode(), json.dumps(custom_core).encode(),
                                                  candidate['monitor'], candidate['firewall'], 8443))

    def test_rejects_collisions_custom_users_and_partial_prior_state(self):
        settings, core, monitor, firewall = fixture()
        with self.assertRaises(ValueError):
            brutal.build_candidates(settings, core, monitor, firewall, 443)
        data = json.loads(core)
        data['inbounds'].append({'tag': 'unrelated', 'port': 8443})
        with self.assertRaises(ValueError):
            brutal.build_candidates(settings, json.dumps(data).encode(), monitor, firewall, 8443)
        data = json.loads(core)
        data['inbounds'][0]['settings']['clients'] = [{'auth': 'do-not-copy'}]
        with self.assertRaises(ValueError):
            brutal.build_candidates(settings, json.dumps(data).encode(), monitor, firewall, 8443)
        data = json.loads(settings)
        data[brutal.KEY] = 8443
        with self.assertRaises(ValueError):
            brutal.build_candidates(json.dumps(data).encode(), core, monitor, firewall, 8443)


class TransactionTests(unittest.TestCase):
    def test_failure_after_dynamic_add_restores_files_and_only_its_own_rule(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            paths = dict(zip(('settings', 'core', 'monitor', 'firewall'), (root / n for n in ('settings', 'core', 'monitor', 'firewall'))))
            original = dict(zip(paths, fixture()))
            for name, path in paths.items():
                path.write_bytes(original[name])
                path.chmod(0o640)
            activation = brutal.Activation({'role': 'panel'}, 8443, Path('/test/xray'), '127.0.0.1:10085', paths)
            activation.backup = root
            active, rules, calls = {'hysteria2'}, set(), []
            def command(*args, **kwargs):
                calls.append(args)
                if args[:3] == (Path('/test/xray'), 'api', 'adi'):
                    active.add(brutal.TAG)
                if args[:3] == (Path('/test/xray'), 'api', 'rmi'):
                    active.discard(brutal.TAG)
                if args[:3] == ('iptables', '-w', '-C'):
                    return SimpleNamespace(returncode=0 if 8443 in rules else 1)
                if args[:3] == ('iptables', '-w', '-A'):
                    rules.add(8443)
                if args[:3] == ('iptables', '-w', '-D'):
                    rules.discard(8443)
                return SimpleNamespace(returncode=0, stdout='')
            real_replace = brutal.replace_preserving
            def fail_on_monitor(path, data, meta):
                if path == paths['monitor'] and data != original['monitor']:
                    raise OSError('injected failure')
                real_replace(path, data, meta)
            with patch.object(brutal.upgrade, 'run', side_effect=command), \
                 patch.object(activation, 'runtime_tags', side_effect=lambda: set(active)), \
                 patch.object(brutal, 'unbound', side_effect=lambda port: brutal.TAG not in active), \
                 patch.object(brutal, 'replace_preserving', side_effect=fail_on_monitor):
                with self.assertRaises(OSError):
                    activation.apply()
                activation.rollback()
            self.assertEqual(active, {'hysteria2'})
            self.assertEqual(rules, set())
            for name, path in paths.items():
                self.assertEqual(path.read_bytes(), original[name])
                self.assertEqual(path.stat().st_mode & 0o777, 0o640)
            self.assertTrue(any(args[:3] == (Path('/test/xray'), 'api', 'rmi') for args in calls))

    def test_never_removes_a_preexisting_runtime_tag(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            paths = dict(zip(('settings', 'core', 'monitor', 'firewall'), (root / n for n in ('settings', 'core', 'monitor', 'firewall'))))
            for path, data in zip(paths.values(), fixture()):
                path.write_bytes(data)
            activation = brutal.Activation({'role': 'panel'}, 8443, Path('/test/xray'), '127.0.0.1:10085', paths)
            activation.backup = root
            with patch.object(activation, 'runtime_tags', return_value={'hysteria2', brutal.TAG}), \
                 patch.object(brutal, 'unbound', return_value=True), \
                 patch.object(brutal.upgrade, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, '标签或端口'):
                    activation.apply()
                activation.rollback()
            run.assert_not_called()

    def test_failed_readiness_checkpoints_usage_then_restores_all_services(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            calls = []
            services = set(brutal.upgrade.PANEL_ORDER)
            services.add('xray-gateway-core')
            class FakeActivation:
                api_attempted = True
                binary = Path('/test/xray')
                api = '127.0.0.1:10085'
                def check(self): return True
                def save_backup(self): return root
                def verify_unchanged(self): pass
                def apply(self): calls.append(('apply',))
                def rollback(self): calls.append(('rollback',))
            def run(*args, **kwargs):
                calls.append(args)
                if args[:2] == ('systemctl', 'stop'): services.difference_update(args[2:])
                if args[:2] == ('systemctl', 'start'): services.update(args[2:])
                return SimpleNamespace(returncode=0, stdout='')
            info = {'role': 'panel', 'db': root / 'db', 'core_pid': root / 'pids', 'port': 18080}
            with patch.object(brutal.upgrade, 'run', side_effect=run), \
                 patch.object(brutal.upgrade, 'active', side_effect=lambda name: name in services), \
                 patch.object(brutal.upgrade, 'core_generation', return_value='123'), \
                 patch.object(brutal.upgrade, 'snapshot'), \
                 patch.object(brutal.upgrade, 'private_rows', return_value=([], {})), \
                 patch.object(brutal.upgrade, 'wait_http', side_effect=[RuntimeError('injected'), None]):
                with self.assertRaisesRegex(RuntimeError, 'injected'):
                    brutal.enable(info, FakeActivation())
            checkpoint = next(i for i, args in enumerate(calls) if str(args[0]).endswith('xcli-panel-checkpoint'))
            rollback = calls.index(('rollback',))
            self.assertLess(checkpoint, rollback)
            self.assertEqual(services, set(brutal.upgrade.PANEL_ORDER) | {'xray-gateway-core'})
            self.assertFalse(any(args[:2] == ('systemctl', 'restart') for args in calls))
            self.assertTrue((root / 'rolled-back').is_file())

    def test_failed_checkpoint_keeps_new_configuration_to_protect_counters(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            calls = []
            services = set(brutal.upgrade.PANEL_ORDER) | {'xray-gateway-core'}
            class FakeActivation:
                api_attempted = True
                binary = Path('/test/xray')
                api = '127.0.0.1:10085'
                def check(self): return True
                def save_backup(self): return root
                def verify_unchanged(self): pass
                def apply(self): pass
                def rollback(self): calls.append(('rollback',))
            def run(*args, **kwargs):
                calls.append(args)
                if str(args[0]).endswith('xcli-panel-checkpoint'):
                    raise subprocess.CalledProcessError(1, args)
                if args[:2] == ('systemctl', 'stop'): services.difference_update(args[2:])
                if args[:2] == ('systemctl', 'start'): services.update(args[2:])
                return SimpleNamespace(returncode=0, stdout='')
            info = {'role': 'panel', 'db': root / 'db', 'core_pid': root / 'pids', 'port': 18080}
            with patch.object(brutal.upgrade, 'run', side_effect=run), \
                 patch.object(brutal.upgrade, 'active', side_effect=lambda name: name in services), \
                 patch.object(brutal.upgrade, 'core_generation', return_value='123'), \
                 patch.object(brutal.upgrade, 'snapshot'), \
                 patch.object(brutal.upgrade, 'private_rows', return_value=([], {})), \
                 patch.object(brutal.upgrade, 'wait_http', side_effect=RuntimeError('injected')):
                with self.assertRaisesRegex(RuntimeError, '保留现有配置'):
                    brutal.enable(info, FakeActivation())
            self.assertNotIn(('rollback',), calls)
            self.assertEqual(services, set(brutal.upgrade.PANEL_ORDER) | {'xray-gateway-core'})


if __name__ == '__main__':
    unittest.main()
