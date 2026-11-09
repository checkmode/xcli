"""Exercise panel and node updates using disposable files and fake services."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('upgrade_rust', ROOT / 'rewrite/deploy/upgrade-rust.py')
upgrade = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upgrade)


class UpdateFixture:
    def __init__(self, root, role='panel'):
        self.root = root
        self.role = role
        self.lib = root / 'lib'
        self.releases = root / 'releases'
        self.backups = root / 'backups'
        self.config = root / 'config'
        self.state = root / 'state'
        self.current = root / 'current'
        self.revision = root / 'node-revision'
        for directory in (self.lib, self.releases, self.backups, self.config, self.state):
            directory.mkdir()
        for name in upgrade.PROGRAMS:
            (self.lib / name).write_bytes(('old-' + name).encode())
        (self.lib / 'xray').write_bytes(b'existing-xray')
        self.release = root / 'candidate'
        (self.release / 'bin').mkdir(parents=True)
        (self.release / 'web/gateway').mkdir(parents=True)
        (self.release / 'BUILD_STATUS').write_text('experimental\n')
        (self.release / 'web/gateway/main.js').write_text('new-web')
        for name in upgrade.PROGRAMS:
            (self.release / 'bin' / name).write_bytes(('new-' + name).encode())
        self.node = root / 'node'
        self.node.write_bytes(b'new-node-runtime')
        self.active = set(upgrade.PANEL_ORDER if role == 'panel' else ('xcli-node',))
        self.calls = []
        self.fail_start = None
        self.db = self.state / ('gateway.sqlite' if role == 'panel' else 'traffic.sqlite')
        with contextlib.closing(sqlite3.connect(str(self.db))) as db:
            if role == 'panel':
                db.execute('CREATE TABLE users(id,name,uuid,token,enabled,quota,expires,upload,download,created,deleted)')
                db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                           ('user', 'synthetic', 'uuid', 'token', 1, 100, 0, 10, 20, 1, 0))
                db.execute('CREATE TABLE admin(id,password)')
                db.execute('INSERT INTO admin VALUES(1,?)', ('fixture-password-hash',))
            else:
                db.execute('CREATE TABLE counters(name,value)')
                db.execute('INSERT INTO counters VALUES(?,?)', ('sample', 42))
                db.execute('CREATE TABLE node_totals(user_id,upload,download,ack_upload,ack_download)')
                db.execute('INSERT INTO node_totals VALUES(?,?,?,?,?)', ('user', 100, 200, 90, 190))
            db.commit()
        if role == 'panel':
            old = self.releases / 'old'
            (old / 'web').mkdir(parents=True)
            self.current.symlink_to(old)
            (self.lib / 'node').write_bytes(b'old-node-runtime')
            self.settings = self.config / 'settings.json'
            self.settings.write_text('{"origin":"https://panel.example"}')
            self.key = self.config / 'security.key'
            self.key.write_bytes(b'key-fixture')
            self.core_pid = root / 'core.pid'
            self.core_pid.write_text('123\n')
            self.info = {'role': 'panel', 'db': self.db, 'settings': self.settings,
                         'key': self.key, 'core_pid': self.core_pid}
        else:
            self.node_config = self.config / 'node.json'
            self.node_config.write_text('{"node_id":"fixture"}')
            self.core = self.config / 'core.json'
            self.core.write_text('{"fixture":true}')
            self.info = {'role': 'node', 'db': self.db, 'config': self.node_config, 'core': self.core}

    def command(self, *args, **kwargs):
        self.calls.append(args)
        if args[:2] == ('systemctl', 'stop'):
            self.active.difference_update(args[2:])
        if args[:2] == ('systemctl', 'start'):
            if self.fail_start in args[2:]:
                self.fail_start = None
                raise subprocess.CalledProcessError(1, args)
            self.active.update(args[2:])
        return SimpleNamespace(returncode=0, stdout='success\n')

    def stop_node(self):
        self.calls.append(('node-checkpoint-and-stop',))
        self.active.discard('xcli-node')

    def patches(self):
        stack = contextlib.ExitStack()
        for name, value in {'LIB': self.lib, 'RELEASES': self.releases, 'CURRENT': self.current,
                            'BACKUPS': self.backups, 'NODE_REVISION': self.revision}.items():
            stack.enter_context(patch.object(upgrade, name, value))
        stack.enter_context(patch.object(upgrade, 'run', side_effect=self.command))
        stack.enter_context(patch.object(upgrade, 'active', side_effect=lambda name: name in self.active))
        stack.enter_context(patch.object(upgrade, 'verify_candidate'))
        stack.enter_context(patch.object(upgrade, 'wait_http'))
        stack.enter_context(patch.object(upgrade, 'request', return_value=(200, b'fixture')))
        stack.enter_context(patch.object(upgrade, 'stop_node', side_effect=self.stop_node))
        stack.enter_context(patch.object(upgrade.time, 'sleep'))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        return stack


class RustUpgradeTests(unittest.TestCase):
    def test_candidate_may_reserve_new_names_without_changing_existing_data(self):
        key = 'residential_client_names_v1'
        before = {'admin': [(1, 'hash')], 'metadata': [('rules', 'unchanged')]}
        with_names = {'admin': [(1, 'hash')], 'metadata': [
            ('rules', 'unchanged'), (key, json.dumps({'SG': {'residential-01': 1}}))]}
        self.assertTrue(upgrade.protected_rows_compatible(before, with_names))
        extended = {'admin': [(1, 'hash')], 'metadata': [
            ('rules', 'unchanged'), (key, json.dumps({'SG': {'residential-01': 1, 'residential-02': 2}}))]}
        self.assertTrue(upgrade.protected_rows_compatible(with_names, extended))
        renumbered = {'admin': [(1, 'hash')], 'metadata': [
            ('rules', 'unchanged'), (key, json.dumps({'SG': {'residential-01': 2}}))]}
        self.assertFalse(upgrade.protected_rows_compatible(with_names, renumbered))
        self.assertFalse(upgrade.protected_rows_compatible(with_names, before))
        changed_rules = {'admin': [(1, 'hash')], 'metadata': [
            ('rules', 'changed'), (key, json.dumps({'SG': {'residential-01': 1}}))]}
        self.assertFalse(upgrade.protected_rows_compatible(with_names, changed_rules))
        self.assertFalse(upgrade.protected_rows_compatible(with_names, {'admin': [(1, 'other')],
            'metadata': with_names['metadata']}))

    def test_detects_existing_node_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = UpdateFixture(Path(temporary), 'node')
            systemd = f.root / 'systemd'
            systemd.mkdir()
            (systemd / 'xcli-node.service').write_text('fixture')
            args = ['/usr/local/lib/xcli/xcli-node-service', '--experimental', '--config', str(f.node_config),
                    '--state', str(f.state), '--core-config', str(f.core), '--xray', str(f.lib / 'xray')]
            with patch.object(upgrade, 'SYSTEMD', systemd), \
                 patch.object(upgrade, 'active', return_value=True), \
                 patch.object(upgrade, 'service_args', return_value=args):
                info = upgrade.detect()
            self.assertEqual(info['role'], 'node')
            self.assertEqual(info['db'], f.db)
            self.assertEqual(info['config'], f.node_config)

    def test_service_override_replaces_earlier_execstart(self):
        output = ('[Service]\nExecStart=/old --db /old.db\n'
                  '[Service]\nExecStart=\nExecStart=/new --db /new.db --settings /settings.json\n')
        with patch.object(upgrade, 'run', return_value=SimpleNamespace(stdout=output)):
            args = upgrade.service_args('xcli-panel')
        self.assertEqual(upgrade.argument(args, '--db'), Path('/new.db'))
        self.assertEqual(upgrade.argument(args, '--settings'), Path('/settings.json'))

    def test_panel_update_preserves_database_and_leaves_xray_running(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = UpdateFixture(Path(temporary))
            with f.patches():
                upgrade.apply(f.info, f.release, f.node, 'a' * 40)
            self.assertEqual((f.current / 'COMMIT').read_text().strip(), 'a' * 40)
            self.assertEqual((f.lib / 'xcli-panel-service').read_bytes(), b'new-xcli-panel-service')
            self.assertEqual((f.lib / 'node').read_bytes(), b'new-node-runtime')
            self.assertEqual((f.lib / 'xray').read_bytes(), b'existing-xray')
            self.assertEqual(f.active, set(upgrade.PANEL_ORDER))
            with contextlib.closing(sqlite3.connect(str(f.db))) as db:
                self.assertEqual(db.execute('SELECT name,token,upload,download FROM users').fetchone(),
                                 ('synthetic', 'token', 10, 20))
            self.assertTrue(list(f.backups.glob('rust-update-*/gateway.sqlite')))
            self.assertFalse(any('xcli-core' in call or 'nginx' in call for call in f.calls))

    def test_failed_panel_start_restores_previous_programs_and_database(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = UpdateFixture(Path(temporary))
            old = f.current.resolve()
            f.fail_start = 'xcli-web'
            with f.patches(), self.assertRaises(subprocess.CalledProcessError):
                upgrade.apply(f.info, f.release, f.node, 'b' * 40)
            self.assertEqual(f.current.resolve(), old)
            self.assertEqual((f.lib / 'xcli-panel-service').read_bytes(), b'old-xcli-panel-service')
            self.assertEqual((f.lib / 'node').read_bytes(), b'old-node-runtime')
            self.assertEqual(f.active, set(upgrade.PANEL_ORDER))
            with contextlib.closing(sqlite3.connect(str(f.db))) as db:
                self.assertEqual(db.execute('SELECT token,upload,download FROM users').fetchone(), ('token', 10, 20))

    def test_partial_binary_copy_failure_also_rolls_back(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = UpdateFixture(Path(temporary))
            original = upgrade.atomic_copy
            count = 0

            def fail_once(*args, **kwargs):
                nonlocal count
                count += 1
                if count == 3:
                    raise OSError('synthetic failure')
                return original(*args, **kwargs)

            with f.patches(), patch.object(upgrade, 'atomic_copy', side_effect=fail_once), self.assertRaises(OSError):
                upgrade.apply(f.info, f.release, f.node, 'c' * 40)
            self.assertEqual((f.lib / upgrade.PROGRAMS[0]).read_bytes(), ('old-' + upgrade.PROGRAMS[0]).encode())
            self.assertEqual(f.active, set(upgrade.PANEL_ORDER))

    def test_interrupt_during_switch_restores_previous_programs(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = UpdateFixture(Path(temporary))
            old = f.current.resolve()
            original = f.command
            interrupted = False

            def interrupt_once(*args, **kwargs):
                nonlocal interrupted
                if args[:3] == ('systemctl', 'start', 'xcli-web') and not interrupted:
                    interrupted = True
                    raise KeyboardInterrupt
                return original(*args, **kwargs)

            with f.patches(), patch.object(upgrade, 'run', side_effect=interrupt_once), \
                 self.assertRaises(KeyboardInterrupt):
                upgrade.apply(f.info, f.release, f.node, 'd' * 40)
            self.assertEqual(f.current.resolve(), old)
            self.assertEqual((f.lib / 'xcli-panel-service').read_bytes(), b'old-xcli-panel-service')
            self.assertEqual(f.active, set(upgrade.PANEL_ORDER))

    def test_incompatible_rollback_never_overwrites_current_database(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = UpdateFixture(Path(temporary))
            f.fail_start = 'xcli-web'
            original_command = f.command

            def corrupt_before_failure(*args, **kwargs):
                if args[:3] == ('systemctl', 'start', 'xcli-web') and f.fail_start:
                    with contextlib.closing(sqlite3.connect(str(f.db))) as db:
                        db.execute('UPDATE users SET upload=99')
                        db.commit()
                return original_command(*args, **kwargs)

            with f.patches(), patch.object(upgrade, 'run', side_effect=corrupt_before_failure), \
                 patch.object(upgrade, 'wait_http', side_effect=[None, None, RuntimeError('fixture')]), \
                 self.assertRaisesRegex(RuntimeError, '当前数据库未覆盖'):
                upgrade.apply(f.info, f.release, f.node, 'f' * 40)
            with contextlib.closing(sqlite3.connect(str(f.db))) as db:
                self.assertEqual(db.execute('SELECT upload FROM users').fetchone()[0], 99)
            failed = list(f.backups.glob('rust-update-*/failed.sqlite'))
            self.assertEqual(len(failed), 1)
            with contextlib.closing(sqlite3.connect(str(failed[0]))) as db:
                self.assertEqual(db.execute('SELECT upload FROM users').fetchone()[0], 99)
            self.assertEqual(f.active, set())

    def test_node_update_preserves_ledger_and_registration(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = UpdateFixture(Path(temporary), 'node')
            with f.patches():
                upgrade.apply(f.info, f.release, f.node, 'd' * 40)
            self.assertEqual(f.revision.read_text().strip(), 'd' * 40)
            self.assertEqual(f.node_config.read_text(), '{"node_id":"fixture"}')
            self.assertEqual((f.lib / 'xray').read_bytes(), b'existing-xray')
            self.assertIn(('node-checkpoint-and-stop',), f.calls)
            self.assertIn('xcli-node', f.active)
            with contextlib.closing(sqlite3.connect(str(f.db))) as db:
                self.assertEqual(db.execute('SELECT value FROM counters').fetchone()[0], 42)

    def test_failed_node_update_restores_old_program_and_ledger(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = UpdateFixture(Path(temporary), 'node')
            f.fail_start = 'xcli-node'
            with f.patches(), self.assertRaises(subprocess.CalledProcessError):
                upgrade.apply(f.info, f.release, f.node, 'f' * 40)
            self.assertEqual((f.lib / 'xcli-node-service').read_bytes(), b'old-xcli-node-service')
            self.assertFalse(f.revision.exists())
            self.assertEqual(f.node_config.read_text(), '{"node_id":"fixture"}')
            self.assertIn('xcli-node', f.active)
            with contextlib.closing(sqlite3.connect(str(f.db))) as db:
                self.assertEqual(db.execute('SELECT value FROM counters').fetchone()[0], 42)

    def test_busy_import_is_left_running_without_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            f = UpdateFixture(Path(temporary))
            report = f.root / 'report.json'
            report.write_text(json.dumps({'status': 'applying'}))
            f.info['import_report'] = report
            with f.patches(), self.assertRaisesRegex(RuntimeError, '代理导入正在执行'):
                upgrade.apply(f.info, f.release, f.node, 'e' * 40)
            self.assertEqual(f.active, set(upgrade.PANEL_ORDER))
            self.assertEqual((f.lib / 'xcli-panel-service').read_bytes(), b'old-xcli-panel-service')


if __name__ == '__main__':
    unittest.main()
