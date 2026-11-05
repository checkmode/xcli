"""Verify that a failed switch restores the old services and user data."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sqlite3
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('upgrade_legacy', ROOT / 'rewrite/deploy/upgrade-legacy.py')
upgrade = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upgrade)


class UpgradeRollback(unittest.TestCase):
    def test_failed_web_start_restores_legacy_installation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config, state, systemd, backups = (root / name for name in ('config', 'state', 'systemd', 'backups'))
            for path in (config, state, systemd, backups):
                path.mkdir()
            firewall = root / 'firewall.sh'
            firewall.write_text(upgrade.OLD_PORTS)
            old_release = root / 'old-release'
            old_release.mkdir()
            current = root / 'current'
            current.symlink_to(old_release)
            new_release = root / 'new-release'
            new_release.mkdir()
            release = root / 'build'
            release.mkdir()
            (release / 'BUILD_STATUS').write_text('experimental\n')
            node = root / 'node'
            node.write_text('fixture')
            with sqlite3.connect(str(state / 'gateway.sqlite')) as db:
                db.execute('CREATE TABLE users(id,name,uuid,token,enabled,quota,expires,upload,download,created,deleted)')
                db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                           ('user', 'synthetic', 'uuid', 'token', 1, 100, 0, 10, 20, 1, 0))
            calls = []

            def command(*args, **kwargs):
                calls.append(args)
                if args[:4] == ('systemctl', 'enable', '--now', 'xcli-web'):
                    raise subprocess.CalledProcessError(1, args)
                return SimpleNamespace(returncode=1 if args[:3] == ('iptables', '-w', '-C') else 0,
                                       stdout='123\n')

            account = SimpleNamespace(pw_uid=1, pw_gid=2)
            settings = {'origin': 'https://example.com'}
            with contextlib.ExitStack() as stack:
                for name, value in {'CONFIG': config, 'STATE': state, 'IMPORT': root / 'import',
                                    'CURRENT': current, 'FIREWALL': firewall, 'SYSTEMD': systemd,
                                    'BACKUPS': backups}.items():
                    stack.enter_context(patch.object(upgrade, name, value))
                stack.enter_context(patch.object(upgrade, 'preflight', return_value=(settings, 'probe', upgrade.OLD_PORTS)))
                stack.enter_context(patch.object(upgrade, 'install_artifacts', return_value=new_release))
                stack.enter_context(patch.object(upgrade, 'subscriptions', return_value={'fixture': (200, b'body')}))
                stack.enter_context(patch.object(upgrade, 'checked_old_request', return_value=False))
                stack.enter_context(patch.object(upgrade, 'command', side_effect=command))
                stack.enter_context(patch.object(upgrade.pwd, 'getpwnam', return_value=account))
                stack.enter_context(patch.object(upgrade.grp, 'getgrnam', return_value=SimpleNamespace(gr_gid=3)))
                stack.enter_context(patch.object(upgrade.os, 'chown'))
                stack.enter_context(patch.object(upgrade.os, 'fchown'))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                with self.assertRaises(subprocess.CalledProcessError):
                    upgrade.upgrade(release, node, 'a' * 40)

            self.assertEqual(current.resolve(), old_release.resolve())
            self.assertEqual(firewall.read_text(), upgrade.OLD_PORTS)
            with sqlite3.connect(str(state / 'gateway.sqlite')) as db:
                self.assertEqual(db.execute('SELECT name,upload,download FROM users').fetchone(),
                                 ('synthetic', 10, 20))
            self.assertTrue(any(c[:3] == ('systemctl', 'enable', '--now') and
                                'xray-gateway-panel' in c for c in calls))
            self.assertFalse(any(systemd.iterdir()))
            self.assertTrue(list(backups.glob('upgrade-*/gateway.sqlite')))


if __name__ == '__main__':
    unittest.main()
