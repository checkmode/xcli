"""Real filesystem and SQLite checks; systemd effects are isolated through a host adapter."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('xcli_release', Path(__file__).parents[1] / 'release.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class FakeHost:
    def __init__(self):
        self.calls = []
        self.pids = {u: i + 100 for i, u in enumerate(r.BASE_UNITS + [r.POOL, 'nginx', 'xray-gateway-core'])}
        self.data = {'schema': 'same', 'identities': 'same', 'security': {'admin': 'same'}, 'users': 1,
                     'traffic': {'alice': [100, 200]}}
        self.config = {'/etc/settings': 'same'}
        self.fail_health = None
        self.fail_preflight = False

    def installed(self, unit): return unit in self.pids
    def active(self, unit): return self.pids.get(unit, 0) > 0
    def pid(self, unit): return self.pids[unit]
    def configs(self): return self.config.copy()
    def state(self): return copy.deepcopy(self.data)
    def ready(self): pass
    def backup(self, folder): (folder / 'snapshot-sentinel').write_text('Never restore this into live data')
    def preflight(self, release):
        if self.fail_preflight: raise r.ReleaseError('schema changed on clone')
        return {'schema_unchanged': True}
    def health(self, release, units, **kwargs):
        if release.name == self.fail_health: raise r.ReleaseError('HTTP health failed')
    def command(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == 'systemctl' and args[1] in ('start', 'restart'):
            for unit in args[2:]: self.pids[unit] += 1
        return ''


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.host = FakeHost()
        self.manager = r.Manager(self.root, self.host)
        self.manager.prepare()
        self.old = self.make_release('baseline')
        self.new = self.make_release('candidate', importer='new importer')
        r.atomic_link(self.manager.current, self.old)

    def tearDown(self): self.temp.cleanup()

    def make_release(self, name, importer='old importer'):
        path = self.manager.app / 'releases' / name
        for file in r.REQUIRED | {'scripts/webshare.py', 'static/app.js', 'static/style.css'}:
            target = path / file
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(importer if file == 'scripts/proxy_import.py' else 'unchanged ' + file)
            target.chmod(0o755 if file.startswith('bin/') else 0o644)
        r.seal(path, name, {'kind': 'test'})
        return path

    def test_publish_and_rollback_keep_new_users_counters_and_configuration(self):
        core, pool, nginx = [self.host.pid(u) for u in ('xray-gateway-core', r.POOL, 'nginx')]
        result = self.manager.activate('candidate')
        self.assertEqual(result['restarted'], [r.PANEL, r.IMPORT])
        self.assertEqual(self.manager.current.resolve(), self.new)
        self.assertEqual(self.manager.previous.resolve(), self.old)
        self.host.data['traffic']['alice'] = [180, 290]
        self.host.data['traffic']['bob'] = [7, 9]
        self.host.data['identities'] = 'user added after release'
        self.host.data['users'] = 2
        self.host.config['/etc/settings'] = 'admin changed after release'
        self.manager.activate('baseline', 'rollback')
        self.assertEqual(self.host.data['traffic']['bob'], [7, 9])
        self.assertEqual(self.host.data['traffic']['alice'], [180, 290])
        self.assertEqual(self.host.config['/etc/settings'], 'admin changed after release')
        self.assertEqual([self.host.pid(u) for u in ('xray-gateway-core', r.POOL, 'nginx')], [core, pool, nginx])
        self.assertEqual(self.manager.current.resolve(), self.old)
        self.assertFalse(self.manager.journal.exists())

    def test_health_failure_restores_all_changed_components(self):
        self.host.fail_health = 'candidate'
        with self.assertRaisesRegex(r.ReleaseError, '已回到原程序'):
            self.manager.activate('candidate')
        self.assertEqual(self.manager.current.resolve(), self.old)
        self.assertIn(('systemctl', 'restart', r.PANEL, r.IMPORT), self.host.calls)
        self.assertFalse(self.manager.journal.exists())
        self.assertFalse(self.manager.previous.exists())
        self.assertEqual(self.host.data['traffic']['alice'], [100, 200])

    def test_recovery_failure_keeps_journal_then_explicit_recover_completes(self):
        normal = self.host.health
        self.host.health = lambda *a: (_ for _ in ()).throw(r.ReleaseError('service failed'))
        with self.assertRaisesRegex(r.ReleaseError, '自动回退未完成'):
            self.manager.activate('candidate')
        self.assertEqual(json.loads(self.manager.journal.read_text())['phase'], 'recovery_required')
        self.host.health = normal
        self.manager.recover()
        self.assertEqual(self.manager.current.resolve(), self.old)
        self.assertFalse(self.manager.journal.exists())

    def test_power_loss_journal_recovers_without_database_restore(self):
        record = self.manager.new_record(self.old, self.new, [r.PANEL, r.IMPORT], r.BASE_UNITS, 'activate')
        self.manager.record(record, 'switched')
        r.atomic_link(self.manager.current, self.new)
        self.host.data['traffic']['alice'] = [230, 410]
        self.manager.recover()
        self.assertEqual(self.manager.current.resolve(), self.old)
        self.assertEqual(self.host.data['traffic']['alice'], [230, 410])

    def test_schema_failure_and_tampering_never_stop_running_services(self):
        self.host.fail_preflight = True
        with self.assertRaisesRegex(r.ReleaseError, 'schema'):
            self.manager.activate('candidate')
        self.assertEqual(self.host.calls, [])
        self.host.fail_preflight = False
        (self.new / 'scripts/proxy_import.py').chmod(0o644)
        (self.new / 'scripts/proxy_import.py').write_text('tampered')
        with self.assertRaisesRegex(r.ReleaseError, 'SHA-256'):
            self.manager.activate('candidate')
        self.assertEqual(self.host.calls, [])
        self.assertEqual(self.manager.current.resolve(), self.old)

    def test_import_lock_blocks_publish(self):
        with self.manager.lock():
            with self.assertRaisesRegex(r.ReleaseError, '事务正在运行'):
                self.manager.activate('candidate')
        self.assertEqual(self.host.calls, [])

    def test_interrupted_transaction_blocks_new_publish(self):
        r.atomic_json(self.manager.journal, {'phase': 'switched'})
        with self.assertRaisesRegex(r.ReleaseError, 'recover'):
            self.manager.activate('candidate')
        self.assertEqual(self.host.calls, [])

    def test_stage_preserves_exact_payload_and_refuses_reuse(self):
        archive = self.root / 'bundle.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            for p in self.new.rglob('*'):
                if p.is_file(): tar.add(p, arcname=p.relative_to(self.new))
        other = r.Manager(self.root / 'other', self.host)
        result = other.stage(archive, r.digest(archive))
        self.assertEqual(result['staged'], 'candidate')
        self.assertEqual(r.inventory(self.new), r.inventory(other.app / 'releases/candidate'))
        with self.assertRaisesRegex(r.ReleaseError, '不可覆盖'):
            other.stage(archive, r.digest(archive))

    def test_wrong_bundle_hash_and_unsafe_tar_do_not_escape_staging(self):
        for kind in ('traversal', 'symlink', 'duplicate'):
            with self.subTest(kind=kind):
                archive = self.root / (kind + '.tar.gz')
                with tarfile.open(archive, 'w:gz') as tar:
                    item = tarfile.TarInfo('../escaped' if kind == 'traversal' else 'a')
                    item.size = 1
                    if kind == 'symlink':
                        item.type = tarfile.SYMTYPE; item.linkname = '/etc/passwd'; item.size = 0
                    tar.addfile(item, io.BytesIO(b'x'))
                    if kind == 'duplicate': tar.addfile(item, io.BytesIO(b'x'))
                with self.assertRaisesRegex(r.ReleaseError, 'SHA-256'):
                    self.manager.stage(archive, '0' * 64)
                with self.assertRaisesRegex(r.ReleaseError, '不安全'):
                    self.manager.stage(archive, r.digest(archive))
                self.assertFalse((self.manager.app / 'escaped').exists())

    def test_admin_helper_does_not_write_caches_into_release(self):
        source = Path(__file__).resolve().parents[2] / 'scripts/gatewayctl.py'
        fixture = self.root / 'admin-fixture'
        (fixture / 'scripts').mkdir(parents=True)
        helper = fixture / 'scripts/gatewayctl.py'
        helper.write_bytes(source.read_bytes())
        (fixture / 'app.py').write_text("import sqlite3\ndef db():\n c=sqlite3.connect(':memory:')\n c.execute('CREATE TABLE users(deleted INTEGER)')\n return c\n")
        before = r.inventory(fixture)
        result = subprocess.run([sys.executable, '-c',
            "import os,sys,runpy;os.geteuid=lambda:0;sys.argv=[sys.argv[1],'status'];runpy.run_path(sys.argv[0],run_name='__main__')",
            str(helper)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, r.inventory(fixture))

    def test_changed_service_definition_is_rejected_before_candidate_execution(self):
        manifest = json.loads((self.new / 'manifest.json').read_text())
        manifest['provenance'] = {'kind': 'git-build', 'service_templates': {}}
        r.atomic_json(self.new / 'manifest.json', manifest, 0o444)
        unit = self.root / 'unit.service'; unit.write_text('[Service]\nExecStart=/existing\n')
        host = r.Host()
        host.installed = lambda name: False
        calls = []
        def command(*args):
            calls.append(args)
            return str(unit)
        host.command = command
        with self.assertRaisesRegex(r.ReleaseError, '服务定义'):
            host.preflight(self.new)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], 'systemctl')

    def test_sqlite_schema_guard_detects_migration_and_counter_reset(self):
        database = self.root / 'test.sqlite'
        with sqlite3.connect(database) as db:
            db.executescript("CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT,upload INTEGER,download INTEGER);"
                             "INSERT INTO users VALUES('alice','Alice',100,200);"
                             "CREATE TABLE admin(id INTEGER,password TEXT);INSERT INTO admin VALUES(1,'test');")
        before = r.db_snapshot(database)
        with sqlite3.connect(database) as db: db.execute('ALTER TABLE users ADD COLUMN portal_origin TEXT')
        with self.assertRaisesRegex(r.ReleaseError, 'schema'):
            r.verify_state(before, r.db_snapshot(database))
        after = copy.deepcopy(before); after['traffic']['alice'] = [0, 0]
        with self.assertRaisesRegex(r.ReleaseError, '流量'):
            r.verify_state(before, after)

    def test_fresh_install_uses_one_immutable_release_and_refuses_reinitialization(self):
        self.manager.current.unlink()
        self.host.pids = {u: 0 for u in r.BASE_UNITS}
        self.manager.p('/usr/local/lib/xray-gateway').mkdir(parents=True)
        result = self.manager.initialize('candidate')
        self.assertEqual(result['status'], 'initialized')
        self.assertEqual(self.manager.current.resolve(), self.new)
        self.assertFalse(self.manager.previous.exists())
        alias = self.manager.p('/opt/xray-gateway/scripts')
        self.assertTrue(alias.is_symlink())
        self.assertEqual(os.readlink(alias), '/opt/xcli/current/scripts')
        self.assertIn('/opt/xcli/current/bin/xray-gateway-panel', self.manager.p(
            '/etc/systemd/system/xray-gateway-panel.service.d/90-release.conf').read_text())
        calls = self.host.calls[:]
        with self.assertRaisesRegex(r.ReleaseError, '不能初始化'):
            self.manager.initialize('baseline')
        self.assertEqual(calls, self.host.calls)

    def legacy_fixture(self):
        self.manager.current.unlink()
        legacy = self.manager.p('/opt/xray-gateway')
        import shutil
        shutil.copytree(self.old, legacy)
        (legacy / 'deploy').mkdir()
        (legacy / 'deploy/firewall.sh').write_text('host-specific firewall')
        link = self.manager.p('/usr/local/lib/xray-gateway/panel-current')
        link.parent.mkdir(parents=True)
        link.symlink_to(self.old / 'bin/xray-gateway-panel')
        command = self.host.command
        def host_command(*args, **kwargs):
            if args[:3] == ('systemctl', 'show', r.PANEL):
                return 'XG_STATIC=' + str(legacy / 'static')
            return command(*args, **kwargs)
        self.host.command = host_command
        return legacy, link

    def test_legacy_adoption_preserves_host_scripts_and_turns_old_paths_into_aliases(self):
        legacy, link = self.legacy_fixture()
        result = self.manager.adopt('captured')
        self.assertEqual(result['restarted'], [r.PANEL])
        self.assertTrue((legacy / 'scripts').is_symlink())
        self.assertTrue((Path(result['backup']) / 'legacy-app/app.py').is_file())
        self.assertEqual(self.manager.p('/usr/local/lib/xcli/host/firewall.sh').read_text(), 'host-specific firewall')
        value = r.validate_manifest(self.manager.current.resolve())
        self.assertEqual(value['provenance']['kind'], 'observed-live-baseline')
        self.assertIsNone(value['provenance']['revision'])

    def test_failed_legacy_adoption_restores_layout_and_old_service_paths(self):
        legacy, link = self.legacy_fixture()
        before = r.inventory(legacy)
        old_link = os.readlink(link)
        def health(release, units, binary=None):
            if binary is None:
                raise r.ReleaseError('candidate health failed')
        self.host.health = health
        with self.assertRaisesRegex(r.ReleaseError, '已回到原程序'):
            self.manager.adopt('captured')
        self.assertFalse(self.manager.current.exists())
        self.assertFalse(self.manager.journal.exists())
        self.assertEqual(r.inventory(legacy), before)
        self.assertEqual(os.readlink(link), old_link)
        self.assertFalse(self.manager.p('/usr/local/lib/xcli/host').exists())

    def test_bundle_from_different_ubuntu_release_is_rejected(self):
        manifest = json.loads((self.new / 'manifest.json').read_text())
        manifest['provenance']['build_platform'] = {'ID': 'ubuntu', 'VERSION_ID': '26.04'}
        r.atomic_json(self.new / 'manifest.json', manifest, 0o444)
        with patch.object(r.platform, 'freedesktop_os_release', create=True,
                          return_value={'ID': 'ubuntu', 'VERSION_ID': '24.04'}):
            with self.assertRaisesRegex(r.ReleaseError, 'Ubuntu 版本不匹配'):
                self.manager.activate('candidate')
        self.assertEqual(self.host.calls, [])

    def test_importer_compatibility_probe_uses_existing_config_without_writing_it(self):
        fixture = self.root / 'importer-fixture'; fixture.mkdir()
        script, settings, core = [fixture / n for n in ('importer.py', 'settings.json', 'core.json')]
        settings.write_text('{}'); core.write_text('{"supported": true}')
        script.write_text('class ImportErrorSafe(Exception): pass\n'
            'def check_capacity(settings,core,proxies):\n'
            ' if not core["supported"]: raise ImportErrorSafe("private input must not leak")\n')
        before = r.inventory(fixture)
        self.assertTrue(r.importer_accepts(script, settings, core))
        self.assertEqual(before, r.inventory(fixture))
        core.write_text('{"supported": false}')
        self.assertFalse(r.importer_accepts(script, settings, core))
        script.write_text('raise RuntimeError("private credential")\n')
        with self.assertRaisesRegex(r.ReleaseError, '无法加载') as caught:
            r.importer_accepts(script, settings, core)
        self.assertNotIn('private credential', str(caught.exception))


if __name__ == '__main__': unittest.main()
