#!/usr/bin/env python3
"""Versioned application releases. Host configuration/core upgrades are separate operations."""
import argparse
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shlex
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import uuid

sys.dont_write_bytecode = True
FORMAT = 1
VERSION = 'xray-gateway-panel 1.3.0 (C++20)'
APP = Path('/opt/xcli')
STATE = Path('/var/lib/xcli')
BACKUPS = Path('/var/backups/xcli/releases')
CACHE = Path('/var/cache/xcli')
PANEL = 'xray-gateway-panel'
IMPORT = 'xray-gateway-import'
MONITOR = 'xray-gateway-monitor'
POOL = 'xray-gateway-webshare'
BASE_UNITS = [PANEL, IMPORT, MONITOR]
WORKERS = {IMPORT: ['scripts/proxy_import.py', 'scripts/proxy_vmess.py'],
           MONITOR: ['scripts/probe.py'], POOL: ['scripts/webshare.py']}
REQUIRED = {'bin/xray-gateway-panel', 'app.py', 'static/runtime.js',
            'scripts/gatewayctl.py', 'scripts/probe.py', 'scripts/proxy_import.py', 'scripts/proxy_vmess.py'}
SCRIPTS = ['gatewayctl.py', 'probe.py', 'proxy_import.py', 'proxy_vmess.py', 'webshare.py']
CONFIGS = ['/etc/xray-gateway', '/etc/xcli-monitor', '/etc/nginx']
ID_RE = re.compile(r'[a-z0-9][a-z0-9._-]{0,95}\Z')


class ReleaseError(RuntimeError):
    pass


def require(value, message):
    if not value:
        raise ReleaseError(message)


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def encoded_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_json(path, value, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    try:
        with temp.open('x') as stream:
            os.chmod(temp, mode)
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        sync_directory(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def atomic_link(path, target):
    path = Path(path)
    require(not path.exists() or path.is_symlink(), f'拒绝覆盖非链接：{path}')
    temp = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    try:
        temp.symlink_to(target)
        os.replace(temp, path)
        sync_directory(path.parent)
    finally:
        temp.unlink(missing_ok=True)


def inventory(root):
    result = {}
    for path in sorted(Path(root).rglob('*')):
        require(not path.is_symlink(), f'版本包不允许符号链接：{path.name}')
        if path.is_dir():
            continue
        require(path.is_file(), '版本包只允许普通文件和目录')
        key = path.relative_to(root).as_posix()
        if key == 'manifest.json':
            continue
        result[key] = {'sha256': digest(path), 'size': path.stat().st_size,
                       'executable': bool(path.stat().st_mode & 0o111)}
    return result


def validate_manifest(root):
    root = Path(root)
    require(not root.is_symlink() and root.is_dir(), '版本目录无效')
    require(not (root / 'manifest.json').is_symlink(), '版本清单不能是链接')
    value = json.loads((root / 'manifest.json').read_text())
    require(value.get('format') == FORMAT and ID_RE.fullmatch(value.get('id', '')), '版本清单格式不支持')
    require(value.get('version') == VERSION, '当前流程仅支持 1.3.0 的兼容更新')
    require(value.get('architecture') == platform.machine(), '版本包架构不匹配')
    build_platform = value.get('provenance', {}).get('build_platform')
    if build_platform:
        current_platform = platform.freedesktop_os_release()
        require(build_platform == {k: current_platform.get(k) for k in ('ID', 'VERSION_ID')},
                '版本包的 Ubuntu 版本不匹配；请使用本机系统版本的构建产物')
    files = inventory(root)
    require(REQUIRED <= files.keys(), '版本包缺少必需组件')
    require(files == value.get('files'), '版本包内容与 SHA-256 清单不一致')
    for name in files:
        require(name in REQUIRED or name == 'scripts/webshare.py' or name.startswith('static/'),
                '版本包含未允许的组件：' + name)
    return value


def seal(root, release_id, provenance):
    require(ID_RE.fullmatch(release_id), '版本编号只能包含小写字母、数字、点、短横线、下划线')
    root = Path(root)
    value = {'format': FORMAT, 'id': release_id, 'version': VERSION, 'architecture': platform.machine(),
             'created_at': stamp(), 'provenance': provenance, 'files': inventory(root)}
    atomic_json(root / 'manifest.json', value, 0o444)
    validate_manifest(root)
    for p in root.rglob('*'):
        p.chmod(0o755 if p.is_dir() else 0o555 if p.stat().st_mode & 0o111 else 0o444)
    root.chmod(0o755)
    return value


def copy_payload(source, binary, static, destination):
    destination = Path(destination)
    (destination / 'bin').mkdir(parents=True)
    shutil.copyfile(binary, destination / 'bin/xray-gateway-panel')
    (destination / 'bin/xray-gateway-panel').chmod(0o755)
    shutil.copyfile(source / 'app.py', destination / 'app.py')
    (destination / 'scripts').mkdir()
    for name in SCRIPTS:
        if (source / 'scripts' / name).is_file():
            shutil.copyfile(source / 'scripts' / name, destination / 'scripts' / name)
    # Only web assets enter a release, never source trees, credentials or test state.
    (destination / 'static').mkdir()
    for path in static.rglob('*'):
        require(not path.is_symlink(), '静态目录不能包含链接')
        if path.is_file() and not path.name.startswith('.'):
            out = destination / 'static' / path.relative_to(static)
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, out)


def build_input_digest(source):
    names = [source / 'app.py']
    for folder in ('cpp', 'scripts', 'static', 'deploy'):
        names.extend(p for p in (source / folder).rglob('*') if p.is_file()
                     and '__pycache__' not in p.parts and not p.name.startswith('.'))
    return encoded_digest({p.relative_to(source).as_posix(): digest(p) for p in sorted(names)})


def pack(source, binary, release_id, revision, output):
    require(re.fullmatch('[0-9a-f]{40}', revision), '必须提供完整源码提交')
    require(not output.exists(), '输出包已经存在')
    receipt = source / '.xcli-build-receipt.json'
    require(receipt.is_file(), '缺少构建记录，请使用 build-release.sh 从固定提交构建')
    proof = json.loads(receipt.read_text())
    require(proof.get('revision') == revision and proof.get('binary_sha256') == digest(binary)
            and proof.get('source_digest') == build_input_digest(source), '源码或二进制与构建记录不一致')
    result = subprocess.check_output([str(binary), '--version'], text=True).strip()
    require(result == VERSION, '候选程序版本不兼容')
    with tempfile.TemporaryDirectory(prefix='xcli-package-') as temp:
        payload = Path(temp) / 'payload'
        copy_payload(source, binary, source / 'static', payload)
        seal(payload, release_id, {'kind': 'git-build', 'revision': revision,
            'build_platform': {k: platform.freedesktop_os_release().get(k) for k in ('ID', 'VERSION_ID')},
            'service_templates': {unit: digest(source / 'deploy' / (unit + '.service'))
                                  for unit in BASE_UNITS + [POOL]}})
        with tarfile.open(output, 'x:gz') as archive:
            for path in sorted(payload.rglob('*')):
                if path.is_file():
                    archive.add(path, arcname=path.relative_to(payload).as_posix(), recursive=False)
    checksum = digest(output)
    print(json.dumps({'bundle': str(output), 'sha256': checksum, 'release': release_id}))
    return checksum


def extract_bundle(bundle, expected, destination):
    require(re.fullmatch('[0-9a-f]{64}', expected), '必须提供独立确认的包 SHA-256')
    require(digest(bundle) == expected, '发布包 SHA-256 不匹配')
    with tarfile.open(bundle, 'r:gz') as archive:
        members = archive.getmembers()
        require(len(members) < 10000 and sum(m.size for m in members) < 512 * 1024 * 1024,
                '发布包过大')
        seen = set()
        for member in members:
            path = PurePosixPath(member.name)
            require(member.isfile() and not path.is_absolute() and '..' not in path.parts
                    and path.as_posix() == member.name and member.name not in seen
                    and not member.name.startswith('.'), '发布包包含不安全路径或重复项')
            seen.add(member.name)
        for member in members:
            target = destination / member.name
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as source, target.open('xb') as out:
                shutil.copyfileobj(source, out)
            target.chmod(0o555 if member.mode & 0o111 else 0o444)
    return validate_manifest(destination)


def db_snapshot(database):
    with contextlib.closing(sqlite3.connect('file:' + str(database) + '?mode=ro', uri=True)) as db:
        db.row_factory = sqlite3.Row
        db.execute('BEGIN')
        require(db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', '数据库完整性检查失败')
        users = [dict(row) for row in db.execute('SELECT * FROM users ORDER BY id')]
        stable = [{k: v for k, v in row.items() if k not in ('upload', 'download')} for row in users]
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        return {'schema': encoded_digest([tuple(r) for r in db.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]),
                'identities': encoded_digest(stable), 'users': len(users),
                'security': {t: encoded_digest([dict(row) for row in db.execute('SELECT * FROM ' + t + ' ORDER BY rowid')])
                             for t in ('admin', 'mfa', 'recovery_codes') if t in tables},
                'traffic': {r['id']: [r['upload'], r['download']] for r in users}}


def verify_state(before, after):
    for key in ('schema', 'identities', 'security'):
        require(before[key] == after[key], f'发布期间 {key} 发生变化；未自动恢复数据库')
    for uid, counters in before['traffic'].items():
        require(uid in after['traffic'] and all(a >= b for a, b in zip(after['traffic'][uid], counters)),
                '累计流量发生回退')


def write_compatibility(path):
    """Stable old paths are aliases, never a second copy of application code."""
    path.mkdir(mode=0o755)
    path.chmod(0o755)
    for name in ('app.py', 'scripts', 'static'):
        (path / name).symlink_to(APP / 'current' / name)
    (path / 'deploy').symlink_to('/usr/local/lib/xcli/host')
    (path / 'LAYOUT.txt').write_text('Compatibility paths only. Application releases: /opt/xcli/current. Host scripts: /usr/local/lib/xcli/host.\n')
    (path / 'LAYOUT.txt').chmod(0o644)


def importer_accepts(script, settings, core, prefix=()):
    """Read-only parser compatibility in a separate, unprivileged Python process."""
    code = '''import importlib.util,json,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('candidate_importer',sys.argv[1])
worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
settings=json.loads(Path(sys.argv[2]).read_text());core=json.loads(Path(sys.argv[3]).read_text())
try: worker.check_capacity(settings,core,[])
except worker.ImportErrorSafe: sys.exit(2)
'''
    result = subprocess.run([*prefix, sys.executable, '-B', '-c', code, str(script), str(settings), str(core)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    require(result.returncode in (0, 2), '节点导入程序无法加载；详细输出未公开，避免泄露配置')
    return result.returncode == 0


class Host:
    def command(self, *args, timeout=60):
        result = subprocess.run([str(x) for x in args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        require(result.returncode == 0, '命令执行失败：' + str(args[0]) + '（详细内容未输出，避免泄露配置）')
        return result.stdout.decode()

    def installed(self, unit):
        return subprocess.run(['systemctl', 'cat', unit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

    def pid(self, unit):
        return int(self.command('systemctl', 'show', unit, '-p', 'MainPID', '--value').strip())

    def active(self, unit):
        return subprocess.run(['systemctl', 'is-active', '--quiet', unit]).returncode == 0

    def configs(self):
        result = {}
        for name in CONFIGS:
            for path in sorted(Path(name).rglob('*')):
                if path.is_file():
                    result[str(path)] = digest(path)
        return result

    def state(self):
        return db_snapshot('/var/lib/xray-gateway/gateway.sqlite')

    def ready(self):
        require(not Path('/var/lib/xray-gateway-import/transaction.json').exists(), '存在未完成的节点导入事务')
        report = Path('/var/lib/xray-gateway-import/report.json')
        if report.exists():
            require(json.loads(report.read_text()).get('status') not in ('verifying', 'applying', 'ready'),
                    '请先完成或取消正在进行的节点操作')
        for unit in BASE_UNITS + ['xray-gateway-core', 'nginx']:
            require(self.active(unit), '服务未就绪：' + unit)

    def backup(self, folder):
        for name in CONFIGS:
            shutil.copytree(name, folder / Path(name).name, symlinks=True)
        with contextlib.closing(sqlite3.connect('file:/var/lib/xray-gateway/gateway.sqlite?mode=ro', uri=True)) as source:
            with contextlib.closing(sqlite3.connect(folder / 'gateway.sqlite')) as target:
                source.backup(target)
        (folder / 'gateway.sqlite').chmod(0o600)

    def preflight(self, release):
        manifest = validate_manifest(release)
        if manifest['provenance'].get('kind') == 'git-build':
            templates = manifest['provenance'].get('service_templates', {})
            for unit in BASE_UNITS + ([POOL] if self.installed(POOL) else []):
                path = self.command('systemctl', 'show', unit, '-p', 'FragmentPath', '--value').strip()
                require(templates.get(unit) == digest(Path(path)),
                        '服务定义与发布包要求不同，须另行迁移：' + unit)
        require(self.command(release / 'bin/xray-gateway-panel', '--version').strip() == VERSION, '版本不兼容')
        for path in (release / 'scripts').glob('*.py'):
            compile(path.read_bytes(), str(path), 'exec')
        current_importer = APP / 'current/scripts/proxy_import.py'
        if not current_importer.is_file():
            current_importer = Path('/opt/xray-gateway/scripts/proxy_import.py')
        candidate_importer = release / 'scripts/proxy_import.py'
        if current_importer.is_file() and digest(current_importer) != digest(candidate_importer):
            args = ('/etc/xray-gateway/settings.json', '/etc/xray-gateway/core.json')
            prefix = ('runuser', '-u', 'xgateway', '-g', 'xgateway', '--')
            accepted_before = importer_accepts(current_importer, *args, prefix=prefix)
            accepted_after = importer_accepts(candidate_importer, *args, prefix=prefix)
            require(not accepted_before or accepted_after,
                    '候选导入程序不再支持现有路由；先将线上兼容修复纳入源码，再构建新包')
        # Candidate initialization may migrate SQLite. Run it on a disposable copy first.
        CACHE.mkdir(parents=True, exist_ok=True)
        CACHE.chmod(0o755)
        with tempfile.TemporaryDirectory(prefix='preflight-', dir=CACHE) as temp:
            stage = Path(temp)
            shutil.chown(stage, 'xgateway', 'xgateway')
            stage.chmod(0o700)
            with contextlib.closing(sqlite3.connect('file:/var/lib/xray-gateway/gateway.sqlite?mode=ro', uri=True)) as src:
                with contextlib.closing(sqlite3.connect(stage / 'gateway.sqlite')) as dst:
                    src.backup(dst)
            shutil.chown(stage / 'gateway.sqlite', 'xgateway', 'xgateway')
            before = db_snapshot(stage / 'gateway.sqlite')
            out = self.command('runuser', '-u', 'xgateway', '-g', 'xgateway', '-G', 'xgmonitor', '--',
                               release / 'bin/xray-gateway-panel', '--state', stage,
                               '--secret-key', '/etc/xray-gateway/security.key',
                               '--monitor-config', '/etc/xcli-monitor/monitor.json', '--preflight')
            value = json.loads(out)
            require(value.get('database_integrity') == 'ok' and value.get('pending_additions') == 0
                    and value.get('pending_revocations') == 0, '候选版本会改变核心账号，停止切换')
            verify_state(before, db_snapshot(stage / 'gateway.sqlite'))
        return {'database_integrity': 'ok', 'schema_unchanged': True, 'core_identities_unchanged': True}

    def health(self, release, units, binary=None):
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for _ in range(30):
            try:
                with client.open('http://127.0.0.1:8080/healthz', timeout=2) as response:
                    require(response.status == 200, '面板未就绪')
                pid = self.pid(PANEL)
                require(Path(f'/proc/{pid}/exe').resolve() == (binary or release / 'bin/xray-gateway-panel').resolve(),
                        '面板实际进程与 current 不一致')
                for asset in ('runtime.js', 'app.js', 'style.css'):
                    if not (release / 'static' / asset).exists():
                        continue
                    with client.open('http://127.0.0.1:8080/static/' + asset, timeout=3) as response:
                        require(hashlib.sha256(response.read()).hexdigest() == digest(release / 'static' / asset),
                                '静态文件与版本包不一致')
                try:
                    client.open('http://127.0.0.1:8080/api/runtime', timeout=2)
                except urllib.error.HTTPError as error:
                    require(error.code == 401, '管理接口认证检查失败')
                else:
                    raise ReleaseError('管理接口未要求认证')
                require(all(self.active(u) for u in units), '发布组件未全部运行')
                return
            except (OSError, ReleaseError):
                time.sleep(1)
        raise ReleaseError('发布后健康检查未通过')


class Manager:
    def __init__(self, root=Path('/'), host=None):
        self.root, self.host = Path(root), host or Host()
        self.app, self.state, self.backups = self.p(APP), self.p(STATE), self.p(BACKUPS)
        self.current, self.previous = self.app / 'current', self.app / 'previous'
        self.journal = self.state / 'transaction.json'

    def p(self, path):
        return self.root / str(path).lstrip('/')

    def prepare(self):
        for path, mode in ((self.app, 0o755), (self.app / 'releases', 0o755),
                           (self.state, 0o700), (self.backups, 0o700)):
            require(not path.is_symlink(), '管理目录不能是链接')
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(mode)

    @contextlib.contextmanager
    def lock(self):
        path = self.p('/run/lock/xcli-update.lock')
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ReleaseError('另一个发布或节点配置事务正在运行') from None
            yield

    def target(self, release_id):
        require(ID_RE.fullmatch(release_id), '版本编号无效')
        path = self.app / 'releases' / release_id
        value = validate_manifest(path)
        require(value['id'] == release_id, '版本目录与清单编号不一致')
        return path, value

    def stage(self, bundle, sha256):
        self.prepare()
        with tempfile.TemporaryDirectory(prefix='.stage-', dir=self.app) as temp:
            payload = Path(temp)
            manifest = extract_bundle(bundle, sha256, payload)
            target = self.app / 'releases' / manifest['id']
            require(not target.exists(), '版本已存在；不可覆盖已发布版本')
            for p in payload.rglob('*'):
                if p.is_dir():
                    p.chmod(0o755)
            payload.chmod(0o755)
            os.rename(payload, target)
            sync_directory(target.parent)
        return {'staged': manifest['id'], 'bundle_sha256': sha256}

    def units(self, manifest):
        result = BASE_UNITS[:]
        if self.host.installed(POOL):
            require('scripts/webshare.py' in manifest['files'], '线上使用动态池，版本包缺少动态池程序')
            result.append(POOL)
        return result

    def dropins(self, units):
        commands = {
            PANEL: f'{APP}/current/bin/xray-gateway-panel',
            IMPORT: f'/usr/bin/python3 {APP}/current/scripts/proxy_import.py',
            MONITOR: f'/usr/bin/python3 {APP}/current/scripts/probe.py --config /etc/xcli-monitor/monitor.json --scope server --output /var/lib/xray-gateway-monitor/report.json --interval 60',
            POOL: f'/usr/bin/python3 {APP}/current/scripts/webshare.py'}
        return {self.p(f'/etc/systemd/system/{u}.service.d/90-release.conf'):
                '[Service]\nWorkingDirectory=' + str(APP / 'current') + '\nExecStart=\nExecStart=' + commands[u]
                + ('\nEnvironment=XG_STATIC=' + str(APP / 'current/static') if u == PANEL else '')
                + '\nEnvironment=PYTHONDONTWRITEBYTECODE=1\n' for u in units}

    def initialize(self, release_id):
        """Fresh installation only; the installer owns initial provisioning/failure cleanup."""
        self.prepare()
        with self.lock():
            require(not self.current.exists() and not self.current.is_symlink() and not self.journal.exists(),
                    '已有版本或未完成事务，不能初始化')
            require(not any(self.host.active(u) for u in BASE_UNITS), '已有应用服务运行，不能初始化')
            release, manifest = self.target(release_id)
            units = self.units(manifest)
            require(not self.p('/opt/xray-gateway').exists(), '已有应用目录，不能初始化')
            write_compatibility(self.p('/opt/xray-gateway'))
            for path, content in self.dropins(units).items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content)
                path.chmod(0o644)
            atomic_link(self.current, release)
            atomic_link(self.p('/usr/local/lib/xray-gateway/panel-current'), APP / 'current/bin/xray-gateway-panel')
            self.host.command('systemctl', 'daemon-reload')
            return {'release': release_id, 'status': 'initialized'}

    def adopt_layout(self, value):
        layout = value['layout']
        support, legacy = Path(layout['support']), self.p('/opt/xray-gateway')
        require(not support.exists(), '主机脚本目录已存在；请先核对历史布局')
        support.mkdir(parents=True, mode=0o755)
        support.chmod(0o755)
        for name in ('certificate.py', 'network.py', 'firewall.sh', 'renewal.sh'):
            source = legacy / 'deploy' / name
            if source.is_file():
                shutil.copy2(source, support / name)
        atomic_json(support / 'manifest.json', {p.name: digest(p) for p in support.iterdir()}, 0o444)
        temporary = Path(layout['temporary'])
        write_compatibility(temporary)
        legacy.rename(layout['archive'])
        temporary.rename(legacy)

    def restore_layout(self, value):
        layout = value.get('layout')
        if not layout:
            return  # Recovery of journals produced by the first release-tool version.
        legacy, archived = self.p('/opt/xray-gateway'), Path(layout['archive'])
        if archived.exists():
            if legacy.exists():
                require((legacy / 'LAYOUT.txt').is_file(), '兼容目录已改变，停止恢复')
                legacy.rename(Path(value['backup']) / 'compatibility-after-adoption')
            archived.rename(legacy)
        for key in ('support', 'temporary'):
            path = Path(layout[key])
            if path.exists():
                path.rename(Path(value['backup']) / ('unused-' + key))

    def guard(self):
        require(not self.journal.exists(), '有未完成发布；先执行 xcli-release recover')
        self.host.ready()

    def retained_pids(self, changed):
        return {u: self.host.pid(u) for u in ['xray-gateway-core', 'nginx', POOL]
                if u not in changed and self.host.installed(u)}

    def validate_after(self, record, release):
        self.host.health(release, record['units'])
        require(self.host.configs() == record['config_hashes'], '线上配置发生变化，未自动覆盖配置')
        verify_state(record['database'], self.host.state())
        require(all(self.host.pid(u) == pid for u, pid in record['retained_pids'].items()),
                '应保留的核心、Nginx 或动态池进程发生变化')

    def new_record(self, old, release, changed, units, kind):
        folder = self.backups / (stamp() + '-' + uuid.uuid4().hex[:8])
        folder.mkdir(mode=0o700)
        self.host.backup(folder)
        record = {'format': FORMAT, 'kind': kind, 'phase': 'prepared', 'created_at': stamp(), 'release_tool_sha256': digest(Path(__file__).resolve()),
                  'previous_target': str(old) if old else None, 'target': str(release),
                  'previous_link': os.readlink(self.previous) if self.previous.is_symlink() else None,
                  'changed': changed, 'units': units, 'backup': str(folder),
                  'config_hashes': self.host.configs(), 'database': self.host.state(),
                  'retained_pids': self.retained_pids(changed)}
        return record

    def record(self, value, phase):
        value['phase'] = phase
        atomic_json(Path(value['backup']) / 'transaction.json', value)
        atomic_json(self.journal, value)

    def finish(self, value, phase):
        self.record(value, phase)
        self.journal.unlink()
        sync_directory(self.journal.parent)

    def restore(self, value):
        old = Path(value['previous_target']) if value['previous_target'] else None
        if value['kind'] == 'adopt':
            self.restore_layout(value)
            for name, content in value['legacy_dropins'].items():
                path = Path(name)
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_text(content)
                    path.chmod(0o644)
            atomic_link(self.p('/usr/local/lib/xray-gateway/panel-current'), value['legacy_panel_link'])
            self.current.unlink(missing_ok=True)
            self.host.command('systemctl', 'daemon-reload')
        else:
            require(old is not None, '事务缺少回退版本')
            validate_manifest(old)
            atomic_link(self.current, old)
        if value['previous_link'] is None:
            self.previous.unlink(missing_ok=True)
        else:
            atomic_link(self.previous, value['previous_link'])
        self.host.command('systemctl', 'restart', *value['changed'])
        if old:
            self.host.health(old, value['units'])
        else:
            self.host.health(Path(value['target']), value['units'], binary=Path(value['legacy_panel_link']))
        self.finish(value, 'rolled_back')

    def apply(self, value, release, adopt=False):
        try:
            self.record(value, 'switching')
            # The importer shares our lock; stopping the panel freezes admin writes for the switch.
            self.host.command('systemctl', 'stop', *value['changed'])
            value['database'] = self.host.state()
            self.record(value, 'stopped')
            if adopt:
                for path, content in self.dropins(value['units']).items():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(content)
                    path.chmod(0o644)
                atomic_link(self.p('/usr/local/lib/xray-gateway/panel-current'), APP / 'current/bin/xray-gateway-panel')
                self.host.command('systemctl', 'daemon-reload')
            atomic_link(self.current, release)
            if adopt:
                self.adopt_layout(value)
            self.record(value, 'switched')
            self.host.command('systemctl', 'start', *value['changed'])
            self.validate_after(value, release)
            if value['previous_target']:
                atomic_link(self.previous, value['previous_target'])
            self.finish(value, 'committed')
        except BaseException:
            # SIGKILL / power loss leave the durable journal for an explicit recover.
            try:
                self.restore(value)
            except BaseException:
                self.record(value, 'recovery_required')
                raise ReleaseError('切换失败且自动回退未完成；运行 xcli-release recover，快照已保留') from None
            raise ReleaseError('切换未通过检查，已回到原程序；当前数据库和配置未被旧快照覆盖') from None
        return {'release': release.name, 'status': 'committed', 'restarted': value['changed'],
                'retained_pids': value['retained_pids'], 'backup': value['backup']}

    def activate(self, release_id, kind='activate'):
        self.prepare()
        with self.lock():
            self.guard()
            require(self.current.is_symlink(), '先执行 adopt 建立线上基线')
            release, manifest = self.target(release_id)
            old = self.current.resolve()
            old_manifest = validate_manifest(old)
            require(old != release, '该版本已经运行')
            units = self.units(manifest)
            self.host.preflight(release)
            changed = [PANEL] + [u for u in units if u in WORKERS and any(
                old_manifest['files'].get(p) != manifest['files'].get(p) for p in WORKERS[u])]
            value = self.new_record(old, release, changed, units, kind)
            return self.apply(value, release)

    def adopt(self, release_id):
        self.prepare()
        with self.lock():
            self.guard()
            require(not self.current.exists() and not self.current.is_symlink(), '部署已经纳入版本管理')
            require(not self.p('/usr/local/lib/xcli/host').exists(), '主机脚本目录已存在；请先核对历史布局')
            require(ID_RE.fullmatch(release_id), '版本编号无效')
            old_link = self.p('/usr/local/lib/xray-gateway/panel-current')
            require(old_link.is_symlink(), '未找到原面板链接')
            env = self.host.command('systemctl', 'show', PANEL, '-p', 'Environment', '--value')
            values = dict(item.split('=', 1) for item in shlex.split(env) if '=' in item)
            static = Path(values.get('XG_STATIC', '/opt/xray-gateway/static'))
            release = self.app / 'releases' / release_id
            require(not release.exists(), '基线版本编号已使用')
            copy_payload(self.p('/opt/xray-gateway'), old_link.resolve(), static, release)
            manifest = seal(release, release_id, {'kind': 'observed-live-baseline',
                'revision': None, 'binary_origin': str(old_link.resolve()), 'static_origin': str(static),
                'note': 'Mixed historical installation; component hashes are authoritative, not an inferred Git revision.'})
            units = self.units(manifest)
            self.host.preflight(release)
            value = self.new_record(None, release, [PANEL], units, 'adopt')
            value['legacy_panel_link'] = os.readlink(old_link)
            value['legacy_dropins'] = {str(p): p.read_text() if p.exists() else None for p in self.dropins(units)}
            value['layout'] = {'support': str(self.p('/usr/local/lib/xcli/host')),
                'archive': str(Path(value['backup']) / 'legacy-app'),
                'temporary': str(self.p('/opt/.xcli-compat-' + uuid.uuid4().hex))}
            return self.apply(value, release, adopt=True)

    def recover(self):
        with self.lock():
            require(self.journal.is_file(), '没有未完成发布')
            value = json.loads(self.journal.read_text())
            if value['phase'] in ('committed', 'rolled_back'):
                self.journal.unlink()
                return {'status': value['phase']}
            self.restore(value)
            return {'status': 'rolled_back', 'backup': value['backup']}

    def status(self):
        require(self.current.is_symlink(), '尚未建立版本管理基线')
        value = validate_manifest(self.current.resolve())
        result = {'current': value['id'], 'previous': self.previous.resolve().name if self.previous.is_symlink() else None,
                  'provenance': value['provenance'], 'component_hashes_verified': True,
                  'pending_transaction': self.journal.exists(),
                  'panel_matches_current': self.p(f'/proc/{self.host.pid(PANEL)}/exe').resolve() == (self.current / 'bin/xray-gateway-panel').resolve(),
                  'units': {u: {'active': self.host.active(u), 'pid': self.host.pid(u)}
                      for u in self.units(value) + ['xray-gateway-core', 'nginx']}}
        return result


def main(argv=None):
    p = argparse.ArgumentParser(description='xcli 完整应用版本的准备、校验、发布和回退；不自动恢复旧数据库')
    sub = p.add_subparsers(dest='action', required=True)
    a = sub.add_parser('pack'); a.add_argument('--source', type=Path, required=True); a.add_argument('--binary', type=Path, required=True)
    a.add_argument('--id', required=True); a.add_argument('--revision', required=True); a.add_argument('--output', type=Path, required=True)
    a = sub.add_parser('stage'); a.add_argument('bundle', type=Path); a.add_argument('--sha256', required=True)
    a = sub.add_parser('adopt'); a.add_argument('id')
    a = sub.add_parser('activate'); a.add_argument('id')
    a = sub.add_parser('check'); a.add_argument('id', nargs='?')
    a = sub.add_parser('rollback'); a.add_argument('id', nargs='?')
    sub.add_parser('status'); sub.add_parser('recover')
    args = p.parse_args(argv)
    os.umask(0o077)
    if args.action == 'pack':
        pack(args.source.resolve(), args.binary.resolve(), args.id, args.revision, args.output.resolve()); return
    require(os.geteuid() == 0, '请使用 sudo 执行')
    manager = Manager()
    if args.action == 'stage':
        with manager.lock():
            result = manager.stage(args.bundle, args.sha256)
    elif args.action == 'adopt': result = manager.adopt(args.id)
    elif args.action == 'activate': result = manager.activate(args.id)
    elif args.action == 'rollback':
        target = args.id or (manager.previous.resolve().name if manager.previous.is_symlink() else '')
        require(target, '尚无上一个版本；初次接管没有伪造的可回退版本')
        result = manager.activate(target, 'rollback')
    elif args.action == 'recover': result = manager.recover()
    elif args.action == 'check':
        with manager.lock():
            manager.guard()
            target = args.id or manager.current.resolve().name
            path, manifest = manager.target(target)
            manager.units(manifest)
            result = {'release': target, **manager.host.preflight(path)}
            if manager.current.is_symlink() and manager.current.resolve() == path:
                manager.host.health(path, manager.units(manifest))
                result['live_health_verified'] = True
    else: result = manager.status()
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (ReleaseError, OSError, ValueError, subprocess.SubprocessError) as error:
        print('发布工具：' + str(error), file=sys.stderr)
        sys.exit(1)
