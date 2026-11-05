#!/usr/bin/env python3
"""Update an installed Rust panel or node without replacing its state."""
import argparse
import contextlib
import datetime
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

LIB = Path('/usr/local/lib/xcli')
RELEASES = Path('/opt/xcli/releases')
CURRENT = Path('/opt/xcli/current')
BACKUPS = Path('/var/backups/xcli')
SYSTEMD = Path('/etc/systemd/system')
RUN_SYSTEMD = Path('/run/systemd/system')
LOCK = Path('/run/lock/xcli-rust-upgrade.lock')
NODE_REVISION = Path('/etc/xcli-node/revision')
PROGRAMS = (
    'xcli-cert-renew', 'xcli-host-disk-probe', 'xcli-import-probe',
    'xcli-import-service', 'xcli-monitor-service', 'xcli-node-service',
    'xcli-panel-checkpoint', 'xcli-panel-init', 'xcli-panel-service',
    'xcli-webhook-sender', 'xcli-webshare-service',
)
PANEL_ORDER = ('xcli-import', 'xcli-monitor', 'xcli-webshare', 'xcli-web', 'xcli-panel')


def run(*args, check=True, timeout=120):
    return subprocess.run([str(value) for value in args], check=check, timeout=timeout,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def active(name):
    return run('systemctl', 'is-active', '--quiet', name, check=False).returncode == 0


def service_args(name):
    text = run('systemctl', 'cat', name + '.service').stdout
    value = ''
    for line in text.splitlines():
        if line.startswith('ExecStart='):
            value = line[len('ExecStart='):]
    if not value:
        raise RuntimeError('无法读取服务启动配置：' + name)
    return shlex.split(value)


def argument(args, name):
    if args.count(name) != 1:
        raise RuntimeError('服务配置缺少参数：' + name)
    index = args.index(name)
    if index + 1 >= len(args) or not Path(args[index + 1]).is_absolute():
        raise RuntimeError('服务配置路径无效：' + name)
    return Path(args[index + 1])


def detect():
    panel = (SYSTEMD / 'xcli-panel.service').exists()
    node = (SYSTEMD / 'xcli-node.service').exists()
    if panel == node:
        raise RuntimeError('请在已安装 Rust 面板或独立节点的服务器上运行')
    role = 'panel' if panel else 'node'
    if not active('xcli-' + role):
        raise RuntimeError('当前服务未运行：xcli-' + role)
    args = service_args('xcli-' + role)
    if role == 'panel':
        result = {'role': role, 'db': argument(args, '--db'),
                  'settings': argument(args, '--settings'), 'key': argument(args, '--secret-key')}
        try:
            result['port'] = int(args[args.index('--port') + 1]) if '--port' in args else 18080
        except (ValueError, IndexError):
            raise RuntimeError('面板端口无效') from None
        if not 1 <= result['port'] <= 65535:
            raise RuntimeError('面板端口无效')
        if not CURRENT.is_symlink() or not active('xcli-web'):
            raise RuntimeError('面板发布目录或网页服务不可用')
        result['core_pid'] = argument(args, '--core-pid-file')
        if '--experimental-import-report-dir' in args:
            result['import_report'] = argument(args, '--experimental-import-report-dir') / 'report.json'
    else:
        state = argument(args, '--state')
        result = {'role': role, 'db': state / 'traffic.sqlite',
                  'config': argument(args, '--config'), 'core': argument(args, '--core-config')}
    for path in (result['db'],):
        if not path.is_file():
            raise RuntimeError('现有数据库不存在：' + str(path))
    with contextlib.closing(sqlite3.connect(f'file:{result["db"]}?mode=ro', uri=True, timeout=30)) as db:
        if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise RuntimeError('现有数据库检查失败')
    return result


def atomic_file(path, data, mode=0o600):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            os.fchmod(out.fileno(), mode)
            out.write(data.encode() if isinstance(data, str) else data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def atomic_copy(source, target, mode=0o755):
    target = Path(target)
    fd, tmp = tempfile.mkstemp(prefix='.' + target.name + '.', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as out, Path(source).open('rb') as incoming:
            shutil.copyfileobj(incoming, out, length=1024 * 1024)
            os.fchmod(out.fileno(), mode)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, target)
    finally:
        Path(tmp).unlink(missing_ok=True)


def atomic_link(target, link):
    temporary = Path(link).with_name('.' + Path(link).name + '.upgrade-' + str(os.getpid()))
    try:
        os.symlink(target, temporary)
        os.replace(temporary, link)
    finally:
        temporary.unlink(missing_ok=True)


def snapshot(source, destination):
    with contextlib.closing(sqlite3.connect(f'file:{source}?mode=ro', uri=True, timeout=30)) as incoming:
        with contextlib.closing(sqlite3.connect(str(destination), timeout=30)) as outgoing:
            incoming.backup(outgoing)
            if outgoing.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('数据库备份校验失败')
    os.chmod(destination, 0o600)


def private_rows(path, include_metadata=False):
    """Return only in memory; never write identities or credentials to logs."""
    with contextlib.closing(sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=30)) as db:
        users = db.execute('SELECT id,name,uuid,token,enabled,quota,expires,upload,download,created,deleted '
                           'FROM users ORDER BY id').fetchall()
        tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        protected = {}
        names = ('admin', 'mfa', 'recovery_codes', 'notification_config')
        if include_metadata:
            names += ('metadata',)
        for name in names:
            if name in tables:
                protected[name] = sorted(db.execute('SELECT * FROM "' + name + '"').fetchall(), key=repr)
    return users, protected


def identities(rows):
    return [row[:7] + row[9:] for row in rows]


def node_totals(path):
    with contextlib.closing(sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=30)) as db:
        rows = db.execute('SELECT user_id,upload,download,ack_upload,ack_download FROM node_totals').fetchall()
    return {row[0]: row[1:] for row in rows}


def request(port, path):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=12)
    try:
        conn.request('GET', path)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def wait_http(port, path='/healthz', timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if request(port, path)[0] == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.25)
    raise RuntimeError('面板服务未就绪')


def free_port():
    with contextlib.closing(socket.socket()) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def stop_process(process):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def verify_candidate(info, release, backup):
    """Open an isolated copy before allowing a panel update to touch live data."""
    if info['role'] != 'panel':
        return
    settings = json.loads(info['settings'].read_text())
    origin = settings.get('origin')
    if not isinstance(origin, str) or not origin.startswith('https://'):
        raise RuntimeError('面板地址无效')
    baseline, protected = private_rows(backup, include_metadata=True)
    account = pwd.getpwnam('xgateway')
    sandbox = Path(tempfile.mkdtemp(prefix='xcli-upgrade-check-', dir='/var/tmp'))
    os.chown(sandbox, account.pw_uid, account.pw_gid)
    os.chmod(sandbox, 0o700)
    try:
        for source, name in ((backup, 'gateway.sqlite'), (info['settings'], 'settings.json'),
                             (info['key'], 'security.key')):
            target = sandbox / name
            shutil.copyfile(source, target)
            os.chown(target, account.pw_uid, account.pw_gid)
            os.chmod(target, 0o600)
        webshare = info['db'].parent / 'webshare/config.xgb'
        if webshare.is_file():
            directory = sandbox / 'webshare'
            directory.mkdir(mode=0o700)
            os.chown(directory, account.pw_uid, account.pw_gid)
            shutil.copyfile(webshare, directory / 'config.xgb')
            os.chown(directory / 'config.xgb', account.pw_uid, account.pw_gid)
            os.chmod(directory / 'config.xgb', 0o600)
        sampled = [row for row in baseline if row[4] and not row[10]][:10]
        paths = ['/s/' + row[3] + suffix for row in sampled
                 for suffix in ('', '/clash.yaml', '/shadowrocket.json', '/shadowrocket.conf')]
        old_status = {path: request(8080, path)[0] for path in paths}

        def drop_identity():
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)

        for binary in (release / 'bin/xcli-panel-service', LIB / 'xcli-panel-service'):
            port = free_port()
            args = [str(binary), '--experimental', '--db', str(sandbox / 'gateway.sqlite'),
                    '--secret-key', str(sandbox / 'security.key'), '--settings', str(sandbox / 'settings.json'),
                    '--origin', origin, '--port', str(port), '--experimental-strict-settings', 'true']
            process = subprocess.Popen(args, preexec_fn=drop_identity, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                wait_http(port, timeout=20)
                if any(status == 200 and request(port, path)[0] != 200 for path, status in old_status.items()):
                    raise RuntimeError('新版无法继续提供原有订阅')
            finally:
                stop_process(process)
            after, after_protected = private_rows(sandbox / 'gateway.sqlite', include_metadata=True)
            if identities(after) != identities(baseline) or after_protected != protected:
                raise RuntimeError('新版数据库兼容检查未通过')
    finally:
        shutil.rmtree(sandbox)


def save_programs(names, backup):
    directory = backup / 'programs'
    directory.mkdir(mode=0o700)
    manifest = {}
    for name in names:
        path = LIB / name
        if path.is_symlink():
            manifest[name] = {'link': os.readlink(path)}
        elif path.is_file():
            shutil.copy2(path, directory / name)
            manifest[name] = {'mode': path.stat().st_mode & 0o777}
        elif path.exists():
            raise RuntimeError('程序路径不是普通文件：' + str(path))
        else:
            manifest[name] = None
    atomic_file(backup / 'programs.json', json.dumps(manifest))
    return manifest


def restore_programs(manifest, backup):
    for name, entry in manifest.items():
        path = LIB / name
        if entry is None:
            path.unlink(missing_ok=True)
        elif 'link' in entry:
            atomic_link(entry['link'], path)
        else:
            atomic_copy(backup / 'programs' / name, path, entry['mode'])


def stop_node(unit='xcli-node'):
    # The node owns its Xray child. Signal the node first so it can sample
    # the ledger before stopping Xray; systemd still kills leftovers on timeout.
    directory = RUN_SYSTEMD / (unit + '.service.d')
    directory.mkdir(parents=True, exist_ok=True)
    override = directory / 'zz-xcli-upgrade.conf'
    if override.exists():
        raise RuntimeError('节点存在同名临时服务配置')
    try:
        atomic_file(override, '[Service]\nKillMode=mixed\n', 0o644)
        run('systemctl', 'daemon-reload')
        if run('systemctl', 'show', unit, '-p', 'KillMode', '--value').stdout.strip() != 'mixed':
            raise RuntimeError('无法启用节点的有序停止')
        run('systemctl', 'stop', unit)
        if run('systemctl', 'show', unit, '-p', 'Result', '--value').stdout.strip() != 'success':
            raise RuntimeError('节点停止前的用量采集未完成')
    finally:
        override.unlink(missing_ok=True)
        try:
            directory.rmdir()
        except OSError:
            pass
        run('systemctl', 'daemon-reload', check=False)


def core_generation(info):
    try:
        return info['core_pid'].read_text().strip()
    except (OSError, KeyError):
        return ''


def apply(info, release, node_binary, revision):
    if (release / 'BUILD_STATUS').read_text().strip() != 'experimental':
        raise RuntimeError('新版构建结果无效')
    for name in PROGRAMS:
        if not (release / 'bin' / name).is_file():
            raise RuntimeError('新版程序不完整：' + name)
    if info['role'] == 'panel' and not (release / 'web/gateway/main.js').is_file():
        raise RuntimeError('新版网页构建结果不完整')
    if info['role'] == 'panel' and info.get('import_report', Path('/nonexistent')).is_file():
        phase = json.loads(info['import_report'].read_text()).get('status')
        if phase in ('verifying', 'applying'):
            raise RuntimeError('代理导入正在执行，请稍后重试')
    BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(BACKUPS, 0o700)
    backup = Path(tempfile.mkdtemp(prefix='rust-update-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-', dir=BACKUPS))
    snapshot(info['db'], backup / 'before.sqlite')
    config_backup = backup / 'config'
    config_backup.mkdir(mode=0o700)
    config_hashes = {}
    for name in ('settings', 'key', 'config', 'core'):
        if name in info:
            shutil.copyfile(info[name], config_backup / name)
            os.chmod(config_backup / name, 0o600)
            config_hashes[name] = hashlib.sha256((config_backup / name).read_bytes()).digest()
    if info['role'] == 'node':
        registration = info['config'].parent / 'registration.json'
        if registration.is_file():
            shutil.copyfile(registration, config_backup / 'registration.json')
            os.chmod(config_backup / 'registration.json', 0o600)
    verify_candidate(info, release, backup / 'before.sqlite')
    names = list(PROGRAMS) + (['node'] if info['role'] == 'panel' else [])
    manifest = save_programs(names, backup)
    services = [name for name in PANEL_ORDER if active(name)] if info['role'] == 'panel' else ['xcli-node']
    old_link = os.readlink(CURRENT) if info['role'] == 'panel' else None
    old_revision = NODE_REVISION.read_bytes() if info['role'] == 'node' and NODE_REVISION.is_file() else None
    atomic_file(backup / 'installation.json', json.dumps({
        'role': info['role'], 'services': services, 'old_current': old_link,
        'old_node_revision': old_revision.decode('ascii').strip() if old_revision else None,
    }))
    generation = core_generation(info)
    old_users = None
    old_node_totals = None
    started = False
    switched = False
    new_release = None
    print('已备份数据并完成更新前检查。', flush=True)
    try:
        started = True
        if info['role'] == 'panel':
            for name in services:
                run('systemctl', 'stop', name)
        else:
            stop_node()
        snapshot(info['db'], backup / 'gateway.sqlite')
        if any(hashlib.sha256(info[name].read_bytes()).digest() != digest
               for name, digest in config_hashes.items()):
            raise RuntimeError('配置在更新期间发生变化，请重试')
        if info['role'] == 'panel':
            old_users, old_protected = private_rows(backup / 'gateway.sqlite')
            RELEASES.mkdir(mode=0o755, parents=True, exist_ok=True)
            new_release = Path(tempfile.mkdtemp(prefix='rust-' + revision[:12] + '-', dir=RELEASES))
            os.chmod(new_release, 0o755)
            shutil.copytree(release / 'web', new_release / 'web')
            atomic_file(new_release / 'COMMIT', revision + '\n', 0o644)
        else:
            old_node_totals = node_totals(backup / 'gateway.sqlite')
        for name in PROGRAMS:
            atomic_copy(release / 'bin' / name, LIB / name)
        if info['role'] == 'panel':
            atomic_copy(node_binary, LIB / 'node')
            atomic_link(str(new_release), CURRENT)
        switched = True
        if info['role'] == 'panel':
            run('systemctl', 'start', 'xcli-panel')
            wait_http(info.get('port', 18080))
            wait_http(info.get('port', 18080), '/internal/ready', timeout=45)
            new_users, new_protected = private_rows(info['db'])
            if identities(new_users) != identities(old_users) or new_protected != old_protected:
                raise RuntimeError('更新后用户数据不一致')
            before_usage = {row[0]: row[7:9] for row in old_users}
            if any(any(value < old for value, old in zip(row[7:9], before_usage[row[0]])) for row in new_users):
                raise RuntimeError('更新后累计用量异常')
            for name in reversed(services):
                if name != 'xcli-panel':
                    run('systemctl', 'start', name)
            wait_http(8080)
            sampled = [row for row in old_users if row[4] and not row[10]][:10]
            for row in sampled:
                for suffix in ('', '/clash.yaml'):
                    if request(8080, '/s/' + row[3] + suffix)[0] != request(info.get('port', 18080), '/s/' + row[3] + suffix)[0]:
                        raise RuntimeError('网页入口未能正确转发订阅')
        else:
            run('systemctl', 'start', 'xcli-node')
            atomic_file(NODE_REVISION, revision + '\n', 0o600)
        time.sleep(2)
        for name in services:
            if not active(name):
                raise RuntimeError('服务未能启动：' + name)
        if info['role'] == 'node':
            current = node_totals(info['db'])
            if any(user not in current or any(value < old for value, old in zip(current[user], totals))
                   for user, totals in old_node_totals.items()):
                raise RuntimeError('节点累计用量异常；原账本已保存在备份中')
        if info['role'] == 'panel' and generation and core_generation(info) != generation:
            print('提示：更新期间 Xray 核心发生了重启。', flush=True)
        print('更新完成，现有配置、用户数据和订阅地址已保留。', flush=True)
        print('更新前备份：' + str(backup), flush=True)
    except BaseException:
        if started:
            print('更新未完成，正在恢复上一版本。', flush=True)
            run('systemctl', 'stop', *services, check=False)
        if switched or started:
            restore_programs(manifest, backup)
            if old_link is not None:
                atomic_link(old_link, CURRENT)
            elif info['role'] == 'node':
                if old_revision is None:
                    NODE_REVISION.unlink(missing_ok=True)
                else:
                    atomic_file(NODE_REVISION, old_revision)
        if started:
            for name in reversed(services):
                run('systemctl', 'start', name, check=False)
            if info['role'] == 'panel':
                try:
                    wait_http(8080, timeout=20)
                except RuntimeError:
                    # Never replace state that the new version may have committed.
                    run('systemctl', 'stop', *services, check=False)
                    try:
                        snapshot(info['db'], backup / 'failed.sqlite')
                    except (OSError, sqlite3.Error, RuntimeError):
                        shutil.copy2(info['db'], backup / 'failed.sqlite.raw')
                        for suffix in ('-wal', '-shm'):
                            source = Path(str(info['db']) + suffix)
                            if source.is_file():
                                shutil.copy2(source, backup / ('failed.sqlite.raw' + suffix))
                    raise RuntimeError('上一版本未能恢复；当前数据库未覆盖，备份：' + str(backup)) from None
            time.sleep(2)
            failed = [name for name in services if not active(name)]
            if failed:
                raise RuntimeError('旧服务未能全部恢复：' + ', '.join(failed) + '；备份：' + str(backup))
            print('已恢复上一版本；备份：' + str(backup), flush=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--release-dir', type=Path)
    parser.add_argument('--node-bin', type=Path)
    parser.add_argument('--revision')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('请使用 root 或 sudo 运行')
    info = detect()
    if args.check:
        print('检查通过：已识别 Rust ' + ('面板' if info['role'] == 'panel' else '独立节点') + '，更新将保留现有数据。')
        return
    if not args.release_dir or not args.node_bin or not re.fullmatch(r'[0-9a-f]{40}', args.revision or ''):
        raise RuntimeError('缺少构建结果或源码版本，请运行项目根目录的 upgrade.sh')
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt
    for value in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(value, interrupted)
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open('a+') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('已有更新任务正在运行') from None
        info = detect()
        marker = CURRENT / 'COMMIT' if info['role'] == 'panel' else NODE_REVISION
        if marker.is_file() and marker.read_text().strip() == args.revision:
            print('当前业务版本已经安装。')
            return
        apply(info, args.release_dir.resolve(strict=True), args.node_bin.resolve(strict=True), args.revision)


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print('更新停止：' + str(error), file=sys.stderr, flush=True)
        raise SystemExit(1)
