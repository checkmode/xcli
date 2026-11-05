#!/usr/bin/env python3
"""Upgrade a legacy single-server panel while keeping its database and URLs."""
import argparse
import contextlib
import datetime
import grp
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

CONFIG = Path('/etc/xray-gateway')
STATE = Path('/var/lib/xray-gateway')
IMPORT = Path('/var/lib/xcli-import')
MONITOR = Path('/etc/xcli-monitor/monitor.json')
REPORT = Path('/var/lib/xray-gateway-monitor/report.json')
FIREWALL = Path('/opt/xray-gateway/deploy/firewall.sh')
CURRENT = Path('/opt/xcli/current')
LIB = Path('/usr/local/lib/xcli')
SYSTEMD = Path('/etc/systemd/system')
BACKUPS = Path('/var/backups/xcli')
OLD = ('xray-gateway-import', 'xray-gateway-monitor', 'xray-gateway-panel')
NEW = ('xcli-panel', 'xcli-web', 'xcli-monitor', 'xcli-import')
OLD_PORTS = '--dports 8080,10085,10080,10443'
NEW_PORTS = OLD_PORTS + ',18080'


def command(*args, check=True, capture=False, timeout=90):
    return subprocess.run([str(x) for x in args], check=check, timeout=timeout,
                          stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                          stderr=subprocess.PIPE, text=True)


def read_json(path):
    return json.loads(Path(path).read_text())


def atomic(path, content, mode=0o600, uid=0, gid=0):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            os.fchown(out.fileno(), uid, gid)
            os.fchmod(out.fileno(), mode)
            out.write(content.encode() if isinstance(content, str) else content)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def swap_current(target):
    link = CURRENT.with_name('.xcli-upgrade-current-' + str(os.getpid()))
    try:
        os.symlink(target, link)
        os.replace(link, CURRENT)
    finally:
        link.unlink(missing_ok=True)


def snapshot_database(destination):
    with sqlite3.connect(f'file:{STATE / "gateway.sqlite"}?mode=ro', uri=True, timeout=30) as source:
        with sqlite3.connect(str(destination), timeout=30) as target:
            source.backup(target)
            if target.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('用户数据库备份校验失败')
    os.chmod(destination, 0o600)


def user_rows(path):
    with sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=30) as db:
        return db.execute('SELECT id,name,uuid,token,enabled,quota,expires,upload,download,created,deleted '
                          'FROM users ORDER BY id').fetchall()


def user_identity(rows):
    return [row[:7] + row[9:] for row in rows]


def fetch(port, path):
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
    try:
        conn.request('GET', path)
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def subscriptions(rows):
    results = {}
    for row in rows:
        for suffix in ('', '/clash.yaml', '/shadowrocket.json', '/shadowrocket.conf'):
            results[(row[0], suffix)] = fetch(8080, '/s/' + row[3] + suffix)
    return results


def wait_http(path, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if fetch(8080, path)[0] == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.5)
    raise RuntimeError('新面板未就绪')


def checked_old_request(backup):
    request = STATE / 'proxy-import/request.xgb'
    if not request.exists():
        return False
    # The old worker keeps its last completed request. Preserve it but don't
    # allow the replacement worker to execute it again.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    frame = request.read_bytes()
    if frame[:4] != b'XGB1' or len(frame) < 32:
        raise RuntimeError('旧导入请求无法识别')
    value = json.loads(AESGCM((CONFIG / 'security.key').read_bytes()).decrypt(
        frame[4:16], frame[32:] + frame[16:32], b'xcli:proxy-import:request:v1'))
    processed = read_json('/var/lib/xray-gateway-import/processed.json')
    if value.get('id') not in processed:
        raise RuntimeError('有尚未完成的代理导入，请稍后重试')
    shutil.move(request, backup / 'previous-import-request.xgb')
    return True


def units(origin, panel_gid):
    panel = f'''[Unit]
Description=XCLI Rust management service
After=network-online.target xray-gateway-core.service
Wants=network-online.target xray-gateway-core.service
[Service]
User=xgateway
Group=xgateway
SupplementaryGroups=xgmonitor
EnvironmentFile=/etc/xray-gateway/rust-panel.env
ExecStart=/usr/local/lib/xcli/xcli-panel-service --experimental --db /var/lib/xray-gateway/gateway.sqlite --secret-key /etc/xray-gateway/security.key --settings /etc/xray-gateway/settings.json --origin ${{XCLI_ORIGIN}} --port 18080 --experimental-strict-settings true --core-binary /usr/local/lib/xcli/xray --core-api 127.0.0.1:10085 --core-pid-file /sys/fs/cgroup/system.slice/xray-gateway-core.service/cgroup.procs --core-tags auto --core-probe-uuid ${{XCLI_PROBE_UUID}} --monitor-report /var/lib/xray-gateway-monitor/report.json --experimental-disk-probe /usr/local/lib/xcli/xcli-host-disk-probe --experimental-import-report-dir /var/lib/xcli-import/report --experimental-import-report-gid {panel_gid} --experimental-import-inbox /var/lib/xray-gateway/proxy-import --experimental-import-apply true --experimental-notification-delivery true --automatic-backups true
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/xray-gateway
CapabilityBoundingSet=
UMask=0077
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
'''
    web = '''[Unit]
Description=XCLI web gateway
After=xcli-panel.service
Wants=xcli-panel.service
[Service]
User=xgateway
Group=xgateway
Environment=XCLI_CORE_PORT=18080
Environment=XCLI_WEB_PORT=8080
ExecStart=/usr/local/lib/xcli/node /opt/xcli/current/web/gateway/main.js
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
CapabilityBoundingSet=
UMask=0077
[Install]
WantedBy=multi-user.target
'''
    monitor = '''[Unit]
Description=XCLI public entry monitor
After=network-online.target xcli-panel.service xcli-web.service
Wants=network-online.target
[Service]
User=xgprobe
Group=xgmonitor
ExecStart=/usr/local/lib/xcli/xcli-monitor-service --experimental --config /etc/xcli-monitor/monitor.json --state-dir /var/lib/xray-gateway-monitor --scope server --interval 60
Restart=on-failure
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/xray-gateway-monitor
CapabilityBoundingSet=
UMask=0027
LimitNOFILE=1024
[Install]
WantedBy=multi-user.target
'''
    worker = '''[Unit]
Description=XCLI fixed proxy import worker
After=network-online.target xcli-panel.service
Wants=network-online.target
[Service]
ExecStart=/usr/local/lib/xcli/xcli-import-service --experimental --config /etc/xray-gateway/rust-import.json
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/xray-gateway /var/lib/xcli-import /etc/xray-gateway /etc/xcli-monitor /etc/nginx /run /var/log/nginx
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UMask=0077
LimitNOFILE=512
[Install]
WantedBy=multi-user.target
'''
    return dict(zip(NEW, (panel, web, monitor, worker)))


def worker_config(panel, probe, probe_gid):
    nginx = Path('/etc/nginx/xcli.conf')
    if not nginx.is_file():
        nginx = Path('/etc/nginx/nginx.conf')
    return {
        'mode': 'apply', 'key': str(CONFIG / 'security.key'),
        'inbox': str(STATE / 'proxy-import'), 'state': str(IMPORT / 'state'),
        'journal': str(IMPORT / 'journal'), 'update_lock': str(IMPORT / 'journal/update.lock'),
        'legacy_processed': '/var/lib/xray-gateway-import/processed.json',
        'report_directory': str(IMPORT / 'report'), 'panel_uid': panel.pw_uid,
        'panel_gid': panel.pw_gid, 'probe_uid': probe.pw_uid, 'probe_gid': probe_gid,
        'targets': {'settings': str(CONFIG / 'settings.json'), 'core': str(CONFIG / 'core.json'),
                    'monitor': str(MONITOR), 'nginx': str(nginx),
                    'locations': '/etc/nginx/xcli-import-locations.conf',
                    'pool': str(CONFIG / 'imported-proxies.json')},
        'database': str(STATE / 'gateway.sqlite'),
        'core_pid_file': '/sys/fs/cgroup/system.slice/xray-gateway-core.service/cgroup.procs',
        'core_api': '127.0.0.1:10085', 'panel_port': 18080,
        'monitor_report': str(REPORT), 'core_unit': 'xray-gateway-core.service',
        'panel_unit': 'xcli-panel.service', 'monitor_unit': 'xcli-monitor.service',
    }


def preflight():
    if os.geteuid() != 0 or platform.system() != 'Linux' or not Path('/run/systemd/system').is_dir():
        raise RuntimeError('请在使用 systemd 的 Linux 主机上以 root 运行')
    if not CURRENT.is_symlink() or not (STATE / 'gateway.sqlite').is_file():
        raise RuntimeError('未找到旧版面板和用户数据库')
    for service in (*OLD, 'xray-gateway-core', 'nginx'):
        command('systemctl', 'is-active', '--quiet', service)
    if command('systemctl', 'is-active', '--quiet', 'xray-gateway-webshare', check=False).returncode == 0:
        raise RuntimeError('当前升级脚本尚不支持正在运行的动态住宅服务')
    for path in (IMPORT, CONFIG / 'rust-panel.env', CONFIG / 'rust-import.json',
                 *(SYSTEMD / (name + '.service') for name in NEW)):
        if path.exists() or path.is_symlink():
            raise RuntimeError('发现已有新版配置：' + str(path))
    firewall = FIREWALL.read_text()
    if firewall.count(OLD_PORTS) != 1:
        raise RuntimeError('旧版防火墙配置与升级脚本不匹配')
    with contextlib.closing(socket.socket()) as sock:
        sock.bind(('127.0.0.1', 18080))
    settings, monitor = read_json(CONFIG / 'settings.json'), read_json(MONITOR)
    origin, probe = settings.get('origin', ''), monitor.get('uuid', '')
    if not re.fullmatch(r'https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?', origin):
        raise RuntimeError('旧版面板地址无效')
    if not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', probe):
        raise RuntimeError('旧版监测配置无效')
    with sqlite3.connect(f'file:{STATE / "gateway.sqlite"}?mode=ro', uri=True) as db:
        if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise RuntimeError('旧版用户数据库检查失败')
    return settings, probe, firewall


def install_artifacts(release, node, revision):
    LIB.mkdir(mode=0o755, parents=True, exist_ok=True)
    for source in sorted((release / 'bin').iterdir()):
        target = LIB / source.name
        if target.exists() and hashlib.sha256(target.read_bytes()).digest() != hashlib.sha256(source.read_bytes()).digest():
            raise RuntimeError('新版程序路径已存在其他文件：' + str(target))
        if not target.exists():
            shutil.copyfile(source, target)
            os.chmod(target, 0o755)
    target = LIB / 'node'
    if target.exists() and hashlib.sha256(target.read_bytes()).digest() != hashlib.sha256(node.read_bytes()).digest():
        raise RuntimeError('Node 路径已存在其他文件')
    if not target.exists():
        shutil.copyfile(node, target)
        os.chmod(target, 0o755)
    xray = LIB / 'xray'
    old_xray = Path('/usr/local/lib/xray-gateway/xray').resolve(strict=True)
    if xray.exists() and xray.resolve() != old_xray:
        raise RuntimeError('新版 Xray 路径指向其他程序')
    if not xray.exists():
        xray.symlink_to(old_xray)
    target = Path('/opt/xcli/releases') / ('rewrite-' + revision[:12])
    if target.exists():
        if not (target / 'COMMIT').is_file() or (target / 'COMMIT').read_text().strip() != revision:
            raise RuntimeError('新版发布目录已存在其他内容')
    else:
        target.mkdir(mode=0o755)
        shutil.copytree(release / 'web', target / 'web')
        atomic(target / 'COMMIT', revision + '\n', 0o644)
    return target


def upgrade(release, node, revision):
    settings, probe_uuid, firewall = preflight()
    if (release / 'BUILD_STATUS').read_text().strip() != 'experimental':
        raise RuntimeError('需要使用当前源码构建的新版程序')
    panel, probe = pwd.getpwnam('xgateway'), pwd.getpwnam('xgprobe')
    probe_gid = grp.getgrnam('xgmonitor').gr_gid
    baseline = user_rows(STATE / 'gateway.sqlite')
    expected_subscriptions = subscriptions(baseline)
    old_link = os.readlink(CURRENT)
    old_core = command('systemctl', 'show', 'xray-gateway-core', '-p', 'MainPID', '--value', capture=True).stdout.strip()
    backup_parent = BACKUPS
    backup_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(backup_parent, 0o700)
    backup = Path(tempfile.mkdtemp(prefix='upgrade-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-', dir=backup_parent))
    shutil.copytree(CONFIG, backup / 'config')
    shutil.copy2(FIREWALL, backup / 'firewall.sh')
    atomic(backup / 'old-current.txt', old_link + '\n')
    snapshot_database(backup / 'before-stop.sqlite')
    print('已备份现有配置和用户数据库。', flush=True)
    stopped = False
    request_moved = False
    rule_added = False
    changed_firewall = False
    swapped = False
    created = []
    try:
        target = install_artifacts(release, node, revision)
        stopped = True
        command('systemctl', 'stop', *OLD)
        snapshot_database(backup / 'gateway.sqlite')
        if user_identity(user_rows(backup / 'gateway.sqlite')) != user_identity(baseline):
            raise RuntimeError('升级期间用户信息发生变化，请重试')
        request_moved = checked_old_request(backup)
        IMPORT.mkdir(mode=0o755)
        created.append(IMPORT)
        for name in ('state', 'journal', 'report'):
            (IMPORT / name).mkdir(mode=0o700)
        os.chown(IMPORT / 'report', 0, panel.pw_gid)
        os.chmod(IMPORT / 'report', 0o750)
        atomic(CONFIG / 'rust-panel.env', f'XCLI_ORIGIN={settings["origin"]}\nXCLI_PROBE_UUID={probe_uuid}\n', 0o640, 0, panel.pw_gid)
        created.append(CONFIG / 'rust-panel.env')
        atomic(CONFIG / 'rust-import.json', json.dumps(worker_config(panel, probe, probe_gid)), 0o600)
        created.append(CONFIG / 'rust-import.json')
        for name, contents in units(settings['origin'], panel.pw_gid).items():
            path = SYSTEMD / (name + '.service')
            atomic(path, contents, 0o644)
            created.append(path)
        command('systemd-analyze', 'verify', *(str(SYSTEMD / (name + '.service')) for name in NEW))
        atomic(FIREWALL, firewall.replace(OLD_PORTS, NEW_PORTS), 0o755)
        changed_firewall = True
        rule = ('iptables', '-w', '-d', '127.0.0.1/32', '-p', 'tcp', '--dport', '18080', '-j', 'RETURN')
        if command('iptables', '-w', '-C', 'XG_OUT', *rule[2:], check=False).returncode != 0:
            command('iptables', '-w', '-I', 'XG_OUT', '1', *rule[2:])
            rule_added = True
        swap_current(str(target))
        swapped = True
        command('systemctl', 'disable', *OLD)
        command('systemctl', 'daemon-reload')
        for name in NEW:
            command('systemctl', 'enable', '--now', name)
        wait_http('/healthz')
        if fetch(8080, '/')[0] != 200 or subscriptions(baseline) != expected_subscriptions:
            raise RuntimeError('新版面板或原订阅校验未通过')
        after = user_rows(STATE / 'gateway.sqlite')
        if user_identity(after) != user_identity(baseline):
            raise RuntimeError('升级后用户信息不一致')
        previous = {row[0]: row for row in baseline}
        if any(row[7] < previous[row[0]][7] or row[8] < previous[row[0]][8] for row in after):
            raise RuntimeError('升级后累计用量异常')
        for name in NEW:
            command('systemctl', 'is-active', '--quiet', name)
        core = command('systemctl', 'show', 'xray-gateway-core', '-p', 'MainPID', '--value', capture=True).stdout.strip()
        print('升级完成：用户、订阅地址和原有节点配置已保留。', flush=True)
        print('Xray 核心' + ('未重启。' if core == old_core else '已重启，请检查现有连接。'), flush=True)
        print('原配置和升级前数据库：' + str(backup), flush=True)
        print('配置：/etc/xray-gateway；用户数据：/var/lib/xray-gateway/gateway.sqlite', flush=True)
    except BaseException:
        if stopped:
            print('升级未完成，正在恢复旧服务。', flush=True)
            command('systemctl', 'disable', '--now', *reversed(NEW), check=False)
        if swapped:
            swap_current(old_link)
        if rule_added:
            command('iptables', '-w', '-D', 'XG_OUT', *rule[2:], check=False)
        if changed_firewall:
            shutil.copy2(backup / 'firewall.sh', FIREWALL)
        for path in reversed(created):
            if path.is_dir():
                shutil.move(path, backup / 'failed-import-state')
            else:
                path.unlink(missing_ok=True)
        if request_moved and not (STATE / 'proxy-import/request.xgb').exists():
            shutil.move(backup / 'previous-import-request.xgb', STATE / 'proxy-import/request.xgb')
        command('systemctl', 'daemon-reload', check=False)
        if stopped:
            command('systemctl', 'enable', '--now', *reversed(OLD), check=False)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--release-dir', type=Path)
    parser.add_argument('--node-bin', type=Path)
    parser.add_argument('--revision')
    args = parser.parse_args()
    if args.check:
        preflight()
        print('检查通过：检测到可升级的旧面板；用户数据和原订阅地址将保留。')
        return
    if not args.release_dir or not args.node_bin or not re.fullmatch(r'[0-9a-f]{40}', args.revision or ''):
        raise RuntimeError('缺少构建结果或源码版本，请运行项目根目录的 upgrade.sh')
    upgrade(args.release_dir.resolve(strict=True), args.node_bin.resolve(strict=True), args.revision)


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print('升级停止：' + str(error), file=sys.stderr, flush=True)
        raise SystemExit(1)
