#!/usr/bin/env python3
"""Upgrade a provisioned 1.2 gateway, retaining identities and a standalone rollback."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile

BASE = Path('/usr/local/lib/xray-gateway')
CONFIG = Path('/etc/xray-gateway')
MONITOR = Path('/etc/xcli-monitor/monitor.json')
APP = Path('/opt/xray-gateway')
PANEL_DROP = Path('/etc/systemd/system/xray-gateway-panel.service.d/50-hysteria.conf')
CORE_DROP = Path('/etc/systemd/system/xray-gateway-core.service.d/20-hysteria.conf')
HOOK = Path('/etc/letsencrypt/renewal-hooks/deploy/xcli-hysteria')
UDP_RULE = ['XG_IN', '-p', 'udp', '--dport', '443', '-j', 'ACCEPT']
SERVICES = ['xray-gateway-monitor', 'xray-gateway-panel', 'xray-gateway-core']
LOG = None


def run(*command, check=True, timeout=60):
    result = subprocess.run(list(map(str, command)), capture_output=True, timeout=timeout)
    if LOG:
        with LOG.open('ab') as stream:
            stream.write(('\n$ ' + ' '.join(map(str, command)) + '\n').encode())
            stream.write(result.stdout + result.stderr)
    if check and result.returncode:
        # Core preflight output and credential-bearing configuration stay private.
        raise RuntimeError(f'{command[0]} failed with exit code {result.returncode}')
    return result


def atomic(path, content, mode=None, uid=None, gid=None):
    path = Path(path)
    old = path.stat() if path.exists() else None
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.xcli-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content.encode() if isinstance(content, str) else content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode if mode is not None else (old.st_mode & 0o777 if old else 0o644))
            os.fchown(stream.fileno(), uid if uid is not None else (old.st_uid if old else 0),
                      gid if gid is not None else (old.st_gid if old else 0))
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def select_panel(target):
    link = BASE / ('panel-next-' + str(os.getpid()))
    link.symlink_to(target)
    os.replace(link, BASE / 'panel-current')


def save_files(backup, paths):
    records = []
    for index, path in enumerate(paths):
        record = {'path': str(path), 'exists': path.exists() or path.is_symlink()}
        if record['exists']:
            stat = path.lstat()
            record.update(mode=stat.st_mode & 0o777, uid=stat.st_uid, gid=stat.st_gid)
            if path.is_symlink():
                record['link'] = os.readlink(path)
            else:
                if not path.is_file():
                    raise ValueError('Expected a regular file: ' + str(path))
                record['copy'] = 'file-' + str(index)
                shutil.copyfile(path, backup / record['copy'])
                os.chmod(backup / record['copy'], 0o600)
        records.append(record)
    return records


def wait_panel():
    for _ in range(30):
        if run('curl', '-q', '--noproxy', '*', '-fsS', '--max-time', '2',
               'http://127.0.0.1:8080/healthz', check=False).returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError('Panel health check timed out')


def panel_preflight(candidate):
    return json.loads(run('runuser', '-u', 'xgateway', '-g', 'xgateway', '-G', 'xgmonitor', '--',
        candidate, '--secret-key', CONFIG / 'security.key', '--monitor-config', MONITOR,
        '--preflight').stdout)


def verify_accounts(candidate):
    for _ in range(20):
        value = panel_preflight(candidate)
        if (value.get('database_integrity') == 'ok' and value.get('pending_additions') == 0
                and value.get('pending_revocations') == 0):
            return
        time.sleep(1)
    raise RuntimeError('Core account synchronization did not finish')


def rollback(backup):
    saved = json.loads((backup / 'manifest.json').read_text())
    run('systemctl', 'stop', *SERVICES, timeout=90)
    for item in saved['files']:
        path = Path(item['path'])
        if not item['exists']:
            path.unlink(missing_ok=True)
        elif 'link' in item:
            temporary = path.with_name(path.name + '.rollback-' + str(os.getpid()))
            temporary.symlink_to(item['link'])
            os.lchown(temporary, item['uid'], item['gid'])
            os.replace(temporary, path)
        else:
            atomic(path, (backup / item['copy']).read_bytes(), item['mode'], item['uid'], item['gid'])
    if not saved['udp_rule_existed'] and run('iptables', '-w', '-C', *UDP_RULE, check=False).returncode == 0:
        run('iptables', '-w', '-D', *UDP_RULE)
    for name in saved['new_directories']:
        path = Path(name)
        if path.exists():
            # Preserve any files added by the operator since the upgrade.
            try:
                path.rmdir()
            except OSError:
                pass
    run('systemctl', 'daemon-reload')
    run('systemctl', 'start', *reversed(SERVICES), timeout=90)
    wait_panel()
    verify_accounts(BASE / 'panel-current')
    atomic(backup / 'rolled-back', str(int(time.time())) + '\n', 0o600)
    print('Previous core, panel and configuration restored; current users, MFA and traffic retained.')


def upgrade(args):
    global LOG
    from certificate import install_tls
    from provision import XRAY_ASSETS, XRAY_VERSION, hysteria_inbound
    source, candidate, backup = args.source.resolve(strict=True), args.candidate.resolve(strict=True), args.backup
    if backup.parent != Path('/root') or backup.exists() or backup.is_symlink():
        raise ValueError('Use an unused backup directory directly under /root')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', backup.name):
        raise ValueError('Backup directory name must contain only letters, numbers, hyphens or underscores')
    if not (BASE / 'panel-current').is_symlink():
        raise ValueError('Expected an existing provisioned C++ gateway')
    if b'1.3.0' not in run(candidate, '--version').stdout or b'1.2.0' not in run(BASE / 'panel-current', '--version').stdout:
        raise ValueError('This upgrade requires a 1.2.0 installation and a verified 1.3.0 candidate')
    settings = json.loads((CONFIG / 'settings.json').read_text())
    core = json.loads((CONFIG / 'core.json').read_text())
    monitor = json.loads(MONITOR.read_text())
    if settings.get('hysteria2_port') or any(item.get('tag') == 'hysteria2' for item in core['inbounds']):
        raise ValueError('Hysteria 2 is already configured; refusing to overwrite it')
    for path in (PANEL_DROP, CORE_DROP, HOOK, CONFIG / 'hysteria-tls'):
        if path.exists() or path.is_symlink():
            raise ValueError('Owned destination already exists: ' + str(path))
    for service in (*SERVICES, 'xray-gateway-firewall', 'nginx'):
        run('systemctl', 'is-active', '--quiet', service)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(('0.0.0.0', 443))
    firewall = APP / 'deploy/firewall.sh'
    firewall_text = firewall.read_text()
    anchor = '    iptables -w -A XG_IN -p tcp -m multiport --dports 80,443 -j ACCEPT\n'
    if firewall_text.count(anchor) != 1:
        raise ValueError('Unrecognized firewall layout; preserve it and review manually')
    if bool(args.certificate) != bool(args.private_key):
        raise ValueError('--certificate and --private-key must be provided together')
    live = Path('/etc/letsencrypt/live') / settings['domain']
    certificate = args.certificate or live / 'fullchain.pem'
    private_key = args.private_key or live / 'privkey.pem'
    if not certificate.is_file() or not private_key.is_file():
        raise ValueError('Provide the existing site certificate and private key')
    arch = {'arm64': 'aarch64'}.get(platform.machine(), platform.machine())
    asset, digest = XRAY_ASSETS[arch]
    verify_accounts(BASE / 'panel-current')
    backup.mkdir(mode=0o700)
    LOG = backup / 'upgrade.log'
    atomic(LOG, b'', 0o600)
    for name in ('upgrade-hysteria.py', 'certificate.py', 'provision.py'):
        shutil.copyfile(source / 'deploy' / name, backup / name)
        os.chmod(backup / name, 0o600)
    shutil.copyfile(source / 'cpp/tests/migration_state.py', backup / 'migration_state.py')
    os.chmod(backup / 'migration_state.py', 0o600)
    run(sys.executable, backup / 'migration_state.py', 'save', backup / 'state.json')
    run(BASE / 'panel-current', '--backup', backup / 'gateway.sqlite')
    archive = backup / asset
    print('Verifying the pinned official core and preserving the previous installation…', flush=True)
    if args.xray_archive:
        shutil.copyfile(args.xray_archive, archive)
    else:
        run('curl', '-q', '--proto', '=https', '--tlsv1.2', '-fsSL', '--retry', '3',
            '--connect-timeout', '10', '--max-time', '180', '-o', archive,
            f'https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/{asset}', timeout=600)
    os.chmod(archive, 0o600)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise ValueError('Official Xray archive SHA-256 mismatch')
    with zipfile.ZipFile(archive) as zipped:
        atomic(backup / 'xray-new', zipped.read('xray'), 0o700)
    install_tls(settings['domain'], certificate, private_key, backup / 'certificate-check')
    paths = [CONFIG / 'settings.json', CONFIG / 'core.json', CONFIG / 'installation.json', MONITOR,
        BASE / 'xray', BASE / 'panel-current', APP / 'scripts/probe.py', APP / 'deploy/certificate.py',
        APP / 'deploy/network.py', firewall, PANEL_DROP, CORE_DROP, HOOK,
        CONFIG / 'hysteria-tls/fullchain.pem', CONFIG / 'hysteria-tls/privkey.pem']
    saved = {'files': save_files(backup, paths),
        'udp_rule_existed': run('iptables', '-w', '-C', *UDP_RULE, check=False).returncode == 0,
        'new_directories': [str(path) for path in (CONFIG / 'hysteria-tls', CORE_DROP.parent, HOOK.parent) if not path.exists()]}
    atomic(backup / 'manifest.json', json.dumps(saved, indent=2), 0o600)
    atomic(backup / 'settings-before.json', (CONFIG / 'settings.json').read_bytes(), 0o600)
    atomic(backup / 'rollback.sh', '#!/bin/sh\nset -eu\nbackup=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n'
        'exec /usr/bin/python3 "$backup/upgrade-hysteria.py" rollback "$backup"\n', 0o700)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    release = BASE / 'releases' / ('cpp-1.3.0-' + stamp)
    release.mkdir(mode=0o755)
    atomic(release / 'xray-gateway-panel', candidate.read_bytes(), 0o755)
    shutil.copytree(source / 'static', release / 'static')
    for path in (release / 'static').rglob('*'):
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
    try:
        print('Switching core and controller; existing client connections will reconnect once.', flush=True)
        run('systemctl', 'stop', *SERVICES, timeout=90)
        settings.update(hysteria2_port=443, xray_version=XRAY_VERSION)
        core['inbounds'].append(hysteria_inbound())
        monitor['hysteria2_port'] = 443
        for path, value in ((CONFIG / 'settings.json', settings), (CONFIG / 'core.json', core), (MONITOR, monitor)):
            atomic(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n')
        if (CONFIG / 'installation.json').is_file():
            metadata = json.loads((CONFIG / 'installation.json').read_text())
            metadata.update(version='1.3.0', xray=XRAY_VERSION, upgraded=int(time.time()))
            atomic(CONFIG / 'installation.json', json.dumps(metadata, indent=2) + '\n')
        install_tls(settings['domain'], certificate, private_key, CONFIG / 'hysteria-tls', 'xgateway')
        atomic(BASE / 'xray', (backup / 'xray-new').read_bytes(), 0o755, 0, 0)
        for name in ('certificate.py', 'network.py'):
            atomic(APP / 'deploy' / name, (source / 'deploy' / name).read_bytes(), 0o644, 0, 0)
        atomic(APP / 'scripts/probe.py', (source / 'scripts/probe.py').read_bytes(), 0o644, 0, 0)
        if not args.certificate:
            atomic(HOOK, '#!/bin/sh\nset -eu\nexec /usr/bin/python3 /opt/xray-gateway/deploy/certificate.py\n', 0o755)
        atomic(PANEL_DROP, '[Service]\nEnvironment=XG_STATIC=' + str(release / 'static') + '\n')
        atomic(CORE_DROP, '[Service]\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n')
        atomic(firewall, firewall_text.replace(anchor, anchor + '    iptables -w -A XG_IN -p udp --dport 443 -j ACCEPT\n'))
        if not saved['udp_rule_existed']:
            run('iptables', '-w', '-A', *UDP_RULE)
        select_panel(release / 'xray-gateway-panel')
        run('runuser', '-u', 'xgateway', '--', BASE / 'xray', 'run', '-test', '-config', CONFIG / 'core.json')
        run('systemctl', 'daemon-reload')
        run('systemctl', 'start', *reversed(SERVICES), timeout=90)
        wait_panel()
        verify_accounts(BASE / 'panel-current')
        run(sys.executable, backup / 'migration_state.py', 'verify', backup / 'state.json',
            '--settings', backup / 'settings-before.json')
        expected = json.loads((backup / 'settings-before.json').read_text())
        expected.update(hysteria2_port=443, xray_version=XRAY_VERSION)
        assert json.loads((CONFIG / 'settings.json').read_text()) == expected
    except BaseException:
        print('Upgrade failed; restoring the previous compatible services.', file=sys.stderr, flush=True)
        rollback(backup)
        raise
    print('Upgrade complete. Identities, subscriptions, sessions, MFA and cumulative traffic preserved.')
    print('Rollback: ' + str(backup / 'rollback.sh'))
    print('Verify server and external probes; the cloud security group must allow UDP 443.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    install = commands.add_parser('upgrade')
    install.add_argument('--source', type=Path, default=Path(__file__).resolve().parent.parent)
    install.add_argument('--candidate', type=Path, required=True)
    install.add_argument('--backup', type=Path, required=True)
    install.add_argument('--xray-archive', type=Path)
    install.add_argument('--certificate', type=Path)
    install.add_argument('--private-key', type=Path)
    revert = commands.add_parser('rollback')
    revert.add_argument('backup', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.system() != 'Linux':
        parser.error('Run as root on the provisioned Linux host')
    if args.action == 'upgrade':
        upgrade(args)
    else:
        rollback(args.backup.resolve(strict=True))


if __name__ == '__main__':
    main()
