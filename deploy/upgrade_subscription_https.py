#!/usr/bin/env python3
"""Safely migrate an existing panel to the shared, self-HTTPS-only rule."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
import uuid

from subscription_https import all_users_candidate, all_users_firewall_candidate

CORE = Path('/etc/xray-gateway/core.json')
SETTINGS = Path('/etc/xray-gateway/settings.json')
FIREWALL = Path('/usr/local/lib/xcli/host/firewall.sh')
XRAY = '/usr/local/lib/xray-gateway/xray'
LOCK = '/run/lock/xcli-update.lock'
BACKUPS = Path('/var/backups/xcli/bootstrap')


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic_write(path, data, metadata):
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data); out.flush(); os.fsync(out.fileno())
        os.chmod(name, stat.S_IMODE(metadata.st_mode)); os.chown(name, metadata.st_uid, metadata.st_gid)
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(name): os.unlink(name)


def firewall_position(address, port):
    """Check the live chain without flushing it or accepting ambiguous rules."""
    lines = [line for line in run('iptables', '-w', '-S', 'XG_OUT').splitlines() if line.startswith('-A XG_OUT ')]
    local = [i for i, line in enumerate(lines) if '--dst-type LOCAL' in line and '-j REJECT' in line]
    if len(local) != 1:
        raise ValueError('无法确认现有本机地址防护的位置')
    command = ['-d', address + '/32', '-p', 'tcp', '--dport', str(port), '-j', 'RETURN']
    found = [i for i, line in enumerate(lines) if '-d ' + address + '/32' in line and
             '-p tcp' in line and '--dport ' + str(port) + ' ' in line and '-j RETURN' in line]
    if len(found) > 1 or (found and found[0] >= local[0]):
        raise ValueError('现有面板出口防火墙规则位置不安全或存在重复')
    if found:
        # Text alone is not enough: confirm that iptables recognizes the exact rule.
        run('iptables', '-w', '-C', 'XG_OUT', *command)
    return command, None if found else local[0] + 1


def main(apply=False):
    if os.geteuid() != 0: raise ValueError('请使用 sudo 运行')
    with open(LOCK, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for path in (CORE, SETTINGS, FIREWALL):
            if path.is_symlink() or not path.is_file(): raise ValueError('现有配置文件无效')
        old_core, old_firewall = CORE.read_bytes(), FIREWALL.read_bytes()
        metadata = {CORE: CORE.stat(), FIREWALL: FIREWALL.stat()}
        settings = json.loads(SETTINGS.read_bytes()); address = settings['public_ip']; port = settings.get('public_port', 443)
        new_core = (json.dumps(all_users_candidate(json.loads(old_core), address, port), indent=2) + '\n').encode()
        new_firewall = all_users_firewall_candidate(old_firewall.decode(), address, port).encode()
        rule, position = firewall_position(address, port)
        run('systemctl', 'is-active', '--quiet', 'xray-gateway-core')
        with tempfile.TemporaryDirectory(prefix='xcli-self-https-') as temp:
            candidate = Path(temp) / 'core.json'; candidate.write_bytes(new_core); candidate.chmod(0o600)
            run(XRAY, 'run', '-test', '-config', str(candidate))
            shell = Path(temp) / 'firewall.sh'; shell.write_bytes(new_firewall); run('bash', '-n', str(shell))
        # Formatting differences alone do not justify a core restart.
        core_changed = json.loads(old_core) != json.loads(new_core)
        changed = core_changed or old_firewall != new_firewall or position is not None
        if not apply or not changed:
            return {'status': 'ready' if changed else 'unchanged', 'apply': apply,
                    'scope': 'authenticated users, server public IPv4, configured TCP port',
                    'core_restart_required': core_changed}
        if CORE.read_bytes() != old_core or FIREWALL.read_bytes() != old_firewall:
            raise ValueError('原配置已变化，请重新检查')
        backup = BACKUPS / (time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8])
        backup.mkdir(parents=True, mode=0o700)
        for name, data in (('core.json', old_core), ('firewall.sh', old_firewall)):
            path = backup / name; path.write_bytes(data); path.chmod(0o600)
        journal = backup / 'transaction.json'
        def record(phase):
            journal.write_text(json.dumps({'phase': phase, 'core_sha256': digest(old_core),
                                           'firewall_sha256': digest(old_firewall)}) + '\n'); journal.chmod(0o600)
        record('prepared')
        inserted = False; touched = False
        try:
            if position is not None:
                run('iptables', '-w', '-I', 'XG_OUT', str(position), *rule); inserted = True
            touched = True
            if old_firewall != new_firewall: atomic_write(FIREWALL, new_firewall, metadata[FIREWALL])
            if core_changed:
                atomic_write(CORE, new_core, metadata[CORE]); record('restarting')
                run('systemctl', 'restart', 'xray-gateway-core')
            run('systemctl', 'is-active', '--quiet', 'xray-gateway-core')
            run('iptables', '-w', '-C', 'XG_OUT', *rule)
            record('applied')
            return {'status': 'applied', 'backup': str(backup), 'core_restarted': core_changed}
        except BaseException:
            errors = []
            if touched:
                for path, data in ((CORE, old_core), (FIREWALL, old_firewall)):
                    try: atomic_write(path, data, metadata[path])
                    except BaseException: errors.append('restore-config')
                if core_changed:
                    try: run('systemctl', 'restart', 'xray-gateway-core'); run('systemctl', 'is-active', '--quiet', 'xray-gateway-core')
                    except BaseException: errors.append('restart-core')
            if inserted:
                try: run('iptables', '-w', '-D', 'XG_OUT', *rule)
                except BaseException: errors.append('restore-firewall')
            record('rollback-incomplete' if errors else 'rolled-back')
            raise RuntimeError('更新失败，' + ('回退未完成；备份：' + str(backup) if errors else '已恢复原配置')) from None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='应用并在必要时重启 VPN 核心')
    args = parser.parse_args()
    try: print(json.dumps(main(args.apply), ensure_ascii=False, indent=2))
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print('面板访问迁移停止：' + str(error), file=__import__('sys').stderr)
        raise SystemExit(1)
