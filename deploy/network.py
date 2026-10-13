#!/usr/bin/env python3
"""Opt-in kernel TCP/UDP settings with a saved before-state and explicit restore."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

STATE = Path('/etc/xray-gateway/network-before.json')
PROFILE = Path('/etc/sysctl.d/91-xray-gateway-network.conf')
MODULES = Path('/etc/modules-load.d/xray-gateway-network.conf')
SERVICE = Path('/etc/systemd/system/xray-gateway-network.service')
KEYS = ('net.ipv4.tcp_congestion_control', 'net.core.default_qdisc',
        'net.core.rmem_max', 'net.core.wmem_max')
MIB16 = 16 * 1024 * 1024


def run(*args, check=True):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, timeout=20)
    if check and result.returncode:
        raise RuntimeError('命令失败：' + ' '.join(map(str, args)) + '\n' + result.stderr.strip())
    return result.stdout.strip()


def interface_name(value=None):
    if not value:
        routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'default'))
        devices = {route['dev'] for route in routes if 'dev' in route}
        if len(devices) != 1:
            raise ValueError('默认出口不唯一，请使用 --interface 指定网卡')
        value = devices.pop()
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', value) or value == 'lo':
        raise ValueError('请选择有效的外网网卡')
    run('ip', 'link', 'show', 'dev', value)
    return value


def status(interface=None):
    interface = interface_name(interface)
    return {'interface': interface, 'sysctl': {key: run('sysctl', '-n', key) for key in KEYS},
            'qdisc': json.loads(run('tc', '-j', 'qdisc', 'show', 'dev', interface)),
            'profile_active': STATE.exists()}


def restore_queue(qdisc):
    """Only reconstruct simple classless queues whose options we can preserve."""
    kind, options = qdisc.get('kind'), qdisc.get('options', {})
    if kind == 'pfifo_fast':
        expected = [1, 2, 2, 2, 1, 2, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]
        if options.get('bands', 3) != 3 or options.get('priomap', expected) != expected or options.get('multiqueue', False):
            return None
        return ['pfifo_fast']
    if kind == 'fq_codel':
        accepted = {'limit', 'flows', 'quantum', 'target', 'interval', 'memory_limit', 'ecn', 'ce_threshold', 'drop_batch'}
        if set(options) - accepted:
            return None
        result = ['fq_codel']
        for key, value in options.items():
            if key == 'ecn':
                result.append('ecn' if value else 'noecn')
            elif isinstance(value, (int, float)) and value >= 0:
                result.extend([key, str(value) + ('us' if key in ('target', 'interval', 'ce_threshold') else '')])
            else:
                return None
        return result
    return None


def plan(before):
    values = dict(before['sysctl'])
    values['net.ipv4.tcp_congestion_control'] = 'bbr'
    values['net.core.default_qdisc'] = 'fq'
    for key in ('net.core.rmem_max', 'net.core.wmem_max'):
        values[key] = str(max(int(values[key]), MIB16))
    queues = before['qdisc']
    restore = restore_queue(queues[0]) if len(queues) == 1 and queues[0].get('root') else None
    return {'values': values, 'queue_restore': restore,
            'queue_note': '设置实际网卡队列为 fq' if restore else
            '保留当前队列：已是 fq、虚拟 noqueue 或包含自定义结构；仅设置新建队列默认值'}


def private_json(path, value):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


def profile_files(value):
    program = str(Path(__file__).resolve())
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', program):
        raise ValueError('请将工具放在不含空格或特殊字符的绝对路径')
    return {str(PROFILE): '# xcli optional network profile; restore with network.py restore\n' +
                ''.join(key + ' = ' + item + '\n' for key, item in value['values'].items()),
            str(MODULES): 'tcp_bbr\nsch_fq\n',
            str(SERVICE): '[Unit]\nDescription=xcli optional network profile\n'
                'After=network-online.target\nWants=network-online.target\n'
                '[Service]\nType=oneshot\nRemainAfterExit=yes\n'
                'ExecStart=/usr/bin/python3 ' + program + ' reapply\n'
                '[Install]\nWantedBy=multi-user.target\n'}


def apply_values(saved):
    if 'bbr' not in run('sysctl', '-n', 'net.ipv4.tcp_available_congestion_control').split():
        run('modprobe', 'tcp_bbr')
    run('modprobe', 'sch_fq', check=False)
    for key, value in saved['plan']['values'].items():
        run('sysctl', '-w', key + '=' + value)
    if saved['plan']['queue_restore']:
        queues = json.loads(run('tc', '-j', 'qdisc', 'show', 'dev', saved['before']['interface']))
        if len(queues) != 1 or not queues[0].get('root'):
            raise ValueError('实际网卡队列结构已改变，拒绝覆盖')
        if queues[0]['kind'] != 'fq':
            if restore_queue(queues[0]) is None:
                raise ValueError('实际网卡队列不再是可恢复的简单队列，拒绝覆盖')
            run('tc', 'qdisc', 'replace', 'dev', saved['before']['interface'], 'root', 'fq')


def restore(cancel_timer=True):
    if not STATE.is_file() or STATE.is_symlink():
        raise ValueError('没有可恢复的 xcli 网络配置快照')
    saved = json.loads(STATE.read_text())
    for name, content in saved['files'].items():
        path = Path(name)
        if path.is_symlink() or (path.exists() and path.read_text() != content):
            raise ValueError('托管文件已被外部修改，拒绝覆盖：' + name)
    if saved['plan']['queue_restore']:
        queues = json.loads(run('tc', '-j', 'qdisc', 'show', 'dev', saved['before']['interface']))
        if len(queues) != 1 or not queues[0].get('root') or (
                queues[0]['kind'] != 'fq' and restore_queue(queues[0]) != saved['plan']['queue_restore']):
            raise ValueError('实际队列结构已被外部修改，拒绝覆盖；原值快照保留')
    if cancel_timer:
        run('systemctl', 'stop', 'xcli-network-rollback.timer', check=False)
    run('systemctl', 'disable', '--now', SERVICE.name, check=False)
    for key, value in saved['before']['sysctl'].items():
        run('sysctl', '-w', key + '=' + value)
    if saved['plan']['queue_restore']:
        run('tc', 'qdisc', 'replace', 'dev', saved['before']['interface'], 'root', *saved['plan']['queue_restore'])
    for name in saved['files']:
        Path(name).unlink(missing_ok=True)
    run('systemctl', 'daemon-reload')
    restored = STATE.with_name('network-restored-' + str(time.time_ns()) + '.json')
    STATE.rename(restored)
    print('已恢复原来的 TCP、UDP 缓冲和队列设置；快照：' + str(restored))


def apply(interface=None, rollback_after=0):
    if any(path.exists() or path.is_symlink() for path in (STATE, PROFILE, MODULES, SERVICE)):
        raise ValueError('已有 xcli 网络快照或配置；请先检查 status，需撤销时执行 restore')
    before = status(interface)
    value = plan(before)
    saved = {'schema': 1, 'created': int(time.time()), 'before': before, 'plan': value, 'files': profile_files(value)}
    STATE.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    private_json(STATE, saved)
    try:
        if rollback_after:
            run('systemd-run', '--collect', '--unit=xcli-network-rollback', '--on-active=' + str(rollback_after) + 's',
                '/usr/bin/python3', Path(__file__).resolve(), 'restore', '--from-timer')
        apply_values(saved)
        for name, content in saved['files'].items():
            with open(name, 'x') as stream:
                stream.write(content)
            os.chmod(name, 0o644)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', '--now', SERVICE.name)
    except Exception:
        restore()
        raise
    print(value['queue_note'])
    print(json.dumps(status(before['interface']), ensure_ascii=False, indent=2))
    if rollback_after:
        print(f'{rollback_after} 秒后自动恢复；确认 SSH 和节点正常后执行 network.py confirm 保留设置。')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['status', 'apply', 'reapply', 'restore', 'confirm'])
    parser.add_argument('--interface')
    parser.add_argument('--rollback-after', type=int, default=0)
    parser.add_argument('--from-timer', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.rollback_after and not 30 <= args.rollback_after <= 600:
        parser.error('--rollback-after must be 30..600 seconds')
    if args.action == 'status':
        print(json.dumps(status(args.interface), ensure_ascii=False, indent=2))
        return
    if os.geteuid() != 0:
        parser.error('修改网络配置需要 root 权限')
    if args.action == 'apply':
        apply(args.interface, args.rollback_after)
    elif args.action == 'restore':
        restore(not args.from_timer)
    elif args.action == 'reapply':
        apply_values(json.loads(STATE.read_text()))
    else:
        if not STATE.is_file():
            raise ValueError('没有正在生效的网络配置快照')
        run('systemctl', 'stop', 'xcli-network-rollback.timer')
        print('已取消自动恢复，保留网络配置。仍可随时执行 network.py restore。')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print('网络配置未完成：' + str(error), file=sys.stderr)
        raise SystemExit(1)
