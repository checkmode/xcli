#!/usr/bin/env python3
"""Add an opt-in, separate Hysteria 2 Brutal listener without restarting Xray."""
import argparse
import copy
import datetime
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time


SPEC = importlib.util.spec_from_file_location('xcli_upgrade_rust', Path(__file__).with_name('upgrade-rust.py'))
upgrade = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(upgrade)
TAG = 'hysteria2-brutal'
KEY = 'hysteria2_brutal_port'
CHECK_TEMP_ROOT = Path('/var/tmp')


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()


def build_candidates(settings_bytes, core_bytes, monitor_bytes, firewall_bytes, port):
    """Return new files and one API inbound, without modifying the inputs."""
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError('Brutal 入口端口必须为 1024..65535')
    settings = json.loads(settings_bytes)
    core = json.loads(core_bytes)
    monitor = json.loads(monitor_bytes)
    if not isinstance(settings, dict) or not isinstance(core, dict) or not isinstance(monitor, dict):
        raise ValueError('现有配置格式不正确')
    old_port = settings.get('hysteria2_port')
    if type(old_port) is not int or not 1 <= old_port <= 65535 or port == old_port:
        raise ValueError('现有 Hysteria 入口无效或与新端口冲突')
    entries = core.get('inbounds')
    if not isinstance(entries, list) or any(not isinstance(item, dict) for item in entries):
        raise ValueError('现有 Xray 入站配置无效')
    original = [item for item in entries if item.get('tag') == 'hysteria2']
    existing = [item for item in entries if item.get('tag') == TAG]
    rate = settings.get('hysteria2_brutal_mbps', 40)
    if type(rate) is not int or not 1 <= rate <= 1000:
        raise ValueError('Brutal 速率必须为 1..1000 Mbps')
    anchor = f'    iptables -w -A XG_IN -p udp --dport {old_port} -j ACCEPT\n'.encode()
    rule = f'    iptables -w -A XG_IN -p udp --dport {port} -j ACCEPT\n'.encode()
    if settings.get(KEY) == port and len(existing) == 1:
        params = existing[0].get('streamSettings', {}).get('finalmask', {}).get('quicParams', {})
        if (existing[0].get('port') == port and existing[0].get('protocol') == 'hysteria'
                and params.get('congestion') == 'force-brutal'
                and str(params.get('brutalUp', '')).strip().lower() == f'{rate} mbps'
                and monitor.get(KEY) == port and firewall_bytes.count(rule) == 1):
            return None
        raise ValueError('已有 Brutal 配置与预期不一致，请先检查')
    if settings.get(KEY, 0) != 0 or monitor.get(KEY, 0) != 0 or existing:
        raise ValueError('发现已有 Brutal 配置，未覆盖')
    if len(original) != 1 or original[0].get('protocol') != 'hysteria' or original[0].get('port') != old_port:
        raise ValueError('未找到唯一的原 Hysteria 入口')
    if any(item.get('port') == port for item in entries):
        raise ValueError('新端口与现有 Xray 入站冲突')
    old = original[0]
    inbound_settings = old.get('settings')
    stream = old.get('streamSettings')
    if (not isinstance(inbound_settings, dict) or inbound_settings.get('version') != 2
            or inbound_settings.get('clients', []) != [] or inbound_settings.get('users', []) != []
            or not isinstance(stream, dict) or stream.get('network') != 'hysteria'
            or stream.get('security') != 'tls'):
        raise ValueError('原 Hysteria 入口包含不支持自动复制的配置')
    finalmask = stream.get('finalmask', {})
    if not isinstance(finalmask, dict) or finalmask.get('udp'):
        raise ValueError('原 Hysteria 入口使用了需要人工迁移的 UDP 混淆')
    params = finalmask.get('quicParams', {})
    if not isinstance(params, dict) or params.get('congestion') != 'bbr':
        raise ValueError('原 Hysteria 入口不是预期的 BBR 配置')
    if monitor.get('hysteria2_port') != old_port:
        raise ValueError('现有 Hysteria 监控配置与入口不一致')
    if firewall_bytes.count(anchor) != 1 or rule in firewall_bytes:
        raise ValueError('防火墙模板需要人工检查，未修改')
    inbound = copy.deepcopy(old)
    inbound['tag'] = TAG
    inbound['port'] = port
    options = inbound['streamSettings'].setdefault('finalmask', {}).setdefault('quicParams', {})
    options['congestion'] = 'force-brutal'
    options['brutalUp'] = f'{rate} mbps'
    options.pop('bbrProfile', None)
    core['inbounds'].append(inbound)
    settings[KEY] = port
    monitor[KEY] = port
    return {'settings': json_bytes(settings), 'core': json_bytes(core), 'monitor': json_bytes(monitor),
            'firewall': firewall_bytes.replace(anchor, anchor + rule), 'inbound': inbound}


def regular_bytes(path):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise ValueError('配置路径不是普通文件：' + str(path))
    return path.read_bytes(), (stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)


def replace_preserving(path, data, metadata):
    path = Path(path)
    mode, uid, gid = metadata
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            os.fchmod(output.fileno(), mode)
            os.fchown(output.fileno(), uid, gid)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def unbound(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        try:
            listener.bind(('0.0.0.0', port))
            return True
        except OSError:
            return False


def value_after(args, name):
    if args.count(name) != 1 or args.index(name) + 1 >= len(args):
        raise ValueError('服务配置缺少参数：' + name)
    return args[args.index(name) + 1]


def discover(info):
    if info['role'] != 'panel':
        raise ValueError('该可选入口目前仅支持 Rust 面板服务器')
    panel = upgrade.service_args('xcli-panel')
    core = upgrade.service_args('xray-gateway-core')
    firewall = upgrade.service_args('xray-gateway-firewall')
    monitor = upgrade.service_args('xcli-monitor')
    api = value_after(panel, '--core-api')
    host, separator, raw_port = api.rpartition(':')
    if not separator or not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
        raise ValueError('Xray 管理地址无效')
    try:
        if not ipaddress.ip_address(host.strip('[]')).is_loopback:
            raise ValueError('Xray 管理地址必须为回环地址')
    except ValueError:
        raise ValueError('Xray 管理地址必须为回环地址') from None
    binary = Path(value_after(panel, '--core-binary'))
    if not binary.is_absolute() or not Path(core[0]).is_absolute() or not os.path.samefile(binary, core[0]):
        raise ValueError('面板与 Xray 核心程序不一致')
    paths = {'settings': info['settings'], 'core': upgrade.argument(core, '-config'),
             'monitor': upgrade.argument(monitor, '--config'), 'firewall': Path(firewall[0])}
    if any(not path.is_absolute() for path in paths.values()):
        raise ValueError('配置路径必须为绝对路径')
    return binary, api, paths


class Activation:
    def __init__(self, info, port, binary, api, paths):
        self.info, self.port, self.binary, self.api, self.paths = info, port, binary, api, paths
        self.before = {}
        self.metadata = {}
        for name, path in paths.items():
            self.before[name], self.metadata[name] = regular_bytes(path)
        self.after = build_candidates(self.before['settings'], self.before['core'],
                                      self.before['monitor'], self.before['firewall'], port)
        self.written = []
        self.rule_attempted = False
        self.api_attempted = False
        self.backup = None

    def verify_unchanged(self):
        if any(regular_bytes(path)[0] != self.before[name] for name, path in self.paths.items()):
            raise RuntimeError('配置在准备期间发生变化，未覆盖')

    def check(self):
        if self.after is None:
            if TAG not in self.runtime_tags() or unbound(self.port) or self.rule('-C', check=False).returncode:
                raise RuntimeError('配置已存在，但 Brutal 入口未监听')
            return False
        tags = self.runtime_tags()
        if 'hysteria2' not in tags or TAG in tags:
            raise RuntimeError('运行中的 Xray 入口与配置不一致')
        if not unbound(self.port):
            raise RuntimeError('新 UDP 端口已被占用')
        upgrade.run('iptables', '-w', '-S', 'XG_IN')
        with tempfile.TemporaryDirectory(prefix='xcli-brutal-check-', dir=CHECK_TEMP_ROOT) as folder:
            candidate = Path(folder) / 'core.json'
            candidate.write_bytes(self.after['core'])
            os.chmod(candidate, 0o600)
            try:
                upgrade.run(self.binary, 'run', '-test', '-config', candidate, timeout=30)
            except (subprocess.SubprocessError, OSError):
                raise RuntimeError('新 Xray 配置校验失败，未修改配置') from None
        return True

    def runtime_tags(self):
        try:
            result = upgrade.run(self.binary, 'api', 'lsi', '--server=' + self.api,
                                 '--isOnlyTags=true', timeout=15)
            entries = json.loads(result.stdout)['inbounds']
            if not isinstance(entries, list) or any(not isinstance(item.get('tag'), str) for item in entries):
                raise ValueError('invalid inbound list')
            return {item['tag'] for item in entries}
        except (subprocess.SubprocessError, OSError, ValueError, KeyError, TypeError, AttributeError):
            raise RuntimeError('无法读取运行中的 Xray 入口') from None

    def save_backup(self):
        upgrade.BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(upgrade.BACKUPS, 0o700)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        self.backup = Path(tempfile.mkdtemp(prefix='brutal-enable-' + stamp + '-', dir=upgrade.BACKUPS))
        for name, data in self.before.items():
            target = self.backup / (name + '.before')
            target.write_bytes(data)
            os.chmod(target, 0o600)
        manifest = {name: {'path': str(path), 'mode': self.metadata[name][0],
                           'uid': self.metadata[name][1], 'gid': self.metadata[name][2],
                           'sha256': hashlib.sha256(self.before[name]).hexdigest()}
                    for name, path in self.paths.items()}
        upgrade.atomic_file(self.backup / 'manifest.json', json.dumps(manifest, indent=2))
        return self.backup

    def rule(self, action, check=True):
        return upgrade.run('iptables', '-w', action, 'XG_IN', '-p', 'udp', '--dport', str(self.port), '-j', 'ACCEPT', check=check)

    def apply(self):
        self.verify_unchanged()
        if TAG in self.runtime_tags() or not unbound(self.port):
            raise RuntimeError('新入口标签或端口已被使用')
        current = self.rule('-C', check=False)
        if current.returncode == 1:
            self.rule_attempted = True
            self.rule('-A')
        elif current.returncode != 0:
            raise RuntimeError('无法检查防火墙规则')
        api_file = self.backup / 'add-inbound.json'
        api_file.write_bytes(json_bytes({'inbounds': [self.after['inbound']]}))
        os.chmod(api_file, 0o600)
        self.api_attempted = True
        try:
            upgrade.run(self.binary, 'api', 'adi', '--server=' + self.api, api_file, timeout=15)
        except (subprocess.SubprocessError, OSError):
            raise RuntimeError('动态新增 Xray 入口失败') from None
        if TAG not in self.runtime_tags() or unbound(self.port):
            raise RuntimeError('新 Xray 入口未开始监听')
        for name in ('core', 'firewall', 'monitor', 'settings'):
            self.written.append(name)
            replace_preserving(self.paths[name], self.after[name], self.metadata[name])

    def rollback(self):
        errors = []
        for name in self.written:
            try:
                current, _ = regular_bytes(self.paths[name])
                if current not in (self.before[name], self.after[name]):
                    errors.append(name + ' 已被外部修改')
            except OSError:
                errors.append(name + ' 无法读取')
        if errors:
            raise RuntimeError('拒绝覆盖外部修改：' + ', '.join(errors))
        if self.api_attempted:
            try:
                if TAG in self.runtime_tags():
                    result = upgrade.run(self.binary, 'api', 'rmi', '--server=' + self.api, TAG, check=False, timeout=15)
                    if result.returncode != 0:
                        errors.append('无法移除动态入口')
                    else:
                        for _ in range(20):
                            if unbound(self.port):
                                break
                            time.sleep(0.1)
                        if not unbound(self.port):
                            errors.append('动态入口端口尚未释放')
            except RuntimeError:
                errors.append('无法检查动态入口')
        if errors:
            raise RuntimeError('；'.join(errors))
        for name in reversed(self.written):
            try:
                replace_preserving(self.paths[name], self.before[name], self.metadata[name])
            except OSError:
                errors.append('无法恢复 ' + name)
        if self.rule_attempted and self.rule('-C', check=False).returncode == 0:
            if self.rule('-D', check=False).returncode != 0:
                errors.append('无法移除临时防火墙规则')
        if errors:
            raise RuntimeError('；'.join(errors))


def enable(info, activation):
    if not activation.check():
        print('Brutal 入口已经配置。')
        return
    report = info.get('import_report', Path('/nonexistent'))
    if report.is_file() and json.loads(report.read_text()).get('status') in ('verifying', 'applying'):
        raise RuntimeError('代理导入正在执行，请稍后重试')
    backup = activation.save_backup()
    services = [name for name in upgrade.PANEL_ORDER if upgrade.active(name)]
    if 'xcli-panel' not in services or not upgrade.active('xray-gateway-core'):
        raise RuntimeError('面板或 Xray 核心未运行')
    generation = upgrade.core_generation(info)
    if not generation:
        raise RuntimeError('无法确认 Xray 核心进程')
    started = False
    panel_started = False
    print('已备份配置；添加入口期间管理面板会短暂重启，Xray 核心保持运行。', flush=True)
    try:
        started = True
        for name in services:
            upgrade.run('systemctl', 'stop', name)
        if report.is_file() and json.loads(report.read_text()).get('status') in ('verifying', 'applying'):
            raise RuntimeError('代理导入尚未完成，未修改配置')
        upgrade.snapshot(info['db'], backup / 'gateway.sqlite')
        before_users, before_protected = upgrade.private_rows(backup / 'gateway.sqlite')
        activation.verify_unchanged()
        if upgrade.core_generation(info) != generation:
            raise RuntimeError('Xray 核心在准备期间发生变化')
        activation.apply()
        upgrade.run('systemctl', 'start', 'xcli-panel')
        panel_started = True
        upgrade.wait_http(info.get('port', 18080), '/internal/ready', timeout=60)
        for name in reversed(services):
            if name != 'xcli-panel':
                upgrade.run('systemctl', 'start', name)
        upgrade.wait_http(8080)
        if any(not upgrade.active(name) for name in services):
            raise RuntimeError('部分管理服务未能恢复')
        if upgrade.core_generation(info) != generation:
            raise RuntimeError('新增入口期间 Xray 核心发生了重启')
        after_users, after_protected = upgrade.private_rows(info['db'])
        if upgrade.identities(before_users) != upgrade.identities(after_users) or before_protected != after_protected:
            raise RuntimeError('新增入口后用户数据发生意外变化')
        old_usage = {row[0]: row[7:9] for row in before_users}
        if any(any(value < old for value, old in zip(row[7:9], old_usage[row[0]])) for row in after_users):
            raise RuntimeError('新增入口后累计流量异常')
        upgrade.atomic_file(backup / 'completed', 'ok\n')
        print('已启用独立 Brutal 入口；原 BBR 入口保持运行。', flush=True)
        print('配置备份：' + str(backup), flush=True)
    except BaseException:
        if started:
            for name in services:
                upgrade.run('systemctl', 'stop', name, check=False)
        if panel_started and activation.api_attempted:
            try:
                upgrade.run(upgrade.LIB / 'xcli-panel-checkpoint', '--experimental', '--db', info['db'],
                            '--core-binary', activation.binary, '--core-pid-file', info['core_pid'],
                            '--core-api', activation.api, timeout=30)
            except (subprocess.SubprocessError, OSError):
                for name in reversed(services):
                    upgrade.run('systemctl', 'start', name, check=False)
                raise RuntimeError('最终用量采样失败，保留现有配置以免丢失流量；备份：' + str(backup)) from None
        rollback_error = None
        try:
            activation.rollback()
        except Exception as error:
            rollback_error = str(error)
        for name in reversed(services):
            upgrade.run('systemctl', 'start', name, check=False)
        if rollback_error:
            raise RuntimeError('入口回退未完全完成：' + rollback_error + '；备份：' + str(backup)) from None
        upgrade.wait_http(info.get('port', 18080), '/internal/ready', timeout=60)
        if any(not upgrade.active(name) for name in services):
            raise RuntimeError('原管理服务未能全部恢复；备份：' + str(backup))
        upgrade.atomic_file(backup / 'rolled-back', 'ok\n')
        print('已恢复原有入口配置；备份：' + str(backup), flush=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('请使用 root 或 sudo 运行')
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt
    for sig in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(sig, interrupted)
    upgrade.LOCK.parent.mkdir(parents=True, exist_ok=True)
    with upgrade.LOCK.open('a+') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('已有更新任务正在运行') from None
        info = upgrade.detect()
        binary, api, paths = discover(info)
        activation = Activation(info, args.port, binary, api, paths)
        if args.check:
            activation.check()
            print('Brutal 入口预检通过。')
        else:
            enable(info, activation)


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print('Brutal 入口操作停止：' + str(error), file=sys.stderr, flush=True)
        raise SystemExit(1)
