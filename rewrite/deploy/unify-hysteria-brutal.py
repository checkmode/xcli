#!/usr/bin/env python3
"""Make an existing panel's Brutal listener the sole Hysteria 2 listener."""
import argparse
import copy
import datetime
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

spec = importlib.util.spec_from_file_location('xcli_brutal_support', Path(__file__).with_name('enable-hysteria-brutal.py'))
support = importlib.util.module_from_spec(spec)
spec.loader.exec_module(support)
upgrade = support.upgrade


def build_candidates(settings_bytes, core_bytes, monitor_bytes):
    """Build a candidate without touching credentials, routes or user data."""
    settings, core, monitor = (json.loads(v) for v in (settings_bytes, core_bytes, monitor_bytes))
    if any(not isinstance(v, dict) for v in (settings, core, monitor)):
        raise ValueError('配置格式不正确')
    rate = settings.get('hysteria2_brutal_mbps', 40)
    primary_port, brutal_port = settings.get('hysteria2_port'), settings.get('hysteria2_brutal_port', 0)
    if type(rate) is not int or not 1 <= rate <= 1000:
        raise ValueError('Brutal 速率无效')
    if type(primary_port) is not int or not 1 <= primary_port <= 65535:
        raise ValueError('Hysteria 端口无效')
    entries = core.get('inbounds')
    routes = core.get('routing', {}).get('rules')
    if not isinstance(entries, list) or any(not isinstance(v, dict) for v in entries) or not isinstance(routes, list):
        raise ValueError('Xray 入站或路由配置无效')
    regular = [v for v in entries if v.get('tag') == 'hysteria2']
    brutal = [v for v in entries if v.get('tag') == 'hysteria2-brutal']
    if len(regular) != 1 or regular[0].get('port') != primary_port:
        raise ValueError('未找到唯一的原 Hysteria 入口')
    if settings.get('hysteria2_primary_brutal') is True:
        params = regular[0].get('streamSettings', {}).get('finalmask', {}).get('quicParams', {})
        if (brutal_port != 0 or brutal or monitor.get('hysteria2_port') != primary_port
                or monitor.get('hysteria2_brutal_port', 0) != 0
                or regular[0].get('protocol') != 'hysteria'
                or params.get('congestion') != 'force-brutal'
                or str(params.get('brutalUp', '')).strip().lower() != f'{rate} mbps'):
            raise ValueError('已有单入口配置不一致')
        return None
    if (settings.get('hysteria2_primary_brutal', False) is not False
            or type(brutal_port) is not int or not 1024 <= brutal_port <= 65535
            or brutal_port == primary_port or len(brutal) != 1
            or brutal[0].get('port') != brutal_port
            or monitor.get('hysteria2_port') != primary_port
            or monitor.get('hysteria2_brutal_port') != brutal_port):
        raise ValueError('现有两个 Hysteria 入口或监控配置不一致')
    for inbound in (regular[0], brutal[0]):
        stream, account = inbound.get('streamSettings', {}), inbound.get('settings', {})
        if (inbound.get('protocol') != 'hysteria' or account.get('version') != 2
                or account.get('clients', []) != [] or account.get('users', []) != []
                or stream.get('network') != 'hysteria' or stream.get('security') != 'tls'):
            raise ValueError('现有入口包含不支持自动迁移的设置')
    params = brutal[0].get('streamSettings', {}).get('finalmask', {}).get('quicParams', {})
    if params.get('congestion') != 'force-brutal' or str(params.get('brutalUp', '')).strip().lower() != f'{rate} mbps':
        raise ValueError('Brutal 入口速率与面板配置不一致')
    if any(not isinstance(rule, dict) or 'hysteria2-brutal' in rule.get('inboundTag', []) for rule in routes):
        raise ValueError('Brutal 入口有自定义路由，需要先检查')
    # Verify the exact routes for each residential identity before retaining them.
    for entry in settings.get('residential_exits', []):
        if not entry.get('hysteria2'):
            continue
        tag = entry.get('tag', '')
        for network, target in (('udp', 'blocked'), ('tcp', tag + '-exit')):
            matches = [r for r in routes if r.get('ruleTag') == tag + '-hy2-' + network]
            if len(matches) != 1 or matches[0].get('inboundTag') != ['hysteria2'] or matches[0].get('user') != ['regexp:@' + tag + '-hy2$'] or matches[0].get('network') != network or matches[0].get('outboundTag') != target:
                raise ValueError('住宅出口认证或路由不一致，未修改配置')
    replacement = copy.deepcopy(brutal[0])
    replacement['tag'] = 'hysteria2'
    core['inbounds'] = [replacement if v.get('tag') == 'hysteria2' else v for v in entries if v.get('tag') != 'hysteria2-brutal']
    settings['hysteria2_port'] = brutal_port
    settings['hysteria2_brutal_port'] = 0
    settings['hysteria2_primary_brutal'] = True
    monitor['hysteria2_port'] = brutal_port
    monitor['hysteria2_brutal_port'] = 0
    return {k: support.json_bytes(v) for k, v in (('settings', settings), ('core', core), ('monitor', monitor))}


def runtime_tags(binary, api):
    result = upgrade.run(binary, 'api', 'lsi', '--server=' + api, '--isOnlyTags=true', timeout=15)
    return {v['tag'] for v in json.loads(result.stdout)['inbounds']}


def wait_runtime_tags(binary, api, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            return runtime_tags(binary, api)
        except (subprocess.SubprocessError, OSError, ValueError, KeyError, TypeError):
            time.sleep(0.25)
    raise RuntimeError('Xray 管理接口未就绪')


def check(info, binary, api, paths, before, after):
    tags = runtime_tags(binary, api)
    expected = {'hysteria2'} if after is None else {'hysteria2', 'hysteria2-brutal'}
    if not expected.issubset(tags) or after is None and 'hysteria2-brutal' in tags:
        raise RuntimeError('运行中的入口与配置不一致')
    port = json.loads((after or before)['settings'])['hysteria2_port']
    if support.unbound(port):
        raise RuntimeError('Hysteria 入口未监听')
    result = upgrade.run('iptables', '-w', '-C', 'XG_IN', '-p', 'udp', '--dport', str(port), '-j', 'ACCEPT', check=False)
    if result.returncode != 0:
        raise RuntimeError('目标 UDP 端口的防火墙规则不可用')
    if after:
        with tempfile.TemporaryDirectory(prefix='xcli-hy2-unify-', dir='/var/tmp') as folder:
            candidate = Path(folder) / 'core.json'; candidate.write_bytes(after['core']); os.chmod(candidate, 0o600)
            try:
                upgrade.run(binary, 'run', '-test', '-config', candidate, timeout=30)
            except (subprocess.SubprocessError, OSError):
                raise RuntimeError('新 Xray 配置校验失败') from None


def checkpoint(info, binary, api):
    upgrade.run(upgrade.LIB / 'xcli-panel-checkpoint', '--experimental', '--db', info['db'],
                '--core-binary', binary, '--core-pid-file', info['core_pid'], '--core-api', api, timeout=30)


def start_services(info, services):
    upgrade.run('systemctl', 'start', 'xcli-panel')
    upgrade.wait_http(info.get('port', 18080), '/internal/ready', timeout=60)
    for name in reversed(services):
        if name != 'xcli-panel':
            upgrade.run('systemctl', 'start', name)
    upgrade.wait_http(8080)
    if any(not upgrade.active(name) for name in services):
        raise RuntimeError('部分管理服务未恢复')


def apply(info, binary, api, paths, before, metadata, after):
    report = info.get('import_report', Path('/nonexistent'))
    if report.is_file() and json.loads(report.read_text()).get('status') in ('verifying', 'applying'):
        raise RuntimeError('代理导入正在进行，请稍后重试')
    services = [v for v in upgrade.PANEL_ORDER if upgrade.active(v)]
    if 'xcli-panel' not in services or not upgrade.active('xray-gateway-core'):
        raise RuntimeError('面板或 Xray 核心未运行')
    upgrade.BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(upgrade.BACKUPS, 0o700)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup = Path(tempfile.mkdtemp(prefix='hy2-unify-' + stamp + '-', dir=upgrade.BACKUPS))
    for name, data in before.items():
        upgrade.atomic_file(backup / (name + '.before'), data)
    upgrade.atomic_file(backup / 'manifest.json', json.dumps({name: {'path':str(paths[name]), 'mode':metadata[name][0], 'uid':metadata[name][1], 'gid':metadata[name][2]} for name in before}, indent=2))
    generation = upgrade.core_generation(info)
    written, core_changed, panel_started = [], False, False
    print('已备份配置；切换期间面板和 VPN 连接会短暂中断。', flush=True)
    try:
        for service in services:
            upgrade.run('systemctl', 'stop', service)
        if report.is_file() and json.loads(report.read_text()).get('status') in ('verifying', 'applying'):
            raise RuntimeError('代理导入尚未结束')
        if not generation or upgrade.core_generation(info) != generation:
            raise RuntimeError('Xray 核心进程发生变化')
        if any(support.regular_bytes(paths[n])[0] != data for n, data in before.items()):
            raise RuntimeError('配置在准备期间发生变化')
        checkpoint(info, binary, api)
        upgrade.snapshot(info['db'], backup / 'gateway.sqlite')
        old_users, old_private = upgrade.private_rows(backup / 'gateway.sqlite')
        for name in ('core', 'monitor', 'settings'):
            written.append(name)
            support.replace_preserving(paths[name], after[name], metadata[name])
        core_changed = True
        upgrade.run('systemctl', 'restart', 'xray-gateway-core')
        tags = wait_runtime_tags(binary, api)
        if 'hysteria2' not in tags or 'hysteria2-brutal' in tags:
            raise RuntimeError('新 Hysteria 入口未就绪')
        panel_started = True
        start_services(info, services)
        users, private = upgrade.private_rows(info['db'])
        if upgrade.identities(old_users) != upgrade.identities(users) or old_private != private:
            raise RuntimeError('用户或管理数据意外发生变化')
        old_usage = {row[0]: row[7:9] for row in old_users}
        if any(any(value < old for value, old in zip(row[7:9], old_usage[row[0]])) for row in users):
            raise RuntimeError('累计用量异常')
        check(info, binary, api, paths, after, None)
        upgrade.atomic_file(backup / 'completed', 'ok\n')
        print('已切换到唯一的 Brutal 入口，用户和订阅地址保持不变。', flush=True)
        print('配置和数据备份：' + str(backup), flush=True)
    except BaseException:
        upgrade.run('systemctl', 'stop', *services, check=False)
        if panel_started and upgrade.active('xray-gateway-core'):
            try:
                checkpoint(info, binary, api)
            except Exception:
                print('回退前用量采样失败，最后一段流量可能未计入。', file=sys.stderr, flush=True)
        for name in written:
            current, _ = support.regular_bytes(paths[name])
            if current not in (before[name], after[name]):
                raise RuntimeError('配置被外部修改，无法自动回退；备份：' + str(backup)) from None
        for name in reversed(written):
            support.replace_preserving(paths[name], before[name], metadata[name])
        if core_changed:
            upgrade.run('systemctl', 'restart', 'xray-gateway-core')
        start_services(info, services)
        upgrade.atomic_file(backup / 'rolled-back', 'ok\n')
        print('已恢复原入口和服务；备份：' + str(backup), flush=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError('请使用 root 或 sudo 运行')
    def interrupted(_sig, _frame): raise KeyboardInterrupt
    for sig in (signal.SIGHUP, signal.SIGTERM): signal.signal(sig, interrupted)
    upgrade.LOCK.parent.mkdir(parents=True, exist_ok=True)
    with upgrade.LOCK.open('a+') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('已有更新任务正在运行') from None
        info = upgrade.detect()
        binary, api, paths = support.discover(info)
        paths = {name:paths[name] for name in ('settings', 'core', 'monitor')}
        before, metadata = {}, {}
        for name, path in paths.items(): before[name], metadata[name] = support.regular_bytes(path)
        after = build_candidates(before['settings'], before['core'], before['monitor'])
        check(info, binary, api, paths, before, after)
        if after is None: print('已经使用唯一的 Brutal 入口。'); return
        if args.check: print('检查通过，可以切换到唯一的 Brutal 入口。'); return
        apply(info, binary, api, paths, before, metadata, after)


if __name__ == '__main__':
    try: main()
    except (Exception, KeyboardInterrupt) as error:
        print('Hysteria 入口切换停止：' + str(error), file=sys.stderr, flush=True)
        raise SystemExit(1)
