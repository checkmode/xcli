#!/usr/bin/env python3
"""Replace a legacy XCLI panel with a fresh experimental panel on the same host.

The existing panel's users and state are not imported.  This command is for an
administrator who has explicitly chosen to replace the legacy installation.
"""
import argparse
import datetime
import importlib.util
import os
from pathlib import Path
import platform
import pwd
import grp
import shutil
import socket
import subprocess
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('xcli_rewrite_installer', HERE / 'install-experimental.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)
import dualstack
from certificate import openssl
from provision import XRAY_ASSETS, domain_name, private_file, public_ipv4

OLD_UNITS = ('xray-gateway-import', 'xray-gateway-monitor', 'xray-gateway-panel',
             'xray-gateway-webshare', 'xray-gateway-core', 'xcli-hk-ipv6-port',
             'xcli-hk-default-port', 'xray-gateway-firewall')
MOVED = {
    '/etc/systemd/system/nginx.service.d/90-xcli.conf': 'nginx-dropin',
    '/etc/xcli-monitor': 'old-monitor-config',
    '/etc/nginx/xcli-import-locations.conf': 'old-import-locations',
    '/etc/nginx/xcli-webshare-locations.conf': 'old-webshare-locations',
    '/opt/xcli/current': 'old-current',
    '/etc/letsencrypt/renewal-hooks/deploy/xcli-tech-nginx': 'old-hook-tech',
    '/etc/letsencrypt/renewal-hooks/deploy/xcli-legacy-hysteria': 'old-hook-legacy',
    '/etc/letsencrypt/renewal-hooks/deploy/xcli-hk-nginx': 'old-hook-hk',
    '/etc/letsencrypt/renewal-hooks/deploy/xcli-hk-panel-nginx': 'old-hook-panel',
}


class Replacement(installer.Installer):
    def rollback_script(self):
        lines = ['#!/bin/sh', 'set +e', 'backup=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)',
                 'systemctl disable --now xcli-import xcli-monitor xcli-webshare xcli-web xcli-panel xcli-core xcli-firewall nginx',
                 'if [ -f "$backup/nginx.conf.before" ]; then cp "$backup/nginx.conf.before" /etc/nginx/nginx.conf; fi',
                 'if [ -f /etc/letsencrypt/renewal-hooks/deploy/xcli-rust ]; then mv /etc/letsencrypt/renewal-hooks/deploy/xcli-rust "$backup/failed-hook"; fi']
        for destination, name in MOVED.items():
            saved = '$backup/' + name
            lines.extend([f'if [ -e "{saved}" ] || [ -L "{saved}" ]; then',
                          f'  if [ -e "{destination}" ] || [ -L "{destination}" ]; then mv "{destination}" "$backup/failed-{name}"; fi',
                          f'  mv "{saved}" "{destination}"', 'fi'])
        lines.extend(['systemctl daemon-reload',
                      'systemctl enable --now xray-gateway-firewall xcli-hk-default-port xcli-hk-ipv6-port',
                      'systemctl enable --now nginx xray-gateway-core xray-gateway-panel xray-gateway-monitor xray-gateway-import xray-gateway-webshare',
                      "echo '旧服务已尝试恢复；新面板数据与安装日志保留。'"])
        private_file(self.backup / 'rollback.sh', '\n'.join(lines) + '\n', 0o700)

    def packages_and_build(self):
        self.step('停止旧版 XCLI 并准备新面板')
        self.rollback_script()
        self.copy('/etc/nginx/nginx.conf', self.backup / 'nginx.conf.before', 0o600)
        self.packages_started = True
        for unit in OLD_UNITS:
            self.run(['systemctl', 'disable', '--now', unit], check=False, timeout=90)
            if self.run(['systemctl', 'is-active', '--quiet', unit], check=False, timeout=15) == 0:
                raise RuntimeError('旧服务未能停止：' + unit)
        self.run(['systemctl', 'stop', 'nginx'], timeout=90)
        for original, name in MOVED.items():
            path = Path(original)
            if path.exists() or path.is_symlink():
                shutil.move(str(path), str(self.backup / name))
        self.run(['systemctl', 'daemon-reload'])

    def install_programs(self):
        self.step('安装 Rust 服务和 Node 网关')
        base = self.directory('/usr/local/lib/xcli')
        for binary in (self.release / 'bin').iterdir():
            if binary.is_file():
                self.copy(binary, base / binary.name, 0o755)
        self.copy(self.node_binary, base / 'node', 0o755)
        self.copy('/usr/local/lib/xray-gateway/xray', base / 'xray', 0o755)
        release_dir = self.directory('/opt/xcli/releases/' + self.args.commit)
        shutil.copytree(self.release / 'web', release_dir / 'web')
        os.symlink(release_dir, '/opt/xcli/current')
        return self.run([base / 'xray', 'x25519'], capture=True).decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domain', required=True)
    parser.add_argument('--public-ip', required=True)
    parser.add_argument('--release-dir', required=True, type=Path)
    parser.add_argument('--node-bin', required=True, type=Path)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or platform.system() != 'Linux' or not Path('/run/systemd/system').is_dir():
        raise ValueError('需要 root 权限和 systemd')
    os_release = platform.freedesktop_os_release()
    if os_release.get('ID') != 'ubuntu' or os_release.get('VERSION_ID') not in ('24.04', '26.04'):
        raise ValueError('当前支持 Ubuntu 24.04 / 26.04')
    arch = {'arm64': 'aarch64'}.get(platform.machine(), platform.machine())
    if arch not in XRAY_ASSETS:
        raise ValueError('当前支持 AMD64 / ARM64')
    args.domain = domain_name(args.domain)
    args.public_ip = public_ipv4(args.public_ip)
    args.ipv6 = dualstack.resolve_domain(args.domain, args.public_ip)
    args.source = args.source.resolve(strict=True)
    release = args.release_dir.resolve(strict=True)
    node = args.node_bin.resolve(strict=True)
    if (release / 'BUILD_STATUS').read_text().strip() != 'experimental':
        raise ValueError('需要实验构建版本')
    if int(subprocess.check_output([node, '-p', 'Number(process.versions.node.split(".")[0])'], text=True, timeout=10)) not in (24, 25, 26):
        raise ValueError('需要 Node.js 24–26')
    if not Path('/usr/local/lib/xray-gateway/xray').is_file():
        raise ValueError('未找到旧版 Xray')
    for path in ('/etc/xcli', '/var/lib/xcli/gateway.sqlite', '/var/lib/xcli-import', '/var/lib/xcli-monitor',
                 '/etc/systemd/system/xcli-core.service', '/etc/letsencrypt/renewal-hooks/deploy/xcli-rust'):
        if Path(path).exists() or Path(path).is_symlink():
            raise ValueError('已存在新面板配置：' + path)
    for user in ('xgateway', 'xgprobe'):
        pwd.getpwnam(user)
    for group in ('xgateway', 'xgmonitor'):
        grp.getgrnam(group)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            listener.bind(('127.0.0.1', 18080))
        except OSError as error:
            raise ValueError('新面板使用的本机 TCP 18080 已被占用') from error
    live = Path('/etc/letsencrypt/live') / args.domain
    args.certificate, args.private_key = live / 'fullchain.pem', live / 'privkey.pem'
    if openssl('x509', '-in', args.certificate, '-noout', '-checkhost', args.domain).strip() != (
            'Hostname ' + args.domain + ' does match certificate').encode():
        raise ValueError('现有证书与域名不匹配')
    openssl('x509', '-in', args.certificate, '-noout', '-checkend', '86400')
    if openssl('x509', '-in', args.certificate, '-pubkey', '-noout').strip() != openssl(
            'pkey', '-in', args.private_key, '-pubout', '-passin', 'pass:').strip():
        raise ValueError('现有证书和私钥不匹配')
    resolvers = []
    import ipaddress
    for line in Path('/etc/resolv.conf').read_text().splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == 'nameserver':
            try:
                resolvers.append(str(ipaddress.IPv4Address(fields[1])))
            except ValueError:
                pass
    if not resolvers:
        raise ValueError('需要 IPv4 系统 DNS 服务器')
    if args.check:
        print('检查完成：将创建全新面板，旧用户和数据不会导入；IPv6 ' + ('已启用' if args.ipv6 else '未启用'))
        return 0
    args.coexist = False
    args.reality_sni = 'www.bing.com'
    args.public_port = 443
    args.panel = None
    args.email = None
    args.no_email = True
    args.commit = 'rewrite-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    return Replacement(args, arch, resolvers, 'panel', release, node).execute()


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError, KeyError, KeyboardInterrupt) as error:
        print('安装停止：' + str(error), file=sys.stderr)
        raise SystemExit(1)
