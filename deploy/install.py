#!/usr/bin/env python3
"""Fresh-server installer. Never run this as an upgrade on an existing deployment."""
import argparse
import datetime
import grp
import hashlib
import ipaddress
import json
import os
import pathlib
import platform
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile

from provision import (XRAY_ASSETS, XRAY_VERSION, core_config, domain_name,
                       initialize_admin, monitor_config, private_file, public_ipv4,
                       render_firewall, render_nginx, settings_for, write_json)
from certificate import install_tls
import release

Path = pathlib.Path
SERVICES = ('xray-gateway-firewall', 'xray-gateway-core', 'xray-gateway-panel', 'xray-gateway-monitor', 'xray-gateway-import')
OWNED_PATHS = ('/etc/xray-gateway', '/etc/xcli-monitor', '/var/lib/xray-gateway',
               '/var/lib/xray-gateway-monitor', '/var/lib/xray-gateway-import', '/usr/local/lib/xray-gateway',
               '/opt/xray-gateway', '/root/xray-gateway-admin.txt', '/etc/nginx',
               '/etc/sysctl.d/91-xray-gateway-network.conf', '/etc/modules-load.d/xray-gateway-network.conf',
               '/etc/systemd/system/xray-gateway-network.service', '/opt/xcli',
               '/usr/local/lib/xcli', '/var/lib/xcli', '/var/backups/xcli', '/var/cache/xcli',
               '/usr/local/sbin/xcli-release', '/usr/local/sbin/xcli-layout', '/usr/local/sbin/xcli-admin')
PORTS = (80, 443, 8080, 8443, 10080, 10085, 10443)
PACKAGES = (Path(__file__).with_name('build-packages.txt').read_text().split()
            + 'nginx libnginx-mod-stream certbot ca-certificates curl iptables iproute2 kmod'.split())


def arguments(argv=None):
    parser = argparse.ArgumentParser(description='xcli 全新服务器安装器；已有部署请按 README 升级')
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--commit', default='local')
    parser.add_argument('--domain')
    parser.add_argument('--email')
    parser.add_argument('--public-ip')
    parser.add_argument('--reality-sni', default='www.bing.com')
    parser.add_argument('--agree-tos', action='store_true')
    parser.add_argument('--yes', action='store_true')
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--certificate', type=Path)
    parser.add_argument('--private-key', type=Path)
    parser.add_argument('--tune-network', action=argparse.BooleanOptionalAction, default=None,
                        help='可选 BBR / fq 和至少 16 MiB UDP 缓冲上限；保存原值以便回退')
    return parser.parse_args(argv)


def ask(label, default=None):
    try:
        with open('/dev/tty', 'r+') as tty:
            tty.write(label + (f' [{default}]' if default else '') + ': ')
            tty.flush()
            answer = tty.readline()
            if not answer:
                raise ValueError('输入已结束，安装取消')
            return answer.strip() or default or ''
    except OSError as error:
        raise ValueError('无交互终端；请使用 --yes 并提供 --domain、--email、--agree-tos 等参数') from error


def resolve_domain(domain, address):
    def addresses(family):
        try:
            return {item[4][0] for item in socket.getaddrinfo(domain, 443, family, socket.SOCK_STREAM)}
        except socket.gaierror:
            return set()
    if addresses(socket.AF_INET) != {address}:
        raise ValueError('面板域名的 A 记录必须仅指向本机公网 IPv4；请检查 DNS，并关闭 CDN 代理')
    if addresses(socket.AF_INET6):
        raise ValueError('当前安装器使用 IPv4，请先移除面板域名的 AAAA 记录')


def check_ports(ports=PORTS):
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            try:
                connection.bind(('0.0.0.0', port))
            except OSError as error:
                raise ValueError(f'TCP {port} 已被占用或无法绑定，请先处理端口冲突') from error


def check_udp_port(port=443):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        try:
            connection.bind(('0.0.0.0', port))
        except OSError as error:
            raise ValueError(f'UDP {port} 已被占用或无法绑定，请先处理端口冲突') from error


def existing_paths(root=Path('/')):
    paths = list(OWNED_PATHS)
    for service in SERVICES:
        for base in ('/etc/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system'):
            paths.extend((f'{base}/{service}.service', f'{base}/{service}.service.d'))
    return [str(path) for value in paths if (path := root / value.lstrip('/')).exists() or path.is_symlink()]


def preflight(args):
    if os.geteuid() != 0 or platform.system() != 'Linux' or not Path('/run/systemd/system').is_dir():
        raise ValueError('需要 root 权限和使用 systemd 的 Ubuntu 服务器')
    release = platform.freedesktop_os_release()
    if release.get('ID') != 'ubuntu' or release.get('VERSION_ID') not in ('24.04', '26.04'):
        raise ValueError('当前支持 Ubuntu 24.04 / 26.04')
    arch = {'arm64': 'aarch64'}.get(platform.machine(), platform.machine())
    if arch not in XRAY_ASSETS:
        raise ValueError('当前支持 AMD64 / ARM64')
    found = existing_paths()
    if found:
        raise ValueError('拒绝覆盖已有配置：' + ', '.join(found))
    for name in ('xgateway', 'xgprobe'):
        try:
            pwd.getpwnam(name)
        except KeyError:
            continue
        raise ValueError(f'系统账户 {name} 已存在，请先人工核对旧安装')
    for name in ('xgateway', 'xgmonitor'):
        try:
            grp.getgrnam(name)
        except KeyError:
            continue
        raise ValueError(f'系统组 {name} 已存在，请先人工核对旧安装')
    if shutil.which('iptables'):
        for chain in ('XG_IN', 'XG_OUT'):
            if subprocess.run(['iptables', '-w', '-S', chain], capture_output=True, timeout=15).returncode == 0:
                raise ValueError(f'防火墙链 {chain} 已存在，拒绝覆盖')
    check_ports()
    check_udp_port()
    if bool(args.certificate) != bool(args.private_key):
        raise ValueError('--certificate 和 --private-key 必须一起提供')
    if not args.check and not re.fullmatch('[0-9a-f]{40}', args.commit):
        raise ValueError('安装必须使用固定的 40 位提交；请通过 install.sh 或传入 --commit')
    for name in ('cpp/CMakeLists.txt', 'static/index.html', 'deploy/templates/nginx.conf'):
        if not (args.source / name).is_file():
            raise ValueError('源码包不完整：' + name)
    return arch


def prepare_input(args):
    args.domain = domain_name(args.domain or (ask('面板域名') if not args.yes else ''))
    args.reality_sni = domain_name(args.reality_sni)
    if args.reality_sni == args.domain:
        raise ValueError('REALITY 目标域名不能与面板域名相同')
    if not args.public_ip:
        try:
            detected = subprocess.check_output(['curl', '-q', '-4', '-fsS', '--noproxy', '*',
                '--connect-timeout', '5', '--max-time', '10', 'https://api.ipify.org'], timeout=12, stderr=subprocess.DEVNULL).decode().strip()
        except (OSError, subprocess.SubprocessError):
            detected = None
        args.public_ip = detected if args.yes else ask('本机公网 IPv4', detected)
    args.public_ip = public_ipv4(args.public_ip or '')
    resolve_domain(args.domain, args.public_ip)
    if args.certificate:
        args.certificate = args.certificate.resolve(strict=True)
        args.private_key = args.private_key.resolve(strict=True)
        if not args.certificate.is_file() or not args.private_key.is_file():
            raise ValueError('证书和私钥必须是普通文件')
    else:
        for path in (Path('/etc/letsencrypt/live') / args.domain,
                     Path('/etc/letsencrypt/renewal') / (args.domain + '.conf'),
                     Path('/etc/letsencrypt/renewal-hooks/deploy/xcli-nginx')):
            if path.exists() or path.is_symlink():
                raise ValueError('已有证书配置，拒绝覆盖：' + str(path))
        if not args.check:
            args.email = args.email or (ask("Let's Encrypt 账户邮箱") if not args.yes else '')
            if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', args.email) or args.email.startswith('-'):
                raise ValueError('请提供有效的证书账户邮箱')
            if not args.agree_tos:
                if args.yes or ask('同意 https://letsencrypt.org/repository/ 中的服务条款？输入 yes') != 'yes':
                    raise ValueError('申请证书需同意服务条款；无人值守使用 --agree-tos')
    dns = []
    for line in Path('/etc/resolv.conf').read_text().splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == 'nameserver':
            try:
                dns.append(str(ipaddress.IPv4Address(fields[1])))
            except ValueError:
                pass
    if not dns:
        raise ValueError('需要至少一个可用的 IPv4 系统 DNS 服务器')
    if args.tune_network is None:
        args.tune_network = False if args.yes or args.check else ask(
            '启用可回退网络调优（BBR、fq、至少 16 MiB UDP 缓冲上限）？yes/no', 'no') == 'yes'
    return dns


class Installer:
    def __init__(self, args, arch, resolvers):
        self.args, self.arch, self.resolvers = args, arch, resolvers
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        self.backup = Path('/var/backups/xcli/install') / stamp
        self.backup.mkdir(parents=True, mode=0o700)
        self.log = self.backup / 'install.log'
        private_file(self.log, '')
        self.packages_started = False
        self.services_installed = False
        self.phase = '初始化'

    def step(self, name):
        self.phase = name
        print(f'\n→ {name}（详细输出：{self.log}）', flush=True)

    def run(self, command, capture=False, timeout=1800, check=True):
        command = [str(value) for value in command]
        with self.log.open('a') as log:
            log.write('\n$ ' + ' '.join(command) + '\n')
            log.flush()
            result = subprocess.run(command, stdout=subprocess.PIPE if capture else log, stderr=log,
                env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive', 'NEEDRESTART_MODE': 'l'}, timeout=timeout)
        if check and result.returncode:
            raise RuntimeError(f'{self.phase}失败（退出码 {result.returncode}），详见 {self.log}')
        return result.stdout if capture else result.returncode

    @staticmethod
    def directory(path, mode=0o755, user='root', group='root'):
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, mode)
        shutil.chown(path, user, group)
        return path

    @staticmethod
    def copy(source, target, mode=0o644):
        shutil.copyfile(source, target)
        os.chmod(target, mode)

    def rollback_script(self):
        private_file(self.backup / 'rollback.sh', '''#!/bin/sh
# Stops only this new installation; keeps credentials, database, packages and logs.
set -u
systemctl disable --now xray-gateway-import xray-gateway-monitor xray-gateway-panel xray-gateway-core 2>/dev/null || true
systemctl disable --now xray-gateway-firewall 2>/dev/null || true
if [ -x /opt/xray-gateway/deploy/firewall.sh ]; then /opt/xray-gateway/deploy/firewall.sh stop; fi
systemctl disable --now nginx 2>/dev/null || true
if [ -f /etc/xray-gateway/network-before.json ]; then
    python3 /opt/xray-gateway/deploy/network.py restore || echo '网络参数自动恢复失败，请检查保留的快照。'
fi
backup=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$backup/nginx.conf.before" ]; then cp "$backup/nginx.conf.before" /etc/nginx/nginx.conf; fi
echo '新安装的服务已停止；账号、数据库、证书和日志保留，未卸载系统软件包。'
''', 0o700)

    def packages_and_build(self):
        self.step('安装系统依赖并构建 C++ 管理服务')
        self.rollback_script()
        self.packages_started = True
        self.run(['apt-get', 'update'])
        self.run(['apt-get', 'install', '-y', '--no-install-recommends', *PACKAGES])
        self.copy('/etc/nginx/nginx.conf', self.backup / 'nginx.conf.before', 0o600)
        self.run(['systemctl', 'stop', 'nginx'])
        self.run(['groupadd', '--system', 'xgateway'])
        self.run(['useradd', '--system', '--no-create-home', '--home-dir', '/var/lib/xray-gateway',
                  '--shell', '/usr/sbin/nologin', '--gid', 'xgateway', 'xgateway'])
        self.run(['groupadd', '--system', 'xgmonitor'])
        self.run(['useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent',
                  '--shell', '/usr/sbin/nologin', '--gid', 'xgmonitor', 'xgprobe'])
        # Fresh install, source update and CI all use the same bundle builder.
        cache = self.directory('/var/cache/xcli/builds')
        self.build = self.directory(tempfile.mkdtemp(prefix='install-', dir=cache), user='xgateway', group='xgateway')
        self.bundle = self.build / 'release.tar.gz'
        self.run(['runuser', '-u', 'xgateway', '--', 'bash', self.args.source / 'deploy/build-source-release.sh',
                  self.args.source, self.args.commit, self.bundle])
        version = re.search(r'project\([^\n]*VERSION\s+([0-9.]+)', (self.args.source / 'cpp/CMakeLists.txt').read_text())
        if not version:
            raise ValueError('未找到管理服务版本')
        self.version = version[1]

    def install_files(self):
        self.step('校验 Xray 官方文件并生成独立凭据')
        base = self.directory('/usr/local/lib/xray-gateway')
        asset, digest = XRAY_ASSETS[self.arch]
        archive = self.args.source.parent / 'xray.zip'
        self.run(['curl', '-q', '--proto', '=https', '--tlsv1.2', '-fsSL', '--retry', '3',
                  '--connect-timeout', '10', '--max-time', '180',
                  f'https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/{asset}', '-o', archive])
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            raise ValueError('Xray 文件的 SHA-256 不匹配，停止安装')
        with zipfile.ZipFile(archive) as zipped:
            private_file(base / 'xray', zipped.read('xray'), 0o755)
        self.manager = release.Manager()
        with self.manager.lock():
            staged = self.manager.stage(self.bundle, release.digest(self.bundle))
        self.release_id = staged['staged']
        host = self.directory('/usr/local/lib/xcli/host')
        for name in ('certificate.py', 'network.py'):
            self.copy(self.args.source / 'deploy' / name, host / name)
        config = self.directory('/etc/xray-gateway', 0o750, group='xgateway')
        state = self.directory('/var/lib/xray-gateway', 0o700, 'xgateway', 'xgateway')
        self.directory('/var/lib/xray-gateway-import', 0o750, group='xgateway')
        monitor = self.directory('/etc/xcli-monitor', 0o750, group='xgmonitor')
        self.directory('/var/lib/xray-gateway-monitor', 0o750, 'xgprobe', 'xgmonitor')
        key_output = self.run([base / 'xray', 'x25519'], capture=True).decode()
        self.settings = settings_for(self.args.domain, self.args.public_ip, self.args.reality_sni, key_output)
        write_json(config / 'settings.json', self.settings)
        write_json(config / 'core.json', core_config(self.settings))
        private_file(config / 'security.key', os.urandom(32), 0o640)
        for name in ('settings.json', 'core.json', 'security.key'):
            shutil.chown(config / name, 'root', 'xgateway')
        write_json(monitor / 'monitor.json', monitor_config(self.settings))
        shutil.chown(monitor / 'monitor.json', 'root', 'xgmonitor')
        initialize_admin(state / 'gateway.sqlite', config / 'initial-admin.txt', self.args.domain)
        shutil.chown(state / 'gateway.sqlite', 'xgateway', 'xgateway')
        write_json(config / 'installation.json', {'version': self.version, 'commit': self.args.commit,
            'architecture': self.arch, 'xray': XRAY_VERSION, 'installed': int(time.time()),
            'certificate': 'provided' if self.args.certificate else 'letsencrypt'}, 0o600)
        private_file(host / 'firewall.sh', render_firewall(self.args.public_ip, self.resolvers), 0o755)
        release.atomic_json(host / 'manifest.json', {p.name: release.digest(p) for p in host.iterdir()}, 0o444)
        for tool, name in (('iptables-save', 'iptables.v4.before'), ('ip6tables-save', 'iptables.v6.before')):
            private_file(self.backup / name, self.run([tool], capture=True))
        for service in SERVICES:
            self.copy(self.args.source / 'deploy' / (service + '.service'),
                      Path('/etc/systemd/system') / (service + '.service'))
        drop = self.directory('/etc/systemd/system/xray-gateway-panel.service.d')
        private_file(drop / '20-cpp-backend.conf', '[Service]\nExecStart=\nExecStart=/usr/local/lib/xray-gateway/panel-current\nTimeoutStopSec=30\n', 0o644)
        private_file(drop / '30-features.conf', '[Service]\nSupplementaryGroups=xgmonitor\n'
            'Environment=XG_SECRET_KEY=/etc/xray-gateway/security.key\n'
            'Environment=XG_MONITOR_CONFIG=/etc/xcli-monitor/monitor.json\n'
            'Environment=XG_MONITOR_REPORT=/var/lib/xray-gateway-monitor/report.json\n'
            'Environment=XG_BACKUP_INTERVAL=21600\nEnvironment=XG_BACKUP_RETENTION=28\n', 0o644)
        self.services_installed = True
        self.run(['bash', self.args.source / 'deploy/install-release-tools.sh'])
        self.manager.initialize(self.release_id)
        shutil.rmtree(self.build)

    def nginx_config(self, certificate=None, key=None):
        target = Path('/etc/nginx/nginx.conf')
        new = target.with_suffix('.conf.xcli-new')
        private_file(new, render_nginx(self.args.source, self.settings, certificate, key), 0o644)
        new.replace(target)
        self.run(['nginx', '-t'])

    def certificate(self):
        self.step('配置 HTTPS 证书和自动续期')
        self.run(['systemctl', 'enable', '--now', 'xray-gateway-firewall'])
        self.directory('/var/www/acme')
        if self.args.certificate:
            cert_dir = self.directory('/etc/xray-gateway/tls', 0o700)
            cert, key = cert_dir / 'fullchain.pem', cert_dir / 'privkey.pem'
            self.copy(self.args.certificate, cert, 0o600)
            self.copy(self.args.private_key, key, 0o600)
            self.run(['openssl', 'x509', '-in', cert, '-noout', '-checkhost', self.args.domain])
            self.run(['openssl', 'x509', '-in', cert, '-noout', '-checkend', '86400'])
            cert_key = self.run(['openssl', 'x509', '-in', cert, '-pubkey', '-noout'], capture=True)
            private_key = self.run(['openssl', 'pkey', '-in', key, '-pubout', '-passin', 'pass:'], capture=True)
            if cert_key.strip() != private_key.strip():
                raise ValueError('证书与私钥不匹配')
        else:
            self.nginx_config()
            self.run(['systemctl', 'enable', '--now', 'nginx'])
            self.run(['certbot', 'certonly', '--webroot', '-w', '/var/www/acme', '--cert-name', self.args.domain,
                      '-d', self.args.domain, '--email', self.args.email, '--agree-tos', '--non-interactive'], timeout=300)
            live = Path('/etc/letsencrypt/live') / self.args.domain
            cert, key = live / 'fullchain.pem', live / 'privkey.pem'
            hook = self.directory('/etc/letsencrypt/renewal-hooks/deploy') / 'xcli-nginx'
            private_file(hook, '#!/bin/sh\nset -eu\n/usr/bin/python3 /opt/xray-gateway/deploy/certificate.py\n'
                '/usr/sbin/nginx -t\n/usr/bin/systemctl reload nginx\n', 0o755)
            self.run(['systemctl', 'enable', '--now', 'certbot.timer'])
        install_tls(self.args.domain, cert, key, Path('/etc/xray-gateway/hysteria-tls'), 'xgateway')
        self.run(['runuser', '-u', 'xgateway', '--', '/usr/local/lib/xray-gateway/xray', 'run', '-test',
                  '-config', '/etc/xray-gateway/core.json'])
        self.nginx_config(cert, key)

    def start_and_verify(self):
        self.step('启动服务并验证 HTTPS、管理接口和节点自检')
        self.run(['systemctl', 'enable', '--now', 'xray-gateway-core', 'xray-gateway-panel'])
        self.run(['systemctl', 'enable', '--now', 'nginx'])
        self.run(['systemctl', 'reload', 'nginx'])
        for attempt in range(30):
            code = self.run(['curl', '-q', '-fsS', '--noproxy', '*', '--max-time', '3',
                             'http://127.0.0.1:8080/healthz'], check=False, timeout=5)
            if code == 0:
                break
            time.sleep(1)
        else:
            raise RuntimeError('管理接口未就绪')
        self.run(['curl', '-q', '-fsS', '--noproxy', '*', '--max-time', '15', '--resolve',
                  self.args.domain + ':443:127.0.0.1', 'https://' + self.args.domain + '/healthz'], timeout=20)
        for attempt in range(15):
            output = self.run(['runuser', '-u', 'xgateway', '-g', 'xgateway', '-G', 'xgmonitor', '--',
                '/usr/local/lib/xray-gateway/panel-current', '--secret-key', '/etc/xray-gateway/security.key',
                '--monitor-config', '/etc/xcli-monitor/monitor.json', '--preflight'], capture=True, check=False)
            try:
                report = json.loads(output)
            except (ValueError, UnicodeError):
                report = {}
            if (report.get('pending_additions') == 0 and report.get('pending_revocations') == 0
                    and report.get('database_integrity') == 'ok'):
                break
            time.sleep(1)
        else:
            raise RuntimeError('管理服务未完成探测账号同步')
        self.run(['systemctl', 'enable', '--now', 'xray-gateway-monitor', 'xray-gateway-import'])
        for service in (*SERVICES, 'nginx'):
            self.run(['systemctl', 'is-active', '--quiet', service])
        self.manager.host.health(self.manager.current.resolve(), release.BASE_UNITS)
        probe = Path('/var/lib/xray-gateway-monitor/report.json')
        for attempt in range(100):
            if probe.is_file():
                report = json.loads(probe.read_text())
                if report.get('status') == 'healthy':
                    print('HTTPS、核心管理接口及三个入口的 HTTPS / UDP 自检均通过。', flush=True)
                    return True
            time.sleep(1)
        print('管理服务和 HTTPS 已就绪，但节点自检尚未全部通过；请登录查看健康监测和入口可达性。', flush=True)
        return False

    def execute(self):
        try:
            self.packages_and_build()
            self.install_files()
            self.certificate()
            if self.args.tune_network:
                self.step('应用可回退网络调优')
                self.run(['python3', '/opt/xray-gateway/deploy/network.py', 'apply'])
            healthy = self.start_and_verify()
        except (Exception, KeyboardInterrupt):
            if self.packages_started:
                self.run(['sh', self.backup / 'rollback.sh'], check=False, timeout=90)
            print(f'\n安装在“{self.phase}”阶段停止。新服务已停用，数据保留。\n日志与回退脚本：{self.backup}\n'
                  '请根据日志处理，勿删除已有配置后盲目重试。', file=sys.stderr, flush=True)
            raise
        print(f'\n安装完成： https://{self.args.domain}/\n'
              '管理员用户名：admin\n初始密码文件：/etc/xray-gateway/initial-admin.txt（仅 root 可读）\n'
              '查看凭据：sudo cat /etc/xray-gateway/initial-admin.txt\n'
              f'日志与停用脚本：{self.backup}\n'
              + ('已有证书不会自动续期，请按原有方式更新安装目录内的证书并重载 Nginx。\n' if self.args.certificate else ''), flush=True)
        return 0 if healthy else 2


def main(argv=None):
    args = arguments(argv)
    args.source = args.source.resolve()
    arch = preflight(args)
    resolvers = prepare_input(args)
    print(f'检查通过：Ubuntu {platform.freedesktop_os_release()["VERSION_ID"]} / {arch}\n'
          f'面板：https://{args.domain}  公网 IPv4：{args.public_ip}\n'
          f'REALITY 目标：{args.reality_sni}\n'
          f'网络调优：{"启用并保存原值" if args.tune_network else "保留现有参数"}\n'
          '将安装依赖、Xray、C++ 面板、Nginx、专用账号、探测服务及专属防火墙规则。\n'
          '请确保云安全组和上游网络允许 TCP 80 / 443 及 UDP 443 入站。', flush=True)
    if args.check:
        print('只检查模式结束；未安装软件或修改系统配置。')
        return 0
    if not args.yes and ask('确认在这台全新服务器安装？输入 yes') != 'yes':
        raise ValueError('已取消安装')
    return Installer(args, arch, resolvers).execute()


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print('安装停止：' + str(error), file=sys.stderr)
        raise SystemExit(1)
