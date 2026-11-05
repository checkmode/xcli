#!/usr/bin/env python3
"""Install the experimental rewrite on a fresh Ubuntu host.

This entry point currently requires a locally built release and Node runtime.
It is separate from the supported installer until both roles and upgrades have
been tested end to end. It never upgrades or migrates an existing installation.
"""
import argparse
import grp
import hashlib
import os
from pathlib import Path
import pwd
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

SOURCE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE / 'deploy'))
import install
import install_node
from certificate import install_tls
from provision import XRAY_ASSETS, XRAY_VERSION, private_file, write_json
import dualstack
import render


class Installer(install.Installer):
    def __init__(self, args, arch, resolvers, role, release, node_binary):
        super().__init__(args, arch, resolvers)
        self.role, self.release, self.node_binary = role, release, node_binary
        self.settings = None

    def rollback_script(self):
        private_file(self.backup / 'rollback.sh', '''#!/bin/sh
set -u
systemctl disable --now xcli-import xcli-monitor xcli-web xcli-panel xcli-core xcli-node xcli-webshare 2>/dev/null || true
systemctl disable --now xcli-firewall nginx 2>/dev/null || true
if [ -f "$(dirname "$0")/nginx.conf.before" ]; then cp "$(dirname "$0")/nginx.conf.before" /etc/nginx/nginx.conf; fi
echo '实验服务已停止；用户数据、凭据、证书与日志均保留。'
''', 0o700)

    def packages_and_build(self):
        self.step('安装系统依赖并创建服务账户')
        self.rollback_script()
        self.packages_started = True
        self.run(['apt-get', 'update'])
        self.run(['apt-get', 'install', '-y', '--no-install-recommends', 'nginx', 'libnginx-mod-stream',
                  'certbot', 'ca-certificates', 'curl', 'openssl', 'iptables', 'iproute2'])
        self.copy('/etc/nginx/nginx.conf', self.backup / 'nginx.conf.before', 0o600)
        self.run(['systemctl', 'stop', 'nginx'])
        self.run(['groupadd', '--system', 'xgateway'])
        self.run(['useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent',
                  '--shell', '/usr/sbin/nologin', '--gid', 'xgateway', 'xgateway'])
        self.run(['groupadd', '--system', 'xgmonitor'])
        self.run(['useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent',
                  '--shell', '/usr/sbin/nologin', '--gid', 'xgmonitor', 'xgprobe'])

    def install_programs(self):
        self.step('安装 Rust 程序和 Xray')
        base = self.directory('/usr/local/lib/xcli')
        for binary in (self.release / 'bin').iterdir():
            if binary.is_file():
                self.copy(binary, base / binary.name, 0o755)
        if self.role == 'panel':
            self.copy(self.node_binary, base / 'node', 0o755)
            release_dir = self.directory('/opt/xcli/releases/' + self.args.commit)
            shutil.copytree(self.release / 'web', release_dir / 'web')
            private_file(release_dir / 'COMMIT', self.args.commit + '\n', 0o644)
            os.symlink(release_dir, '/opt/xcli/current')
        asset, digest = XRAY_ASSETS[self.arch]
        archive = self.backup / 'xray.zip'
        self.run(['curl', '-q', '--proto', '=https', '--tlsv1.2', '-fsSL', '--retry', '3',
                  '--connect-timeout', '10', '--max-time', '180',
                  f'https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/{asset}', '-o', archive])
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            raise ValueError('Xray 文件的 SHA-256 不匹配')
        with zipfile.ZipFile(archive) as zipped:
            private_file(base / 'xray', zipped.read('xray'), 0o755)
        archive.unlink()
        return self.run([base / 'xray', 'x25519'], capture=True).decode()

    def install_units(self):
        names = ['xcli-firewall', 'xcli-node'] if self.role == 'node' else [
            'xcli-firewall', 'xcli-core', 'xcli-panel', 'xcli-web', 'xcli-monitor', 'xcli-import', 'xcli-webshare']
        for name in names:
            self.copy(SOURCE / 'rewrite/deploy' / (name + '.service.example'),
                      Path('/etc/systemd/system') / (name + '.service'))
        self.services_installed = True
        self.run(['systemctl', 'daemon-reload'])

    def install_configuration(self, key_output):
        self.step('生成首次配置和凭据')
        self.directory('/var/www/acme')
        panel_user = pwd.getpwnam('xgateway')
        probe_user = pwd.getpwnam('xgprobe')
        panel_gid = grp.getgrnam('xgateway').gr_gid
        probe_gid = grp.getgrnam('xgmonitor').gr_gid
        if self.role == 'panel':
            self.directory('/etc/xcli', 0o750, group='xgateway')
            self.directory('/etc/xcli-monitor', 0o750, group='xgmonitor')
            self.directory('/var/lib/xcli', 0o700, user='xgateway', group='xgateway')
            self.directory('/var/lib/xcli/proxy-import', 0o700, user='xgateway', group='xgateway')
            self.directory('/var/lib/xcli-import', 0o755)
            self.directory('/var/lib/xcli-import/state', 0o700)
            self.directory('/var/lib/xcli-import/journal', 0o700)
            self.directory('/var/lib/xcli-import/report', 0o750, group='xgateway')
            self.directory('/var/lib/xcli-monitor', 0o750, user='xgprobe', group='xgmonitor')
            self.directory('/etc/xcli/hysteria-tls', 0o750, group='xgateway')
            data = render.panel(self.args.source, self.args.domain, self.args.public_ip, self.args.reality_sni,
                                key_output, self.args.public_port, self.resolvers, panel_user.pw_uid,
                                panel_gid, probe_user.pw_uid, probe_gid, getattr(self.args, 'ipv6', False))
            for name, value in (('settings.json', data['settings']), ('core.json', data['core'])):
                path = Path('/etc/xcli') / name
                write_json(path, value)
                shutil.chown(path, 'root', 'xgateway')
            write_json(Path('/etc/xcli/import-service.json'), data['worker'], 0o600)
            write_json(Path('/etc/xcli-monitor/monitor.json'), data['monitor'])
            shutil.chown('/etc/xcli-monitor/monitor.json', 'root', 'xgmonitor')
            private_file('/etc/xcli/security.key', secrets.token_bytes(32), 0o640)
            private_file('/etc/xcli/panel.env', data['environment'], 0o640)
            for path in ('/etc/xcli/security.key', '/etc/xcli/panel.env'):
                shutil.chown(path, 'root', 'xgateway')
            private_file('/etc/nginx/xcli-import-locations.conf', '', 0o644)
            private_file('/etc/nginx/xcli-webshare-locations.conf', data['webshare_locations'], 0o644)
            password = secrets.token_urlsafe(24)
            private_file('/etc/xcli/initial-admin.txt', f'URL: {data["settings"]["origin"]}/\nUsername: admin\nPassword: {password}\n')
            result = subprocess.run(['runuser', '-u', 'xgateway', '--', '/usr/local/lib/xcli/xcli-panel-init',
                                     '--experimental', '--database', '/var/lib/xcli/gateway.sqlite'],
                                    input=(password + '\n').encode(), stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=30)
            if result.returncode:
                raise RuntimeError('创建管理员数据库失败')
        else:
            self.directory('/etc/xcli-node', 0o750, group='xgateway')
            self.directory('/etc/xcli-node/tls', 0o750, group='xgateway')
            self.directory('/var/lib/xcli-node', 0o700, user='xgateway', group='xgateway')
            data = render.node(self.args.source, self.args.domain, self.args.public_ip, self.args.reality_sni,
                               key_output, self.args.public_port, self.resolvers, self.args.panel,
                               getattr(self.args, 'ipv6', False))
            for name, value in (('settings.json', data['settings']), ('core.json', data['core']), ('node.json', data['node'])):
                path = Path('/etc/xcli-node') / name
                write_json(path, value)
                shutil.chown(path, 'root', 'xgateway')
            write_json(Path('/etc/xcli-node/registration.json'), data['registration'], 0o600)
            private_file('/etc/xcli-node/revision', self.args.commit + '\n', 0o600)
        private_file('/usr/local/lib/xcli/firewall.sh', data['firewall'], 0o755)
        self.settings, self.nginx_text = data['settings'], data['nginx']
        self.install_units()

    def certificate(self):
        self.step('配置 HTTPS 证书')
        self.run(['systemctl', 'enable', '--now', 'xcli-firewall'])
        live = Path('/etc/letsencrypt/live') / self.args.domain
        if self.args.certificate:
            cert, key = self.args.certificate, self.args.private_key
            managed = (live / 'fullchain.pem').is_file() and (live / 'privkey.pem').is_file() \
                and os.path.samefile(cert, live / 'fullchain.pem') and os.path.samefile(key, live / 'privkey.pem')
        else:
            Path('/etc/nginx/nginx.conf').write_text(render.acme(self.args.source, self.settings,
                                                                getattr(self.args, 'ipv6', False)))
            self.run(['nginx', '-t'])
            self.run(['systemctl', 'enable', '--now', 'nginx'])
            contact = ['--register-unsafely-without-email'] if self.args.no_email else ['--email', self.args.email]
            self.run(['certbot', 'certonly', '--webroot', '-w', '/var/www/acme', '--cert-name', self.args.domain,
                      '-d', self.args.domain, *contact, '--agree-tos', '--non-interactive'], timeout=300)
            cert, key = live / 'fullchain.pem', live / 'privkey.pem'
            managed = True
        tls_dir = Path('/etc/xcli/hysteria-tls' if self.role == 'panel' else '/etc/xcli-node/tls')
        # Existing certificate validation is used only during installation;
        # the installed Certbot hook is the Rust renewal program.
        with tempfile.TemporaryDirectory(prefix='xcli-cert-install-') as temporary:
            install_tls(self.args.domain, cert, key, Path(temporary) / 'pair')
            pair = Path(temporary) / 'pair'
            private_file(tls_dir / 'bundle.pem', (pair / 'fullchain.pem').read_bytes() + b'\n' +
                         (pair / 'privkey.pem').read_bytes(), 0o640)
        shutil.chown(tls_dir / 'bundle.pem', 'root', 'xgateway')
        if managed:
            probe = pwd.getpwnam('xgprobe')
            command = ['/usr/local/lib/xcli/xcli-cert-renew', '--experimental', '--certbot-root', '/etc/letsencrypt',
                       '--lineage', self.args.domain, '--domain', self.args.domain, '--target', str(tls_dir / 'bundle.pem'),
                       '--validator-uid', str(probe.pw_uid), '--validator-gid', str(probe.pw_gid),
                       '--output-gid', str(grp.getgrnam('xgateway').gr_gid)]
            hook = Path('/etc/letsencrypt/renewal-hooks/deploy/xcli-rust')
            hook.parent.mkdir(parents=True, exist_ok=True)
            private_file(hook, '#!/bin/sh\nset -eu\n[ "${RENEWED_LINEAGE:-}" = ' + shlex.quote(str(live)) + ' ] || exit 0\n' +
                         shlex.join(command) + '\n/usr/sbin/nginx -t\n/usr/bin/systemctl reload nginx\n', 0o755)
            self.run(['systemctl', 'enable', '--now', 'certbot.timer'])
        core = '/etc/xcli/core.json' if self.role == 'panel' else '/etc/xcli-node/core.json'
        self.run(['runuser', '-u', 'xgateway', '--', '/usr/local/lib/xcli/xray', 'run', '-test', '-config', core])
        Path('/etc/nginx/nginx.conf').write_text(self.nginx_text)
        self.run(['nginx', '-t'])
        self.run(['systemctl', 'enable', '--now', 'nginx'])
        self.run(['systemctl', 'reload', 'nginx'])

    def start_and_verify(self):
        self.step('启动并检查实验服务')
        names = ['xcli-node'] if self.role == 'node' else ['xcli-core', 'xcli-panel', 'xcli-web', 'xcli-monitor', 'xcli-import', 'xcli-webshare']
        self.run(['systemctl', 'enable', '--now', *names])
        for name in names:
            self.run(['systemctl', 'is-active', '--quiet', name])
        if self.role == 'panel':
            for _ in range(30):
                if self.run(['curl', '-q', '-fsS', '--noproxy', '*', '--max-time', '2',
                             'http://127.0.0.1:8080/healthz'], check=False, timeout=3) == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError('面板未就绪')
            self.run(['curl', '-q', '-fsS', '--noproxy', '*', '--max-time', '10', '--resolve',
                      self.args.domain + ':' + str(self.args.public_port) + ':127.0.0.1',
                      self.settings['origin'] + '/healthz'], timeout=15)
        else:
            # The node can be healthy before it has been registered by a panel.
            self.run(['systemctl', 'is-active', '--quiet', 'xcli-node'])

    def execute(self):
        try:
            self.packages_and_build()
            key_output = self.install_programs()
            self.install_configuration(key_output)
            self.certificate()
            self.start_and_verify()
        except (Exception, KeyboardInterrupt):
            if self.packages_started:
                self.run(['sh', self.backup / 'rollback.sh'], check=False, timeout=90)
            print(f'安装在“{self.phase}”阶段停止；文件和日志保留于 {self.backup}', file=sys.stderr)
            raise
        if self.role == 'panel':
            print(f'实验面板已启动：{self.settings["origin"]}/\n管理员凭据：/etc/xcli/initial-admin.txt\n'
                  '配置：/etc/xcli/settings.json；数据：/var/lib/xcli/gateway.sqlite')
        else:
            print('实验节点已启动。请在已有面板中添加 /etc/xcli-node/registration.json 的内容。\n'
                  '节点配置：/etc/xcli-node/node.json；账本：/var/lib/xcli-node/traffic.sqlite')
        print(f'日志和停用脚本：{self.backup}\n实验安装尚未完成生产验收。')
        return 0


def use_rewrite_answers(args, role):
    install.use_cached_answers(args, role)
    # Old installation profiles may include features the rewrite installer
    # does not provide. Keep shared input defaults without inheriting them.
    if '--coexist' not in args.provided_options:
        args.coexist = False
    if '--tune-network' not in args.provided_options:
        args.tune_network = False
    if '--dns-relay-ip' not in args.provided_options:
        args.dns_relay_ip = None
    if not args.provided_options.intersection({'--bundle', '--sha256'}):
        args.bundle = args.sha256 = None


def main(argv=None):
    parser = argparse.ArgumentParser(description='实验性全新安装器；其余选项与旧安装器相同。')
    parser.add_argument('--experimental', action='store_true')
    parser.add_argument('--role', choices=('panel', 'node'), required=True)
    parser.add_argument('--release-dir', type=Path)
    parser.add_argument('--node-bin', type=Path)
    extra, rest = parser.parse_known_args(argv)
    if not extra.experimental:
        raise ValueError('此安装器仍在验证中，需要 --experimental')
    args = install.arguments(rest)
    args.source = args.source.resolve()
    use_rewrite_answers(args, extra.role)
    args.ipv6 = False
    def resolve_domain(domain, address):
        args.ipv6 = dualstack.resolve_domain(domain, address)
    install.resolve_domain = resolve_domain
    if args.coexist or args.bundle or args.dns_relay_ip or args.tune_network:
        raise ValueError('实验安装仅支持干净主机，不支持共存、旧发布包、DNS 转发和网络调优')
    # This installer does not install the legacy network-tuning service.
    args.tune_network = False
    for path in ('/etc/xcli', '/etc/xcli-node', '/var/lib/xcli-node', '/var/lib/xcli-import',
                 '/var/lib/xcli-monitor', '/etc/systemd/system/xcli-core.service',
                 '/etc/systemd/system/xcli-node.service', '/etc/letsencrypt/renewal-hooks/deploy/xcli-rust'):
        if Path(path).exists() or Path(path).is_symlink():
            raise ValueError('检测到已有配置：' + path)
    if extra.role == 'node':
        arch = install_node.node_preflight(args, ('deploy/templates/nginx.conf', 'rewrite/deploy/xcli-node.service.example'))
        resolvers = install_node.node_input(args)
    else:
        if args.panel:
            raise ValueError('--panel 仅用于节点模式')
        arch = install.preflight(args, ('deploy/templates/nginx.conf', 'rewrite/deploy/xcli-panel.service.example'))
        install.check_ports((18080,))
        resolvers = install.prepare_input(args)
    if args.check:
        install.save_checked_answers(args, extra.role)
        print('检查完成；没有安装程序或修改服务。')
        return 0
    release = extra.release_dir.resolve(strict=True) if extra.release_dir else None
    if not release or (release / 'BUILD_STATUS').read_text().strip() != 'experimental':
        raise ValueError('需要使用 rewrite/build-release.sh 构建的实验版本')
    if extra.role == 'panel':
        if not extra.node_bin:
            raise ValueError('面板安装需要 --node-bin')
        node_binary = extra.node_bin.resolve(strict=True)
        version = subprocess.check_output([node_binary, '-p', 'Number(process.versions.node.split(".")[0])'], text=True, timeout=10)
        if int(version.strip()) not in (24, 25, 26):
            raise ValueError('需要 Node.js 24–26')
    else:
        node_binary = None
    if not args.yes and install.ask('确认开始实验安装？输入 yes') != 'yes':
        raise ValueError('安装已取消')
    return Installer(args, arch, resolvers, extra.role, release, node_binary).execute()


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        print('安装停止：' + str(error), file=sys.stderr)
        raise SystemExit(1)
