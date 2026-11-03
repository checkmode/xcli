#!/usr/bin/env python3
"""Fresh independent node installer. Never run over an existing deployment."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import sys
import time
import zipfile

import install
from provision import XRAY_ASSETS, XRAY_VERSION, core_config, hysteria_inbound, private_file, render_firewall, settings_for, write_json
from certificate import install_tls


def panel_origin(value):
    # Same validation as the installed controller; avoids non-TLS and URL credentials.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
    from node_agent import panel_url
    return panel_url(value)


def node_preflight(args):
    if args.coexist or args.bundle or args.dns_relay_ip or args.tune_network:
        raise ValueError('节点模式暂不支持共存、预构建面板包、DNS 转发或网络调优')
    for path in ('/etc/xcli-node', '/var/lib/xcli-node', '/usr/local/lib/xcli-node',
                 '/etc/systemd/system/xcli-node.service', '/etc/systemd/system/xcli-node-firewall.service',
                 '/etc/letsencrypt/renewal-hooks/deploy/xcli-node'):
        p = Path(path)
        if p.exists() or p.is_symlink():
            raise ValueError('拒绝覆盖已有节点配置：' + path)
    for name in ('scripts/node_agent.py', 'scripts/node_ledger.py', 'deploy/templates/node-nginx.conf',
                 'deploy/node_certificate.py', 'deploy/xcli-node.service', 'deploy/xcli-node-firewall.service'):
        if not (args.source / name).is_file():
            raise ValueError('源码包不完整：' + name)
    return install.preflight(args)


def node_input(args):
    args.panel = panel_origin(args.panel or (install.ask('已有面板 HTTPS 地址（例如 https://panel.example.com）', check_only=args.check) if not args.yes else ''))
    # The generic installer asks about network tuning; node mode does not change host sysctls.
    args.tune_network = False
    return install.prepare_input(args, role='node')


def nginx_config(source, settings, tls):
    template = 'node-nginx.conf' if tls else 'nginx-acme.conf'
    result = (source / 'deploy' / 'templates' / template).read_text()
    values = {'DOMAIN': settings['domain'], 'SNI': settings['reality_sni'],
              'PUBLIC_PORT': str(settings.get('public_port', 443)), 'WS_PATH': settings['ws_path'],
              'CERTIFICATE': '/etc/xcli-node/tls/fullchain.pem', 'PRIVATE_KEY': '/etc/xcli-node/tls/privkey.pem'}
    for key, value in values.items():
        result = result.replace('@@' + key + '@@', value)
    if '@@' in result:
        raise ValueError('节点 Nginx 模板含未替换字段')
    return result


class NodeInstaller(install.Installer):
    def rollback_script(self):
        private_file(self.backup / 'rollback.sh', '''#!/bin/sh
# Stops only this new node; keeps its files, identity, certificate and logs.
set -u
systemctl disable --now xcli-node 2>/dev/null || true
systemctl disable --now xcli-node-firewall 2>/dev/null || true
systemctl disable --now nginx 2>/dev/null || true
if [ -f "$(dirname "$0")/nginx.conf.before" ]; then cp "$(dirname "$0")/nginx.conf.before" /etc/nginx/nginx.conf; fi
echo '节点服务已停止；身份、配置、证书、账本及系统软件包均保留。'
''', 0o700)

    def packages_and_build(self):
        self.step('安装节点系统依赖')
        self.rollback_script()
        self.packages_started = True
        self.run(['apt-get', 'update'])
        self.run(['apt-get', 'install', '-y', '--no-install-recommends', 'python3', 'nginx',
                  'libnginx-mod-stream', 'certbot', 'ca-certificates', 'curl', 'openssl', 'iptables', 'iproute2'])
        self.copy('/etc/nginx/nginx.conf', self.backup / 'nginx.conf.before', 0o600)
        self.run(['systemctl', 'stop', 'nginx'])
        self.run(['groupadd', '--system', 'xgateway'])
        self.run(['useradd', '--system', '--no-create-home', '--home-dir', '/var/lib/xcli-node',
                  '--shell', '/usr/sbin/nologin', '--gid', 'xgateway', 'xgateway'])

    def install_files(self):
        self.step('安装受校验的 Xray 并生成节点身份')
        base = self.directory('/usr/local/lib/xcli-node')
        asset, digest = XRAY_ASSETS[self.arch]
        archive = self.args.source.parent / 'node-xray.zip'
        self.run(['curl', '-q', '--proto', '=https', '--tlsv1.2', '-fsSL', '--retry', '3',
                  '--connect-timeout', '10', '--max-time', '180',
                  f'https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/{asset}', '-o', archive])
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            raise ValueError('Xray 文件的 SHA-256 不匹配，停止安装')
        with zipfile.ZipFile(archive) as zipped:
            private_file(base / 'xray', zipped.read('xray'), 0o755)
        for name in ('node_agent.py', 'node_ledger.py'):
            self.copy(self.args.source / 'scripts' / name, base / name)
        for name in ('certificate.py', 'node_certificate.py'):
            self.copy(self.args.source / 'deploy' / name, base / name)
        config = self.directory('/etc/xcli-node', 0o750, group='xgateway')
        self.directory('/var/lib/xcli-node', 0o700, user='xgateway', group='xgateway')
        key_output = self.run([base / 'xray', 'x25519'], capture=True).decode()
        settings = settings_for(self.args.domain, self.args.public_ip, self.args.reality_sni, key_output, self.args.public_port)
        core = core_config(settings)
        core['inbounds'][-1] = hysteria_inbound(self.args.public_port, '/etc/xcli-node/tls/fullchain.pem', '/etc/xcli-node/tls/privkey.pem')
        node_id, token = secrets.token_hex(16), secrets.token_urlsafe(32)
        registration = {'version': 1, 'id': node_id, 'key': token, 'public_ip': settings['public_ip'],
                        'domain': settings['domain'], 'public_port': self.args.public_port,
                        'reality_sni': settings['reality_sni'], 'reality_public': settings['reality_public'],
                        'short_id': settings['short_id'], 'ws_path': settings['ws_path'], 'hysteria2_port': self.args.public_port}
        write_json(config / 'settings.json', settings)
        write_json(config / 'core.json', core)
        write_json(config / 'node.json', {'node_id': node_id, 'token': token, 'panel': self.args.panel})
        write_json(config / 'registration.json', registration, 0o600)
        write_json(config / 'installation.json', {'commit': self.args.commit, 'architecture': self.arch,
                    'xray': XRAY_VERSION, 'installed': int(time.time()),
                    'certificate': 'provided' if self.args.certificate else 'letsencrypt'}, 0o600)
        for name in ('settings.json', 'core.json', 'node.json'):
            shutil.chown(config / name, 'root', 'xgateway')
        private_file(base / 'firewall.sh', render_firewall(self.args.public_ip, self.resolvers, self.args.public_port), 0o755)
        for tool, name in (('iptables-save', 'iptables.v4.before'), ('ip6tables-save', 'iptables.v6.before')):
            private_file(self.backup / name, self.run([tool], capture=True))
        for service in ('xcli-node', 'xcli-node-firewall'):
            self.copy(self.args.source / 'deploy' / (service + '.service'), Path('/etc/systemd/system') / (service + '.service'))
        self.run(['systemctl', 'daemon-reload'])
        self.settings = settings

    def node_nginx(self, tls):
        target = Path('/etc/nginx/nginx.conf')
        new = target.with_suffix('.conf.xcli-node-new')
        private_file(new, nginx_config(self.args.source, self.settings, tls), 0o644)
        new.replace(target)
        self.run(['nginx', '-t'])

    def certificate(self):
        self.step('配置节点 HTTPS 证书')
        self.run(['systemctl', 'enable', '--now', 'xcli-node-firewall'])
        self.directory('/var/www/acme')
        if self.args.certificate:
            cert, key = self.args.certificate, self.args.private_key
        else:
            self.node_nginx(False)
            self.run(['systemctl', 'enable', '--now', 'nginx'])
            contact = ['--register-unsafely-without-email'] if self.args.no_email else ['--email', self.args.email]
            self.run(['certbot', 'certonly', '--webroot', '-w', '/var/www/acme', '--cert-name', self.args.domain,
                      '-d', self.args.domain, *contact, '--agree-tos', '--non-interactive'], timeout=300)
            live = Path('/etc/letsencrypt/live') / self.args.domain
            cert, key = live / 'fullchain.pem', live / 'privkey.pem'
            hook = self.directory('/etc/letsencrypt/renewal-hooks/deploy') / 'xcli-node'
            private_file(hook, '#!/bin/sh\nset -eu\n/usr/bin/python3 /usr/local/lib/xcli-node/node_certificate.py\n'
                         '/usr/sbin/nginx -t\n/usr/bin/systemctl reload nginx\n', 0o755)
            self.run(['systemctl', 'enable', '--now', 'certbot.timer'])
        install_tls(self.args.domain, cert, key, Path('/etc/xcli-node/tls'), 'xgateway')
        self.run(['runuser', '-u', 'xgateway', '--', '/usr/local/lib/xcli-node/xray', 'run', '-test',
                  '-config', '/etc/xcli-node/core.json'])
        self.node_nginx(True)
        self.run(['systemctl', 'enable', '--now', 'nginx'])
        self.run(['systemctl', 'reload', 'nginx'])

    def execute(self):
        try:
            self.packages_and_build()
            self.install_files()
            self.certificate()
            self.step('启动独立节点')
            self.run(['systemctl', 'enable', '--now', 'xcli-node'])
            self.run(['systemctl', 'is-active', '--quiet', 'nginx'])
            for _ in range(20):
                self.run(['systemctl', 'is-active', '--quiet', 'xcli-node'])
                code = self.run(['runuser', '-u', 'xgateway', '--', '/usr/local/lib/xcli-node/xray', 'api',
                                 'inboundusercount', '--server=127.0.0.1:10085', '-tag=reality', '--timeout=1'],
                                check=False, timeout=3)
                if code == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError('节点核心管理接口未就绪')
        except (Exception, KeyboardInterrupt):
            if self.packages_started:
                self.run(['sh', self.backup / 'rollback.sh'], check=False, timeout=90)
            print(f'安装在“{self.phase}”阶段停止；新服务已停用，配置保留。日志及停用脚本：{self.backup}', file=sys.stderr)
            raise
        print('\n独立节点已安装。节点尚未获得任何用户授权。\n'
              '请在节点终端查看注册信息：sudo cat /etc/xcli-node/registration.json\n'
              '登录已有面板 → 接入节点 → 添加服务器，粘贴完整 JSON 并选择允许访问的用户。\n'
              '注册信息包含密钥，请通过可信渠道传递，勿公开。\n'
              '节点配置：/etc/xcli-node/node.json；Xray 配置：/etc/xcli-node/core.json\n'
              '用量账本：/var/lib/xcli-node/traffic.sqlite\n'
              '运行状态：systemctl status xcli-node；日志：journalctl -u xcli-node\n'
              f'安装日志与停用脚本：{self.backup}\n'
              + ('自备证书需要按原有方式更新 /etc/xcli-node/tls 并重载 Nginx。\n' if self.args.certificate else ''), flush=True)
        return 0


def main(argv=None):
    args = install.arguments(argv)
    args.source = args.source.resolve()
    arch = node_preflight(args)
    resolvers = node_input(args)
    print(f'检查通过：Ubuntu {platform.freedesktop_os_release()["VERSION_ID"]} / {arch}\n'
          f'节点域名：{args.domain}；公网 IPv4：{args.public_ip}；面板：{args.panel}\n'
          f'将安装 Xray、节点代理、Nginx、证书和专属防火墙规则。请开放 TCP 80/{args.public_port} 和 UDP {args.public_port}。', flush=True)
    if args.check:
        print('仅检查模式结束，没有安装或修改系统配置。')
        return 0
    if not args.yes and install.ask('确认开始安装？输入 yes') != 'yes':
        raise ValueError('安装已取消')
    return NodeInstaller(args, arch, resolvers).execute()


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, OSError, KeyboardInterrupt) as error:
        print('安装停止：' + str(error), file=sys.stderr)
        raise SystemExit(1)
