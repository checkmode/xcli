"""Validated configuration generation and first administrator initialization."""
import contextlib
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import secrets
import sqlite3
import uuid

XRAY_VERSION = '26.10.21'
XRAY_ASSETS = {
    'x86_64': ('Xray-linux-64.zip', '0eec3ed4163c273d8c8bf821f7d219e257921cf584aa3fb970715e458e631978'),
    'aarch64': ('Xray-linux-arm64-v8a.zip', 'd1304946c486d98e6b886e9b931eaaaebb23835b30e217638037b7f2721d4e9c'),
}
BLOCKED_V4 = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
              '172.16.0.0/12', '192.168.0.0/16', '192.0.0.0/24', '192.0.2.0/24', '198.18.0.0/15',
              '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4']


def domain_name(value):
    value = value.strip().lower().rstrip('.')
    labels = value.split('.')
    if len(value) > 253 or len(labels) < 2 or not re.fullmatch(r'[a-z][a-z0-9-]*', labels[-1]):
        raise ValueError('请填写域名，不要包含协议、端口、路径或通配符')
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in labels):
        raise ValueError('域名格式不正确；国际化域名请使用 Punycode')
    return value


def public_ipv4(value):
    address = ipaddress.ip_address(value.strip())
    if address.version != 4 or not address.is_global or address.is_multicast:
        raise ValueError('需要可路由的公网 IPv4 地址')
    return str(address)


def settings_for(domain, address, sni, key_output):
    domain, address, sni = domain_name(domain), public_ipv4(address), domain_name(sni)
    if domain == sni:
        raise ValueError('REALITY 目标域名不能与面板域名相同')
    fields = dict(line.split(':', 1) for line in key_output.splitlines() if ':' in line)
    private = fields.get('PrivateKey', '').strip()
    public = next((fields[key].strip() for key in ('Password (PublicKey)', 'Password', 'PublicKey') if key in fields), '')
    if not all(re.fullmatch(r'[A-Za-z0-9_-]{43}', value) for value in (private, public)):
        raise ValueError('Xray 未返回预期的 X25519 密钥')
    return {'domain': domain, 'origin': 'https://' + domain, 'public_ip': address, 'reality_sni': sni,
            'reality_private': private, 'reality_public': public, 'short_id': secrets.token_hex(8),
            'ws_path': '/connect/' + secrets.token_hex(12), 'hysteria2_port': 443, 'xray_version': XRAY_VERSION}


def core_config(settings):
    s = settings
    result = {'log': {'loglevel': 'warning', 'access': 'none'},
        'api': {'tag': 'api', 'listen': '127.0.0.1:10085', 'services': ['HandlerService', 'StatsService']},
        'stats': {}, 'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True, 'handshake': 8, 'connIdle': 300}}},
        'inbounds': [
            {'tag': 'reality', 'listen': '127.0.0.1', 'port': 10443, 'protocol': 'vless',
             'settings': {'clients': [], 'decryption': 'none'}, 'streamSettings': {'network': 'tcp', 'security': 'reality',
                 'tcpSettings': {'acceptProxyProtocol': True}, 'realitySettings': {'show': False,
                    'target': s['reality_sni'] + ':443', 'xver': 0, 'serverNames': [s['reality_sni']],
                    'privateKey': s['reality_private'], 'shortIds': [s['short_id']], 'maxTimeDiff': 120000}}},
            {'tag': 'websocket', 'listen': '127.0.0.1', 'port': 10080, 'protocol': 'vless',
             'settings': {'clients': [], 'decryption': 'none'},
             'streamSettings': {'network': 'ws', 'wsSettings': {'path': s['ws_path']}}}],
        'outbounds': [{'tag': 'direct', 'protocol': 'freedom', 'streamSettings': {'sockopt': {'domainStrategy': 'UseIPv4'}}},
                      {'tag': 'blocked', 'protocol': 'blackhole'}],
        'routing': {'domainStrategy': 'IPOnDemand', 'rules': [{'type': 'field', 'outboundTag': 'blocked',
            'ip': BLOCKED_V4 + [s['public_ip'] + '/32', '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8']}]}}
    if s.get('hysteria2_port', 0):
        result['inbounds'].append(hysteria_inbound(s['hysteria2_port']))
    return result


def hysteria_inbound(port=443, certificate='/etc/xray-gateway/hysteria-tls/fullchain.pem',
                     private_key='/etc/xray-gateway/hysteria-tls/privkey.pem'):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Hysteria 2 端口必须为 1..65535')
    return {'tag': 'hysteria2', 'listen': '0.0.0.0', 'port': port, 'protocol': 'hysteria',
        # Empty persisted users; the controller adds accounts through HandlerService.
        'settings': {'version': 2, 'clients': []},
        'streamSettings': {'network': 'hysteria', 'security': 'tls',
            'hysteriaSettings': {'version': 2},
            'tlsSettings': {'alpn': ['h3'], 'certificates': [
                {'certificateFile': str(certificate), 'keyFile': str(private_key), 'oneTimeLoading': False}]},
            'finalmask': {'quicParams': {'congestion': 'bbr'}}}}


def monitor_config(settings):
    result = {key: settings[key] for key in ('domain', 'public_ip', 'reality_sni', 'reality_public', 'short_id', 'ws_path')}
    result['uuid'] = str(uuid.uuid4())
    if settings.get('hysteria2_port', 0):
        result['hysteria2_port'] = settings['hysteria2_port']
    return result


def render_nginx(source, settings, certificate=None, private_key=None):
    name = 'nginx.conf' if certificate else 'nginx-acme.conf'
    text = (source / 'deploy' / 'templates' / name).read_text()
    values = {'DOMAIN': domain_name(settings['domain']), 'SNI': domain_name(settings['reality_sni']),
              'WS_PATH': settings['ws_path'], 'CERTIFICATE': certificate or '', 'PRIVATE_KEY': private_key or ''}
    if not re.fullmatch(r'/connect/[0-9a-f]{24}', values['WS_PATH']):
        raise ValueError('WebSocket 路径格式不正确')
    for key in ('CERTIFICATE', 'PRIVATE_KEY'):
        if values[key] and not re.fullmatch(r'/[a-zA-Z0-9_./-]+', str(values[key])):
            raise ValueError('证书安装路径格式不正确')
    for key, value in values.items():
        text = text.replace('@@' + key + '@@', str(value))
    if '@@' in text:
        raise ValueError('配置模板含有未替换字段')
    return text


def render_firewall(address, resolvers):
    address = public_ipv4(address)
    dns = sorted({str(ipaddress.IPv4Address(value)) for value in resolvers})
    # Only the system's actual IPv4 DNS servers can bypass private-destination filtering on port 53.
    exceptions = '\n'.join('    iptables -w -A XG_OUT -d ' + value + '/32 -p ' + protocol + ' --dport 53 -j RETURN'
                           for value in dns for protocol in ('udp', 'tcp'))
    networks = ' '.join(BLOCKED_V4 + [address + '/32'])
    return '''#!/bin/sh
set -eu
case "${1:-start}" in
start)
    iptables -w -N XG_IN 2>/dev/null || true
    iptables -w -F XG_IN
    iptables -w -A XG_IN -p tcp -m multiport --dports 80,443 -j ACCEPT
    iptables -w -A XG_IN -p udp --dport 443 -j ACCEPT
    iptables -w -C INPUT -j XG_IN 2>/dev/null || iptables -w -I INPUT 1 -j XG_IN
    iptables -w -N XG_OUT 2>/dev/null || true
    iptables -w -F XG_OUT
@@DNS@@
    iptables -w -A XG_OUT -d 127.0.0.1/32 -p tcp -m multiport --dports 8080,10085,10080,10443 -j RETURN
    iptables -w -A XG_OUT -m addrtype --dst-type LOCAL -j REJECT
    for net in @@NETWORKS@@; do iptables -w -A XG_OUT -d "$net" -j REJECT; done
    iptables -w -C OUTPUT -m owner --uid-owner xgateway -m conntrack --ctstate NEW -j XG_OUT 2>/dev/null || iptables -w -I OUTPUT 1 -m owner --uid-owner xgateway -m conntrack --ctstate NEW -j XG_OUT
    ip6tables -w -C OUTPUT -m owner --uid-owner xgateway -m conntrack --ctstate NEW -j REJECT 2>/dev/null || ip6tables -w -I OUTPUT 1 -m owner --uid-owner xgateway -m conntrack --ctstate NEW -j REJECT
    ;;
stop)
    iptables -w -D INPUT -j XG_IN 2>/dev/null || true
    iptables -w -D OUTPUT -m owner --uid-owner xgateway -m conntrack --ctstate NEW -j XG_OUT 2>/dev/null || true
    ip6tables -w -D OUTPUT -m owner --uid-owner xgateway -m conntrack --ctstate NEW -j REJECT 2>/dev/null || true
    iptables -w -F XG_IN 2>/dev/null || true
    iptables -w -X XG_IN 2>/dev/null || true
    iptables -w -F XG_OUT 2>/dev/null || true
    iptables -w -X XG_OUT 2>/dev/null || true
    ;;
*) exit 2 ;;
esac
'''.replace('@@DNS@@', exceptions).replace('@@NETWORKS@@', networks)


def private_file(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(data.encode() if isinstance(data, str) else data)


def initialize_admin(database, credentials, domain):
    """Create only the admin table. The C++ backend creates the remaining schema at first start."""
    if database.exists() or credentials.exists():
        raise ValueError('管理员凭据或数据库已存在，拒绝覆盖')
    password = secrets.token_urlsafe(24)
    salt = secrets.token_bytes(16)
    encoded = salt.hex() + ':' + hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32).hex()
    private_file(database, b'')
    with contextlib.closing(sqlite3.connect(database)) as db, db:
        db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY CHECK(id=1),password TEXT NOT NULL)')
        db.execute('INSERT INTO admin VALUES(1,?)', (encoded,))
    private_file(credentials, 'URL: https://' + domain_name(domain) + '/\nUsername: admin\nPassword: ' + password + '\n')


def write_json(path, value, mode=0o640):
    private_file(path, json.dumps(value, ensure_ascii=False, indent=2) + '\n', mode)
