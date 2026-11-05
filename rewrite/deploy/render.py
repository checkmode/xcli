"""Build the initial configuration for an experimental fresh installation.

The caller creates service accounts, directories, certificates and files.  This
module is also used by the isolated installation test; it does not alter the
machine or contact a remote service.
"""
from pathlib import Path
import importlib.util
import secrets
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deploy'))
from provision import core_config, hysteria_inbound, monitor_config, render_firewall, render_nginx, settings_for


def _core(settings, tls_dir, ipv6=False):
    core = core_config(settings)
    bundle = f'{tls_dir}/bundle.pem'
    core['inbounds'][-1] = hysteria_inbound(settings['hysteria2_port'], bundle, bundle)
    if ipv6:
        core['inbounds'][-1]['listen'] = '::'
    return core


def _dualstack_nginx(nginx, port, ipv6):
    if not ipv6:
        return nginx
    stream = 'server { listen ' + str(port) + ';'
    http = 'listen 80 default_server;'
    if nginx.count(stream) != 1 or nginx.count(http) != 1:
        raise ValueError('Nginx 模板缺少公网入口')
    return nginx.replace(stream, stream + ' listen [::]:' + str(port) + ' ipv6only=on;').replace(
        http, http + '\n        listen [::]:80 ipv6only=on default_server;')


def acme(source, settings, ipv6=False):
    nginx = render_nginx(source, settings)
    if ipv6:
        marker = 'listen 80 default_server;'
        if nginx.count(marker) != 1:
            raise ValueError('Nginx 模板缺少证书验证入口')
        nginx = nginx.replace(marker, marker + '\n        listen [::]:80 ipv6only=on default_server;')
    return nginx


def _firewall(address, resolvers, port, ipv6):
    firewall = render_firewall(address, resolvers, port)
    old_ports = '--dports 8080,10085,10080,10443'
    if firewall.count(old_ports) != 1:
        raise ValueError('防火墙模板缺少本机服务规则')
    firewall = firewall.replace(old_ports, old_ports + ',18080')
    if ipv6:
        start = ('    ip6tables -w -N XG6_IN 2>/dev/null || true\n'
                 '    ip6tables -w -F XG6_IN\n'
                 f'    ip6tables -w -A XG6_IN -p tcp -m multiport --dports 80,{port} -j ACCEPT\n'
                 f'    ip6tables -w -A XG6_IN -p udp --dport {port} -j ACCEPT\n'
                 '    ip6tables -w -C INPUT -j XG6_IN 2>/dev/null || ip6tables -w -I INPUT 1 -j XG6_IN\n')
        stop = ('    ip6tables -w -D INPUT -j XG6_IN 2>/dev/null || true\n'
                '    ip6tables -w -F XG6_IN 2>/dev/null || true\n'
                '    ip6tables -w -X XG6_IN 2>/dev/null || true\n')
        firewall = firewall.replace('start)\n', 'start)\n' + start).replace('stop)\n', 'stop)\n' + stop)
    return firewall


def panel(source, domain, address, sni, key_output, port, resolvers,
          panel_uid, panel_gid, probe_uid, probe_gid, ipv6=False):
    settings = settings_for(domain, address, sni, key_output, port)
    core = _core(settings, '/etc/xcli/hysteria-tls', ipv6)
    nginx = render_nginx(source, settings, '/etc/xcli/hysteria-tls/bundle.pem',
                         '/etc/xcli/hysteria-tls/bundle.pem')
    nginx = _dualstack_nginx(nginx, port, ipv6)
    marker = '        location = /api/login {'
    if nginx.count(marker) != 1:
        raise ValueError('Nginx 模板缺少固定代理入口')
    nginx = nginx.replace(marker, '        include /etc/nginx/xcli-import-locations.conf;\n' + marker)
    panel_location = '        location / {\n            proxy_pass http://127.0.0.1:8080;'
    if nginx.count(panel_location) != 1:
        raise ValueError('Nginx 模板缺少面板代理入口')
    nginx = nginx.replace(panel_location, panel_location + '\n            proxy_read_timeout 120s;')
    if port != 443:
        nginx = nginx.replace('return 301 https://' + settings['domain'] + '$request_uri;',
                              'return 301 https://' + settings['domain'] + ':' + str(port) + '$request_uri;')
    spec = importlib.util.spec_from_file_location('xcli_webshare_pool', source / 'deploy/webshare-pool.py')
    pool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pool)
    settings, core, nginx, firewall, webshare_locations = pool.configure(
        settings, core, nginx, _firewall(address, resolvers, port, ipv6))
    monitor = monitor_config(settings)
    identity = (panel_uid, panel_gid, probe_uid, probe_gid)
    if not all(type(value) is int and value > 0 for value in identity):
        raise ValueError('服务账户无效')
    worker = {
        'mode': 'apply', 'key': '/etc/xcli/security.key', 'inbox': '/var/lib/xcli/proxy-import',
        'state': '/var/lib/xcli-import/state', 'journal': '/var/lib/xcli-import/journal',
        'update_lock': '/var/lib/xcli-import/journal/update.lock',
        'report_directory': '/var/lib/xcli-import/report',
        'panel_uid': panel_uid, 'panel_gid': panel_gid, 'probe_uid': probe_uid, 'probe_gid': probe_gid,
        'targets': {'settings': '/etc/xcli/settings.json', 'core': '/etc/xcli/core.json',
                    'monitor': '/etc/xcli-monitor/monitor.json', 'nginx': '/etc/nginx/nginx.conf',
                    'locations': '/etc/nginx/xcli-import-locations.conf',
                    'pool': '/etc/xcli/imported-proxies.json'},
        'database': '/var/lib/xcli/gateway.sqlite',
        'core_pid_file': '/sys/fs/cgroup/system.slice/xcli-core.service/cgroup.procs',
        'core_api': '127.0.0.1:10085', 'panel_port': 18080,
        'monitor_report': '/var/lib/xcli-monitor/report.json', 'core_unit': 'xcli-core.service',
        'panel_unit': 'xcli-panel.service', 'monitor_unit': 'xcli-monitor.service',
    }
    environment = (f'XCLI_ORIGIN={settings["origin"]}\nXCLI_PROBE_UUID={monitor["uuid"]}\n'
                   f'XCLI_PANEL_GID={panel_gid}\n')
    return {'settings': settings, 'core': core,
            'monitor': monitor, 'nginx': nginx, 'worker': worker, 'environment': environment,
            'firewall': firewall, 'webshare_locations': webshare_locations}


def node(source, domain, address, sni, key_output, port, resolvers, panel_origin, ipv6=False):
    # Use the same URL validation as the existing independent node installer.
    from install_node import panel_origin as validate_panel_origin, nginx_config
    settings = settings_for(domain, address, sni, key_output, port)
    origin = validate_panel_origin(panel_origin)
    node_id, token = secrets.token_hex(16), secrets.token_urlsafe(32)
    registration = {'version': 1, 'id': node_id, 'key': token, 'public_ip': settings['public_ip'],
                    'domain': settings['domain'], 'public_port': port, 'reality_sni': settings['reality_sni'],
                    'reality_public': settings['reality_public'], 'short_id': settings['short_id'],
                    'ws_path': settings['ws_path'], 'hysteria2_port': port}
    nginx = nginx_config(source, settings, True).replace('/etc/xcli-node/tls/fullchain.pem',
                                                        '/etc/xcli-node/tls/bundle.pem')
    nginx = nginx.replace('/etc/xcli-node/tls/privkey.pem', '/etc/xcli-node/tls/bundle.pem')
    nginx = _dualstack_nginx(nginx, port, ipv6)
    return {'settings': settings, 'core': _core(settings, '/etc/xcli-node/tls', ipv6), 'nginx': nginx,
            'node': {'node_id': node_id, 'token': token, 'panel': origin}, 'registration': registration,
            'firewall': _firewall(address, resolvers, port, ipv6)}
