"""Exercise revocation and accounting on a disposable Xray core, never production."""
import contextlib
import http.server
import importlib.util
import json
import os
import pathlib
import socket
import sqlite3
import struct
import subprocess
import threading
import time
import pytest

from test_http import BINARY, LEGACY, PASSWORD, ORIGIN, Client, available_port

XRAY = pathlib.Path(os.environ.get('XG_TEST_XRAY', '/usr/local/lib/xray-gateway/xray'))


def eventually(check, seconds=15):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            if check():
                return
        except (OSError, ValueError, AssertionError):
            pass
        time.sleep(.15)
    raise AssertionError('Isolated test condition did not become true')


def udp_roundtrip(proxy, target, payload):
    def read(sock, size):
        result = b''
        while len(result) < size:
            part = sock.recv(size - len(result))
            assert part, 'SOCKS control connection closed'
            result += part
        return result
    with socket.create_connection(('127.0.0.1', int(proxy.rsplit(':', 1)[1])), timeout=3) as control:
        control.settimeout(3)
        control.sendall(b'\x05\x01\x00')
        assert read(control, 2) == b'\x05\x00'
        control.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
        assert read(control, 4) == b'\x05\x00\x00\x01'
        address, port = socket.inet_ntoa(read(control, 4)), struct.unpack('!H', read(control, 2))[0]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(5)
            udp.connect((address if address != '0.0.0.0' else '127.0.0.1', port))
            head = b'\x00\x00\x00\x01' + socket.inet_aton(target[0]) + struct.pack('!H', target[1])
            udp.send(head + payload)
            assert udp.recv(65535) == head + payload[::-1], 'Native UDP payload changed'


def test_real_grpc_accounting_and_live_revocation(tmp_path):
    state = tmp_path / 'state'
    api_port, reality_port, ws_port, hy2_port, panel_port = [available_port() for _ in range(5)]
    core_pid_file = tmp_path / 'core.pid'
    keys = subprocess.check_output([str(XRAY), 'x25519'], text=True)
    keys = dict(line.split(':', 1) for line in keys.splitlines() if ':' in line)
    private = keys['PrivateKey'].strip()
    public = keys.get('Password (PublicKey)', keys.get('Password', keys.get('PublicKey', ''))).strip()
    assert public
    short_id = 'aabbccddeeff0011'
    config = {'log': {'loglevel': 'warning'},
        'api': {'tag': 'api', 'listen': '127.0.0.1:' + str(api_port), 'services': ['HandlerService', 'StatsService']},
        'stats': {}, 'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True}}},
        'inbounds': [
            {'tag': 'reality', 'listen': '127.0.0.1', 'port': reality_port, 'protocol': 'vless',
             'settings': {'clients': [], 'decryption': 'none'},
             'streamSettings': {'network': 'tcp', 'security': 'reality',
                 'realitySettings': {'target': 'www.bing.com:443', 'serverNames': ['www.bing.com'], 'privateKey': private, 'shortIds': [short_id]}}},
            {'tag': 'websocket', 'listen': '127.0.0.1', 'port': ws_port, 'protocol': 'vless',
             'settings': {'clients': [], 'decryption': 'none'}, 'streamSettings': {'network': 'ws', 'wsSettings': {'path': '/isolated-test'}}}],
        # The origin and UDP echo server exist only in this isolated fixture.
        # New Xray cores block private destinations unless explicitly allowed.
        'outbounds': [{'protocol': 'freedom', 'settings': {'finalRules': [
            {'action': 'allow', 'ip': ['127.0.0.1/32']}]}}]}
    # A local trust anchor keeps certificate verification enabled in the QUIC client.
    cert, key = tmp_path / 'hy2.crt', tmp_path / 'hy2.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=testserver', '-addext', 'subjectAltName=DNS:testserver',
        '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', str(key), '-out', str(cert)],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    config['inbounds'].append({'tag': 'hysteria2', 'listen': '127.0.0.1', 'port': hy2_port,
        'protocol': 'hysteria', 'settings': {'version': 2, 'clients': []},
        'streamSettings': {'network': 'hysteria', 'security': 'tls', 'hysteriaSettings': {'version': 2},
            'tlsSettings': {'alpn': ['h3'], 'certificates': [{'certificateFile': str(cert), 'keyFile': str(key)}]},
            'finalmask': {'quicParams': {'congestion': 'bbr'}}}})
    residence_ports = {tag: available_port() for tag in ('residential-01', 'residential-02')}
    upstream_port, broken_port = available_port(), available_port()
    config['outbounds'][0]['tag'] = 'direct'
    config['outbounds'].append({'tag': 'blocked', 'protocol': 'blackhole'})
    config['routing'] = {'rules': []}
    residence = []
    for index, (tag, port) in enumerate(residence_ports.items()):
        path = '/isolated-test/' + tag
        residence.append({'tag': tag, 'label': tag, 'exit_ip': '8.8.4.4', 'country': 'US', 'ws_path': path, 'port': port})
        config['inbounds'].append({'tag': tag, 'listen': '127.0.0.1', 'port': port, 'protocol': 'vless',
            'settings': {'clients': [], 'decryption': 'none'}, 'streamSettings': {'network': 'ws', 'wsSettings': {'path': path}}})
        config['outbounds'].append({'tag': tag + '-exit', 'protocol': 'socks', 'settings': {'servers': [
            {'address': '127.0.0.1', 'port': upstream_port if index == 0 else broken_port,
             'users': [{'user': 'fixture-user', 'pass': 'fixture-password'}]}]}})
        config['routing']['rules'].extend([
            {'type': 'field', 'inboundTag': [tag], 'network': 'udp', 'outboundTag': 'blocked'},
            {'type': 'field', 'inboundTag': [tag], 'network': 'tcp', 'outboundTag': tag + '-exit'}])
    core_config = tmp_path / 'core.json'
    core_config.write_text(json.dumps(config));core_config.chmod(0o600)
    settings = tmp_path / 'settings.json'
    settings.write_text(json.dumps({'origin': ORIGIN, 'domain': 'testserver', 'public_ip': '127.0.0.1',
        'reality_sni': 'www.bing.com', 'reality_public': public, 'short_id': short_id, 'ws_path': '/isolated-test', 'hysteria2_port': hy2_port,
        'residential_exits': residence}))
    settings.chmod(0o600)
    spec = importlib.util.spec_from_file_location('legacy_core_test', LEGACY)
    legacy = importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
    legacy.STATE = state;legacy.SETTINGS = settings;legacy.init_db()
    with legacy.db() as db:
        db.execute('INSERT INTO admin VALUES(1,?)', (legacy.password_hash(PASSWORD),))

    stop = threading.Event()
    processes = []
    core_log = (tmp_path / 'core.log').open('wb')
    panel_log = (tmp_path / 'panel.log').open('wb')
    core_error = []
    upstream_cfg = tmp_path / 'upstream.json'
    upstream_cfg.write_text(json.dumps({'log': {'loglevel': 'none'},
        'inbounds': [{'listen': '127.0.0.1', 'port': upstream_port, 'protocol': 'socks',
                      'settings': {'auth': 'password', 'accounts': [{'user': 'fixture-user', 'pass': 'fixture-password'}]}}],
        'outbounds': [config['outbounds'][0]]}))
    upstream_cfg.chmod(0o600)
    upstream = subprocess.Popen([str(XRAY), 'run', '-config', str(upstream_cfg)], stdout=core_log, stderr=core_log)
    processes.append(upstream)
    def supervise():
        try:
            while not stop.is_set():
                core = subprocess.Popen([str(XRAY), 'run', '-config', str(core_config)], stdout=core_log, stderr=core_log)
                core_pid_file.write_text(str(core.pid));core_pid_file.chmod(0o600)
                while core.poll() is None and not stop.wait(.05):
                    pass
                if core.poll() is None:
                    core.terminate();core.wait(timeout=5)
                stop.wait(.1)
        except Exception as error:
            core_error.append(type(error).__name__)
    supervisor = threading.Thread(target=supervise)
    supervisor.start()

    payload = os.urandom(262144)
    class Origin(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            data = payload if self.path == '/blob' else payload * 128
            self.send_response(200);self.send_header('Content-Length', str(len(data)));self.end_headers()
            with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                for i in range(0, len(data), 16384):
                    self.wfile.write(data[i:i+16384]);self.wfile.flush()
                    if self.path != '/blob':
                        time.sleep(.025)
    origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    origin.daemon_threads = True
    serving = threading.Thread(target=origin.serve_forever);serving.start()
    base = 'http://127.0.0.1:' + str(origin.server_port)
    echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    echo.bind(('127.0.0.1', 0));echo.settimeout(.2)
    def echo_loop():
        while not stop.is_set():
            try:
                data, peer = echo.recvfrom(65535)
                echo.sendto(data[::-1], peer)
            except socket.timeout:
                pass
            except OSError:
                break
    echo_thread = threading.Thread(target=echo_loop);echo_thread.start()

    def start_panel():
        proc = subprocess.Popen([str(BINARY), '--state', str(state), '--settings', str(settings),
            '--static', str(LEGACY.parent / 'static'), '--port', str(panel_port), '--poll-seconds', '1',
            '--api', '127.0.0.1:' + str(api_port), '--core-binary', str(XRAY), '--core-pid-file', str(core_pid_file)],
            stdout=panel_log, stderr=panel_log)
        processes.append(proc)
        return proc
    def db_user(uid):
        with legacy.db() as db:
            return dict(legacy.get_user(db, uid))
    def counter_value(pattern):
        with legacy.db() as db:
            row = db.execute('SELECT value FROM counters WHERE name LIKE ?', (pattern,)).fetchone()
            return row[0] if row else 0
    def live_count(tag):
        response = subprocess.run([str(XRAY), 'api', 'inbounduser', '--server=127.0.0.1:' + str(api_port), '--timeout=2', '-tag=' + tag], capture_output=True)
        if response.returncode:
            return -1
        return len(json.loads(response.stdout).get('users', []))
    def start_client(user, kind):
        port = available_port()
        account = {'id': user['uuid'], 'encryption': 'none'}
        if kind == 'reality':
            account['flow'] = 'xtls-rprx-vision'
            stream = {'network': 'tcp', 'security': 'reality', 'realitySettings':
                      {'serverName': 'www.bing.com', 'fingerprint': 'chrome', 'publicKey': public, 'shortId': short_id}}
        else:
            stream = {'network': 'ws', 'security': 'none', 'wsSettings': {'path': '/isolated-test' + ('/' + kind if kind in residence_ports else '')}}
        cfg = {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True}}],
            'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{'address': '127.0.0.1',
                'port': reality_port if kind == 'reality' else residence_ports.get(kind, ws_port), 'users': [account]}]}, 'streamSettings': stream}]}
        if kind == 'hysteria2':
            cfg['outbounds'] = [{'protocol': 'hysteria', 'settings': {'version': 2, 'address': '127.0.0.1', 'port': hy2_port},
                'streamSettings': {'network': 'hysteria', 'security': 'tls',
                    'hysteriaSettings': {'version': 2, 'auth': user['uuid']},
                    'tlsSettings': {'serverName': 'testserver', 'allowInsecure': False, 'alpn': ['h3'],
                        'disableSystemRoot': True, 'certificates': [{'certificateFile': str(cert), 'usage': 'verify'}]},
                    'finalmask': {'quicParams': {'congestion': 'bbr'}}}}]
        path = tmp_path / ('client-' + str(port) + '.json')
        path.write_text(json.dumps(cfg));path.chmod(0o600)
        process = subprocess.Popen([str(XRAY), 'run', '-config', str(path)], stdout=core_log, stderr=core_log)
        processes.append(process)
        def listening():
            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                return True
        eventually(listening)
        return 'socks5h://127.0.0.1:' + str(port)
    def fetch(proxy, target='/blob', timeout=8):
        return subprocess.run(['curl', '--noproxy', '', '--proxy', proxy, '-fsS', '--max-time', str(timeout), base + target], capture_output=True)

    panel = None
    try:
        eventually(lambda: core_pid_file.exists() and live_count('reality') == 0)
        panel = start_panel()
        client = Client(panel_port)
        eventually(lambda: client.call('/healthz')[0] == 200)
        client.login()
        uid = client.json('/api/users', 'POST', {'name': 'integration-one'})['id']
        uid2 = client.json('/api/users', 'POST', {'name': 'integration-two'})['id']
        eventually(lambda: all(live_count(kind) == 2 for kind in ('reality', 'websocket', 'hysteria2', 'residential-01', 'residential-02')))
        user = db_user(uid)
        proxies = {kind: start_client(user, kind) for kind in ('reality', 'websocket', 'hysteria2', 'residential-01')}
        for proxy in proxies.values():
            reply = fetch(proxy)
            assert reply.returncode == 0 and reply.stdout == payload, reply.stderr.decode()[:100]
        broken = start_client(user, 'residential-02')
        assert fetch(broken, timeout=3).returncode != 0, 'Unavailable residential upstream fell back to direct'
        with pytest.raises((OSError, AssertionError)):
            udp_roundtrip(proxies['residential-01'], echo.getsockname(), os.urandom(64))
        sizes = (64, 1200, 1400, 2000, 4096)
        for size in sizes:
            udp_roundtrip(proxies['hysteria2'], echo.getsockname(), os.urandom(size))
        eventually(lambda: db_user(uid)['download'] >= len(payload) * 4)
        eventually(lambda: counter_value('user>>>' + uid + '.%@hysteria2>>>traffic>>>downlink') >= len(payload) + sum(sizes))
        with legacy.db() as db:
            hy2_count = db.execute("SELECT value FROM counters WHERE name LIKE ?", ('user>>>' + uid + '.%@hysteria2>>>traffic>>>downlink',)).fetchone()
            assert hy2_count and hy2_count[0] >= len(payload) + sum(sizes), 'Hy2 TCP and native UDP were not both counted'
            res_count = db.execute("SELECT value FROM counters WHERE name LIKE ?", ('user>>>' + uid + '.%@residential-01>>>traffic>>>downlink',)).fetchone()
            assert res_count and res_count[0] >= len(payload), 'Residential TCP was not charged to its owner'
        core_pid = core_pid_file.read_text()
        before = db_user(uid)['download']
        panel.terminate();panel.wait(timeout=15)
        panel = start_panel()
        eventually(lambda: client.call('/healthz')[0] == 200)
        eventually(lambda: client.json('/api/overview')['health']['core'])
        time.sleep(1.5)
        assert core_pid_file.read_text() == core_pid, 'Management restart interrupted Xray'
        assert db_user(uid)['download'] == before, 'Management restart double-counted traffic'
        assert client.json('/api/session')['csrf'] == client.csrf, 'Session did not survive management restart'
        client.json('/api/users/' + uid + '/reset-traffic', 'POST', {})
        time.sleep(1.5)
        assert db_user(uid)['download'] == 0

        partial = tmp_path / 'inflight.bin'
        stream = subprocess.Popen(['curl', '--noproxy', '', '--proxy', proxies['hysteria2'], '-fsS', '--max-time', '20',
            '-o', str(partial), base + '/slow'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(stream)
        eventually(lambda: partial.exists() and partial.stat().st_size > 32768)
        client.json('/api/users/' + uid, 'PUT', {'name': 'disabled', 'enabled': False})
        eventually(lambda: core_pid_file.read_text() != core_pid)
        # QUIC peers can wait for their own idle timeout after the server exits.
        # Verify cessation of traffic independently of the client's error timing.
        time.sleep(1)
        stopped_at = partial.stat().st_size
        time.sleep(1)
        assert partial.stat().st_size == stopped_at < len(payload) * 128, 'Revoked QUIC stream continued receiving'
        eventually(lambda: all(live_count(kind) == 1 for kind in ('reality', 'websocket', 'hysteria2')))
        disabled_proxy = start_client(user, 'hysteria2')
        assert fetch(disabled_proxy, timeout=3).returncode != 0, 'Disabled credentials still connected'
        assert fetch(proxies['residential-01'], timeout=3).returncode != 0, 'Disabled residential credentials still connected'
        other_residential = start_client(db_user(uid2), 'residential-01')
        assert fetch(other_residential).stdout == payload, 'Other residential user did not recover'
        other = start_client(db_user(uid2), 'hysteria2')
        assert fetch(other).stdout == payload, 'Other user did not recover after revocation'
        assert stream.wait(timeout=20) != 0, 'Revoked transfer reported success'

        client.json('/api/users/' + uid, 'PUT', {'name': 'active'})
        eventually(lambda: live_count('hysteria2') == 2)
        renewed_proxy = start_client(db_user(uid), 'hysteria2')
        assert fetch(renewed_proxy).stdout == payload
        old_links = client.json('/api/users/' + uid + '/links')
        old_pid = core_pid_file.read_text()
        client.json('/api/users/' + uid + '/rotate', 'POST', {})
        eventually(lambda: core_pid_file.read_text() != old_pid and live_count('hysteria2') == 2)
        assert fetch(proxies['hysteria2'], timeout=3).returncode != 0
        assert fetch(proxies['residential-01'], timeout=3).returncode != 0, 'Rotated residential credentials still connected'
        new_proxy = start_client(db_user(uid), 'hysteria2')
        assert fetch(new_proxy).stdout == payload
        assert client.call(old_links['subscription'].replace(ORIGIN, ''))[0] == 404

        old_pid = core_pid_file.read_text()
        client.json('/api/users/' + uid, 'PUT', {'name': 'quota', 'quota': 1})
        eventually(lambda: core_pid_file.read_text() != old_pid and live_count('hysteria2') == 1)
        assert next(u for u in client.json('/api/overview')['users'] if u['id'] == uid)['status'] == 'exhausted'
        client.json('/api/users/' + uid + '/reset-traffic', 'POST', {})
        eventually(lambda: live_count('hysteria2') == 2)
        assert next(u for u in client.json('/api/overview')['users'] if u['id'] == uid)['status'] == 'active'

        old_pid = core_pid_file.read_text()
        client.json('/api/users/' + uid, 'PUT', {'name': 'expired', 'expires': int(time.time()) - 1})
        eventually(lambda: core_pid_file.read_text() != old_pid and live_count('hysteria2') == 1)
        assert fetch(new_proxy, timeout=3).returncode != 0, 'Expired Hy2 credentials still connected'
        assert not core_error
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill();process.wait()
        stop.set();supervisor.join(timeout=10)
        echo.close();echo_thread.join(timeout=5)
        origin.shutdown();origin.server_close();serving.join(timeout=5)
        core_log.close();panel_log.close()
