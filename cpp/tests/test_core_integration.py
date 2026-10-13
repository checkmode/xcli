"""Exercise revocation and accounting on a disposable Xray core, never production."""
import contextlib
import http.server
import importlib.util
import json
import os
import pathlib
import socket
import sqlite3
import subprocess
import threading
import time

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


def test_real_grpc_accounting_and_live_revocation(tmp_path):
    state = tmp_path / 'state'
    api_port, reality_port, ws_port, panel_port = [available_port() for _ in range(4)]
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
        'outbounds': [{'protocol': 'freedom'}]}
    core_config = tmp_path / 'core.json'
    core_config.write_text(json.dumps(config));core_config.chmod(0o600)
    settings = tmp_path / 'settings.json'
    settings.write_text(json.dumps({'origin': ORIGIN, 'domain': 'testserver', 'public_ip': '127.0.0.1',
        'reality_sni': 'www.bing.com', 'reality_public': public, 'short_id': short_id, 'ws_path': '/isolated-test'}))
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
            stream = {'network': 'ws', 'security': 'none', 'wsSettings': {'path': '/isolated-test'}}
        cfg = {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'socks', 'settings': {'auth': 'noauth'}}],
            'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{'address': '127.0.0.1',
                'port': reality_port if kind == 'reality' else ws_port, 'users': [account]}]}, 'streamSettings': stream}]}
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
        eventually(lambda: live_count('reality') == 2 and live_count('websocket') == 2)
        user = db_user(uid)
        proxies = {kind: start_client(user, kind) for kind in ('reality', 'websocket')}
        for proxy in proxies.values():
            reply = fetch(proxy)
            assert reply.returncode == 0 and reply.stdout == payload, reply.stderr.decode()[:100]
        eventually(lambda: db_user(uid)['download'] >= len(payload) * 2)
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
        stream = subprocess.Popen(['curl', '--noproxy', '', '--proxy', proxies['reality'], '-fsS', '--max-time', '30',
            '-o', str(partial), base + '/slow'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(stream)
        eventually(lambda: partial.exists() and partial.stat().st_size > 32768)
        client.json('/api/users/' + uid, 'PUT', {'name': 'disabled', 'enabled': False})
        eventually(lambda: core_pid_file.read_text() != core_pid)
        assert stream.wait(timeout=10) != 0, 'Existing connection survived revocation'
        eventually(lambda: live_count('reality') == 1 and live_count('websocket') == 1)
        assert fetch(proxies['reality'], timeout=3).returncode != 0, 'Disabled credentials still connected'
        other = start_client(db_user(uid2), 'websocket')
        assert fetch(other).stdout == payload, 'Other user did not recover after revocation'

        client.json('/api/users/' + uid, 'PUT', {'name': 'active'})
        eventually(lambda: live_count('reality') == 2)
        assert fetch(proxies['reality']).stdout == payload
        old_links = client.json('/api/users/' + uid + '/links')
        old_pid = core_pid_file.read_text()
        client.json('/api/users/' + uid + '/rotate', 'POST', {})
        eventually(lambda: core_pid_file.read_text() != old_pid and live_count('reality') == 2)
        assert fetch(proxies['reality'], timeout=3).returncode != 0
        new_proxy = start_client(db_user(uid), 'reality')
        assert fetch(new_proxy).stdout == payload
        assert client.call(old_links['subscription'].replace(ORIGIN, ''))[0] == 404

        old_pid = core_pid_file.read_text()
        client.json('/api/users/' + uid, 'PUT', {'name': 'quota', 'quota': 1})
        eventually(lambda: core_pid_file.read_text() != old_pid and live_count('reality') == 1)
        assert next(u for u in client.json('/api/overview')['users'] if u['id'] == uid)['status'] == 'exhausted'
        client.json('/api/users/' + uid + '/reset-traffic', 'POST', {})
        eventually(lambda: live_count('reality') == 2)
        assert next(u for u in client.json('/api/overview')['users'] if u['id'] == uid)['status'] == 'active'

        old_pid = core_pid_file.read_text()
        client.json('/api/users/' + uid, 'PUT', {'name': 'expired', 'expires': int(time.time()) - 1})
        eventually(lambda: core_pid_file.read_text() != old_pid and live_count('reality') == 1)
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
        origin.shutdown();origin.server_close();serving.join(timeout=5)
        core_log.close();panel_log.close()
