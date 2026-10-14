"""Read live Linux/Xray state in isolated processes; never use production state."""
import contextlib
import importlib.util
import json
import os
import pathlib
import socket
import subprocess
import time

from test_http import BINARY, LEGACY, PASSWORD, Client, available_port, fixture
from test_core_integration import XRAY, eventually


def test_runtime_authentication_and_offline_unknown(fixture):
    # Reuse the disposable offline HTTP fixture, not a fake successful runtime.
    client = fixture['client']
    for path in ('/api/runtime', '/api/diagnostics'):
        client.json(path, expected=401)
    client.login()
    data = client.json('/api/runtime')
    assert data['process']['state'] == 'unknown'
    assert data['process'].get('version') is None
    assert data['management_api']['state'] == 'unknown'
    assert data['host']['memory']['total'] > 0
    assert data['host']['disk']['total'] > 0
    assert client.json('/api/diagnostics')['scope'] == 'server'


def test_live_runtime_truth_redaction_reload_and_failure(tmp_path):
    api_port, reality_port, ws_port, hy2_port, panel_port = [available_port() for _ in range(5)]
    private_keys = subprocess.check_output([str(XRAY), 'x25519'], text=True)
    private = dict(line.split(':', 1) for line in private_keys.splitlines() if ':' in line)['PrivateKey'].strip()
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=runtime.invalid', '-keyout', str(key), '-out', str(cert)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    config = {
        'log': {'loglevel': 'warning', 'access': 'none'},
        'api': {'tag': 'api', 'listen': f'127.0.0.1:{api_port}', 'services': ['HandlerService', 'StatsService']},
        'stats': {},
        'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True}}},
        'inbounds': [
            {'tag': 'reality', 'listen': '127.0.0.1', 'port': reality_port, 'protocol': 'vless',
             'settings': {'clients': [], 'decryption': 'none'},
             'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {
                 'target': 'www.bing.com:443', 'serverNames': ['www.bing.com'],
                 'privateKey': private, 'shortIds': ['12345678']}}},
            {'tag': 'websocket', 'listen': '127.0.0.1', 'port': ws_port, 'protocol': 'vless',
             'settings': {'clients': [], 'decryption': 'none'},
             'streamSettings': {'network': 'ws', 'wsSettings': {'path': '/actual-runtime'}}},
            {'tag': 'hysteria2', 'listen': '127.0.0.1', 'port': hy2_port, 'protocol': 'hysteria',
             'settings': {'version': 2, 'clients': []},
             'streamSettings': {'network': 'hysteria', 'security': 'tls', 'hysteriaSettings': {'version': 2},
                 'tlsSettings': {'alpn': ['h3'], 'certificates': [{'certificateFile': str(cert), 'keyFile': str(key)}]}}}],
        'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}
    core_config = tmp_path / 'core.json'
    core_config.write_text(json.dumps(config))
    os.utime(core_config, (time.time() - 2, time.time() - 2))
    pid_file = tmp_path / 'core.pid'
    state = tmp_path / 'state'
    settings = tmp_path / 'settings.json'
    # Deliberately incorrect configured version/parameters must not become runtime facts.
    settings.write_text(json.dumps({'origin': 'https://testserver', 'domain': 'testserver',
        'public_ip': '192.0.2.99', 'reality_sni': 'wrong.invalid', 'reality_public': 'p' * 43,
        'short_id': 'aabbccdd', 'ws_path': '/wrong-configured', 'hysteria2_port': 9999,
        'xray_version': 'configured-version-is-not-runtime'}))
    spec = importlib.util.spec_from_file_location('runtime_legacy', LEGACY)
    legacy = importlib.util.module_from_spec(spec); spec.loader.exec_module(legacy)
    legacy.STATE, legacy.SETTINGS = state, settings
    legacy.init_db()
    with legacy.db() as db:
        db.execute('INSERT INTO admin VALUES(1,?)', (legacy.password_hash(PASSWORD),))
    processes = []
    log = (tmp_path / 'processes.log').open('wb')
    try:
        def start_core():
            process = subprocess.Popen([str(XRAY), 'run', '-config', str(core_config)], stdout=log, stderr=log)
            processes.append(process); pid_file.write_text(str(process.pid))
            return process
        core = start_core()
        panel = subprocess.Popen([str(BINARY), '--state', str(state), '--settings', str(settings),
            '--static', str(LEGACY.parent / 'static'), '--port', str(panel_port),
            '--core-binary', str(XRAY), '--core-pid-file', str(pid_file),
            '--api', f'127.0.0.1:{api_port}', '--poll-seconds', '1', '--no-auto-backup'], stdout=log, stderr=log)
        processes.append(panel)
        client = Client(panel_port)
        eventually(lambda: client.call('/healthz')[0] == 200)
        client.login()
        eventually(lambda: client.json('/api/runtime')['management_api']['state'] == 'reachable')
        data = client.json('/api/runtime')
        p = data['process']
        expected_version = subprocess.check_output([str(XRAY), 'version'], text=True).split()[1]
        assert p['version'] == expected_version and p['pid'] == core.pid
        assert p['version_source'] == 'running_process_executable'
        assert data['management_api']['generation'] == p['generation']
        assert data['access_sync']['generation'] == p['generation']
        assert p['uptime_seconds'] >= 0 and p['started_at'] <= time.time()
        assert p['config']['scope'] == 'file_snapshot'
        assert p['config']['changed_since_start'] is False
        entries = {entry['tag']: entry for entry in p['inbounds']}
        assert set(entries) == {'reality', 'websocket', 'hysteria2'}
        assert all(entry['listener']['state'] == 'listening' for entry in entries.values())
        assert all(entry['listener']['bindings'][0]['address'] == '127.0.0.1' for entry in entries.values())
        assert entries['websocket']['path'] == '/actual-runtime'
        assert entries['reality']['target'] == 'www.bing.com:443'
        assert entries['hysteria2']['port'] == hy2_port
        assert entries['hysteria2']['certificate']['state'] == 'within_validity'
        serialized = json.dumps(client.json('/api/diagnostics'))
        assert private not in serialized and 'configured-version-is-not-runtime' not in serialized
        assert '12345678' not in serialized and 'privateKey' not in serialized and 'keyFile' not in serialized
        eventually(lambda: client.json('/api/runtime')['host']['cpu_percent'] is not None)
        assert 0 <= client.json('/api/runtime')['host']['cpu_percent'] <= 100

        # A port owned by another process must not count as this Xray's listener.
        with socket.socket() as foreign:
            foreign.bind(('127.0.0.1', 0)); foreign.listen()
            time.sleep(1.1)
            config['inbounds'][1]['port'] = foreign.getsockname()[1]
            core_config.write_text(json.dumps(config))
            eventually(lambda: client.json('/api/runtime')['process']['config']['changed_since_start'])
            eventually(lambda: next(e for e in client.json('/api/runtime')['process']['inbounds']
                                   if e['tag'] == 'websocket')['listener']['state'] == 'not_listening')
            assert core.poll() is None  # The file edit did not restart or reconfigure the core.
        core.terminate(); core.wait(timeout=5)
        eventually(lambda: client.json('/api/runtime')['process']['state'] == 'unavailable')
        stopped = client.json('/api/runtime')
        assert stopped['process'].get('version') is None and not stopped['process'].get('inbounds')
        assert stopped['management_api']['state'] != 'reachable'
        assert stopped['access_sync']['state'] != 'ready'
        config['inbounds'][1]['port'] = ws_port
        core_config.write_text(json.dumps(config))
        core = start_core()
        eventually(lambda: client.json('/api/runtime')['process'].get('pid') == core.pid)
        restarted = client.json('/api/runtime')
        assert restarted['process']['generation'] != p['generation']
        assert restarted['process']['version'] == expected_version
        assert len(client.json('/api/diagnostics')['transitions']) >= 3
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
        log.close()
