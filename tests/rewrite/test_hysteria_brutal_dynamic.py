"""Exercise the opt-in migration against an isolated real Xray process."""
import importlib.util
import copy
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('brutal_dynamic', ROOT / 'rewrite/deploy/enable-hysteria-brutal.py')
brutal = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(brutal)
XRAY = os.environ.get('XCLI_TEST_XRAY', '')


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


@unittest.skipUnless(XRAY and Path(XRAY).is_file(), 'set XCLI_TEST_XRAY to the disposable-test binary')
class DynamicMigrationTests(unittest.TestCase):
    def test_adds_and_rolls_back_a_real_listener_without_restarting_existing_core(self):
        with tempfile.TemporaryDirectory(prefix='xcli-brutal-integration-') as folder:
            root = Path(folder)
            cert, key = root / 'cert.pem', root / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-subj', '/CN=node.test', '-keyout', str(key), '-out', str(cert)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            fingerprint = subprocess.check_output(['openssl', 'x509', '-in', str(cert), '-noout', '-fingerprint', '-sha256'],
                                                  text=True).strip().split('=', 1)[1].replace(':', '')
            api, old_port, new_port = free_port(socket.SOCK_STREAM), free_port(socket.SOCK_DGRAM), free_port(socket.SOCK_DGRAM)
            while new_port == old_port:
                new_port = free_port(socket.SOCK_DGRAM)
            entry = {'tag': 'hysteria2', 'listen': '127.0.0.1', 'port': old_port, 'protocol': 'hysteria',
                     'settings': {'version': 2, 'clients': []}, 'streamSettings': {
                       'network': 'hysteria', 'security': 'tls', 'hysteriaSettings': {'version': 2},
                       'tlsSettings': {'certificates': [{'certificateFile': str(cert), 'keyFile': str(key)}]},
                       'finalmask': {'quicParams': {'congestion': 'bbr'}}}}
            config = {'log': {'loglevel': 'error'}, 'api': {'tag': 'api', 'listen': f'127.0.0.1:{api}',
                       'services': ['HandlerService', 'StatsService']}, 'stats': {},
                       'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True}}},
                       'inbounds': [entry], 'outbounds': [{'protocol': 'freedom',
                         'settings': {'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32']}]}}]}
            paths = {name: root / (name + ('.sh' if name == 'firewall' else '.json'))
                     for name in ('settings', 'core', 'monitor', 'firewall')}
            originals = {'settings': json.dumps({'hysteria2_port': old_port, 'preserve': 'yes'}).encode(),
                         'core': json.dumps(config).encode(), 'monitor': json.dumps({'hysteria2_port': old_port}).encode(),
                         'firewall': f'    iptables -w -A XG_IN -p udp --dport {old_port} -j ACCEPT\n'.encode()}
            for name, path in paths.items():
                path.write_bytes(originals[name]); path.chmod(0o600)
            core = subprocess.Popen([XRAY, 'run', '-config', str(paths['core'])], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_): pass
                def do_GET(self):
                    payload = b'isolated-hysteria-test'
                    self.send_response(200); self.send_header('Content-Length', str(len(payload))); self.end_headers()
                    self.wfile.write(payload)
            origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            origin_thread = threading.Thread(target=origin.serve_forever, daemon=True); origin_thread.start()
            try:
                for _ in range(80):
                    if core.poll() is not None:
                        self.fail('isolated Xray exited: ' + core.communicate()[0][:800])
                    try:
                        with socket.create_connection(('127.0.0.1', api), timeout=.2): break
                    except OSError: time.sleep(.1)
                else: self.fail('isolated Xray API did not start')
                rules = set()
                real_run = brutal.upgrade.run
                def run(*args, **kwargs):
                    if args[0] != 'iptables':
                        return real_run(*args, **kwargs)
                    if args[2] == '-C': return SimpleNamespace(returncode=0 if new_port in rules else 1)
                    if args[2] == '-A': rules.add(new_port)
                    if args[2] == '-D': rules.discard(new_port)
                    return SimpleNamespace(returncode=0, stdout='')
                migration = brutal.Activation({'role': 'panel'}, new_port, Path(XRAY), f'127.0.0.1:{api}', paths)
                migration.backup = root
                with patch.object(brutal.upgrade, 'run', side_effect=run), patch.object(brutal, 'CHECK_TEMP_ROOT', root):
                    self.assertTrue(migration.check())
                    old_pid = core.pid
                    migration.apply()
                    self.assertIsNone(core.poll())
                    self.assertEqual(core.pid, old_pid)
                    self.assertEqual(migration.runtime_tags(), {'hysteria2', brutal.TAG})
                    self.assertFalse(brutal.unbound(old_port)); self.assertFalse(brutal.unbound(new_port))
                    self.assertEqual(json.loads(paths['core'].read_bytes())['inbounds'][0], entry)
                    identity = '01234567-89ab-4def-8123-456789abcdef'
                    for tag, target_port in [('hysteria2', old_port), (brutal.TAG, new_port)]:
                        inbound = copy.deepcopy(entry if tag == 'hysteria2' else migration.after['inbound'])
                        inbound['settings']['clients'] = [{'auth': identity, 'email': 'test@' + tag}]
                        account_file = root / 'account.json'
                        account_file.write_text(json.dumps({'inbounds': [inbound]}))
                        add = subprocess.run([XRAY, 'api', 'adu', f'--server=127.0.0.1:{api}', str(account_file)],
                                             capture_output=True, text=True, timeout=10)
                        self.assertEqual(add.returncode, 0, add.stderr)
                        self.assertIn('1', add.stdout)
                        socks = free_port(socket.SOCK_STREAM)
                        client_cfg = {'log': {'loglevel': 'error'},
                            'inbounds': [{'listen': '127.0.0.1', 'port': socks, 'protocol': 'socks', 'settings': {'auth': 'noauth'}}],
                            'outbounds': [{'protocol': 'hysteria', 'settings': {'version': 2, 'address': '127.0.0.1', 'port': target_port},
                                'streamSettings': {'network': 'hysteria', 'security': 'tls',
                                    'hysteriaSettings': {'version': 2, 'auth': identity},
                                    'tlsSettings': {'serverName': 'node.test', 'pinnedPeerCertSha256': fingerprint, 'alpn': ['h3']}}}]}
                        client_path = root / 'client.json'; client_path.write_text(json.dumps(client_cfg))
                        client = subprocess.Popen([XRAY, 'run', '-config', str(client_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                        try:
                            for _ in range(60):
                                if client.poll() is not None: self.fail('isolated Hysteria client exited: ' + client.communicate()[0][:800])
                                try:
                                    with socket.create_connection(('127.0.0.1', socks), timeout=.2): break
                                except OSError: time.sleep(.1)
                            else: self.fail('isolated client did not start')
                            response = subprocess.run(['curl', '--noproxy', '', '--proxy', f'socks5h://127.0.0.1:{socks}',
                                '-fsS', '--max-time', '8', f'http://127.0.0.1:{origin.server_port}/'], capture_output=True, timeout=12)
                            self.assertEqual(response.returncode, 0, response.stderr.decode(errors='replace'))
                            self.assertEqual(response.stdout, b'isolated-hysteria-test')
                        finally:
                            client.terminate()
                            try: client.wait(timeout=5)
                            except subprocess.TimeoutExpired: client.kill(); client.wait()
                            if client.stdout is not None: client.stdout.close()
                    migration.rollback()
                    self.assertEqual(migration.runtime_tags(), {'hysteria2'})
                    self.assertFalse(brutal.unbound(old_port)); self.assertTrue(brutal.unbound(new_port))
                self.assertEqual(rules, set())
                self.assertIsNone(core.poll())
                for name, path in paths.items(): self.assertEqual(path.read_bytes(), originals[name])
            finally:
                core.terminate()
                try: core.wait(timeout=5)
                except subprocess.TimeoutExpired: core.kill(); core.wait()
                if core.stdout is not None: core.stdout.close()
                origin.shutdown(); origin.server_close(); origin_thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
