"""Experimental Rust node against disposable TLS panel and loopback-only Xray.

Requires XCLI_TEST_XRAY and XCLI_NODE_SERVICE. Never use production config.
"""
import contextlib
import http.server
import json
import os
from pathlib import Path
import shlex
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

XRAY = os.environ.get('XCLI_TEST_XRAY', '')
SERVICE = os.environ.get('XCLI_NODE_SERVICE', '')
NODE_ID, TOKEN, USER_ID = 'a' * 32, 'B' * 43, 'c' * 32


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_for(check, timeout=25):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(.2)
    return False


@unittest.skipUnless(XRAY and SERVICE and Path(XRAY).is_file() and Path(SERVICE).is_file(), 'set XCLI_TEST_XRAY and XCLI_NODE_SERVICE for the isolated test')
class NodeServiceIntegration(unittest.TestCase):
    def test_tls_sync_accounting_revocation_lease_and_shutdown(self):
        with tempfile.TemporaryDirectory(prefix='xcli-rust-node-') as folder:
            root = Path(folder); cert = root / 'cert.pem'; key = root / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                '-addext', 'basicConstraints=critical,CA:FALSE', '-keyout', str(key), '-out', str(cert)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            fields = dict(line.split(':', 1) for line in subprocess.check_output([XRAY, 'x25519'], text=True).splitlines() if ':' in line)
            private = fields['PrivateKey'].strip()
            reality, websocket, hysteria, api = port(), port(), port(), port()
            cfg = {'log': {'loglevel': 'warning', 'access': 'none'},
                'api': {'tag': 'api', 'listen': f'127.0.0.1:{api}', 'services': ['HandlerService', 'StatsService']},
                'stats': {}, 'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True}}},
                'inbounds': [
                    {'tag': 'reality', 'listen': '127.0.0.1', 'port': reality, 'protocol': 'vless',
                     'settings': {'clients': [], 'decryption': 'none'}, 'streamSettings': {'network': 'tcp', 'security': 'reality',
                       'realitySettings': {'target': 'www.bing.com:443', 'serverNames': ['www.bing.com'], 'privateKey': private, 'shortIds': ['0123456789abcdef']}}},
                    {'tag': 'websocket', 'listen': '127.0.0.1', 'port': websocket, 'protocol': 'vless',
                     'settings': {'clients': [], 'decryption': 'none'}, 'streamSettings': {'network': 'ws', 'wsSettings': {'path': '/test'}}},
                    {'tag': 'hysteria2', 'listen': '127.0.0.1', 'port': hysteria, 'protocol': 'hysteria',
                     'settings': {'version': 2, 'clients': []}, 'streamSettings': {'network': 'hysteria', 'security': 'tls',
                       'hysteriaSettings': {'version': 2}, 'tlsSettings': {'alpn': ['h3'], 'certificates': [{'certificateFile': str(cert), 'keyFile': str(key)}]}}}],
                'outbounds': [{'protocol': 'freedom', 'settings': {'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32']}]}}]}
            core_config = root / 'core.json'; core_config.write_text(json.dumps(cfg))
            credential = str(uuid.uuid4())
            user = {'id': USER_ID, 'uuid': credential, 'expires': 0}
            shared = {'users': [user], 'records': [], 'drop_once': False, 'dropped': False,
                      'delay_reply': False}
            reply_delayed = threading.Event()
            lock = threading.Lock()
            class Panel(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_): pass
                def do_POST(self):
                    data = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    if self.path != '/api/nodes/sync' or self.headers.get('Authorization') != 'Xcli-Node '+NODE_ID+'.'+TOKEN:
                        self.send_response(401); self.end_headers(); return
                    with lock:
                        shared['records'].append(data['counters'])
                        should_drop = shared['drop_once'] and bool(data['counters']) and not shared['dropped']
                        if should_drop: shared['dropped'] = True
                        delay_reply = shared['delay_reply']
                        reply = {'revision': 'f'*64, 'users': list(shared['users']), 'lease_seconds': 10,
                                 'issued_at': int(time.time()), 'ack': data['counters']}
                    if delay_reply:
                        reply_delayed.set()
                        time.sleep(3)
                    if should_drop:
                        self.close_connection = True
                        with contextlib.suppress(OSError): self.connection.shutdown(socket.SHUT_RDWR)
                        return
                    body = json.dumps(reply).encode()
                    self.send_response(200); self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(body))); self.end_headers()
                    with contextlib.suppress(BrokenPipeError, ConnectionResetError, ssl.SSLError): self.wfile.write(body)
            panel = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Panel)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, key)
            panel.socket = context.wrap_socket(panel.socket, server_side=True)
            thread = threading.Thread(target=panel.serve_forever, daemon=True); thread.start()
            config = root / 'node.json'; config.write_text(json.dumps({'node_id':NODE_ID, 'token':TOKEN, 'panel':f'https://localhost:{panel.server_port}'}))
            state = root / 'state'; state.mkdir()
            env = {**os.environ, 'SSL_CERT_FILE':str(cert)}
            marker = root/'stall'; blocked = root/'stalled'
            bad_sample = root/'bad-sample'; sample_attempt = root/'sample-attempt'
            wrapper = root/'xray-wrapper'
            wrapper.write_text('#!/bin/sh\n' +
                f'if [ "$1" = api ] && [ "$2" = adu ] && [ -f {shlex.quote(str(marker))} ]; then touch {shlex.quote(str(blocked))}; sleep 30; fi\n' +
                f'if [ "$1" = api ] && [ "$2" = statsquery ] && [ -f {shlex.quote(str(bad_sample))} ]; then touch {shlex.quote(str(sample_attempt))}; exit 1; fi\n' +
                f'exec {shlex.quote(XRAY)} "$@"\n')
            wrapper.chmod(0o700)
            command = [SERVICE, '--experimental', '--config', str(config), '--state', str(state), '--core-config', str(core_config), '--xray', str(wrapper), '--api', f'127.0.0.1:{api}']
            daemon = subprocess.Popen(command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            panel_open = True; client = None; origin = None; origin_thread = None
            def live_users(tag):
                result = subprocess.run([XRAY, 'api', 'inbounduser', f'--server=127.0.0.1:{api}', '-tag='+tag, '--timeout=1'],
                    capture_output=True, timeout=3)
                if result.returncode: return None
                try: return json.loads(result.stdout).get('users', [])
                except ValueError: return None
            try:
                self.assertTrue(wait_for(lambda: all(len(live_users(tag) or []) == 1 for tag in ('reality', 'websocket', 'hysteria2'))), 'initial grant did not reach Xray')
                duplicate = subprocess.run(command, env=env, capture_output=True, timeout=8)
                self.assertNotEqual(duplicate.returncode, 0, 'duplicate Rust agent acquired the same state')
                self.assertIsNone(daemon.poll())
                body = b'x' * 65536
                class Origin(http.server.BaseHTTPRequestHandler):
                    def log_message(self, *_): pass
                    def do_GET(self):
                        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers()
                        with contextlib.suppress(BrokenPipeError, ConnectionResetError): self.wfile.write(body)
                origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
                origin_thread = threading.Thread(target=origin.serve_forever, daemon=True); origin_thread.start()
                socks = port()
                outgoing = {'protocol':'vless', 'settings':{'vnext':[{'address':'127.0.0.1','port':websocket,
                    'users':[{'id':credential,'encryption':'none'}]}]},
                    'streamSettings':{'network':'ws','security':'none','wsSettings':{'path':'/test'}}}
                client_config = root/'client.json'
                client_config.write_text(json.dumps({'log':{'loglevel':'warning'}, 'inbounds':[{'listen':'127.0.0.1','port':socks,
                    'protocol':'socks','settings':{'auth':'noauth','udp':True}}], 'outbounds':[outgoing]}))
                client = subprocess.Popen([XRAY,'run','-config',str(client_config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.assertTrue(wait_for(lambda: socket_open(socks), 8), 'fixture client did not start')
                with lock: shared['drop_once'] = True
                request = ['curl','--noproxy','','--proxy',f'socks5h://127.0.0.1:{socks}','-fsS','--max-time','5',f'http://127.0.0.1:{origin.server_port}/blob']
                result = subprocess.run(request, capture_output=True, timeout=8)
                self.assertEqual(result.returncode, 0); self.assertEqual(result.stdout, body)
                def retried():
                    with lock:
                        nonempty=[items for items in shared['records'] if items]
                        return shared['dropped'] and len(nonempty)>=2 and nonempty[0]==nonempty[1] and nonempty[-1][0]['download']>=len(body)
                self.assertTrue(wait_for(retried, 20), 'lost response was not retried with the same cumulative data')
                # Capture a lower bound immediately before a controlled revoke.
                # The node must retain and eventually report this count even if
                # the core is restarted to terminate established connections.
                result = subprocess.run(request, capture_output=True, timeout=8)
                self.assertEqual(result.returncode, 0); self.assertEqual(result.stdout, body)
                observed=json.loads(subprocess.check_output([XRAY,'api','statsquery',f'--server=127.0.0.1:{api}',
                    '-pattern','user>>>'],timeout=5)).get('stat',[])
                prefix=f'user>>>{USER_ID}.{credential[:8]}@websocket>>>traffic>>>'
                lower=tuple(sum(int(item.get('value',0)) for item in observed if item['name']==prefix+direction)
                    for direction in ('uplink','downlink'))
                self.assertGreaterEqual(lower[1],len(body))
                with lock: shared['users'] = []
                self.assertTrue(wait_for(lambda: all(live_users(tag)==[] for tag in ('reality','websocket','hysteria2'))), 'revocation did not reach Xray')
                def final_report():
                    with lock:
                        return any(item['id']==USER_ID and item['upload']>=lower[0] and item['download']>=len(body)*2
                                   for batch in shared['records'] for item in batch)
                self.assertTrue(wait_for(final_report,20),'node did not report its pre-restart accounting lower bound')
                self.assertNotEqual(subprocess.run(request, capture_output=True, timeout=8).returncode, 0, 'revoked credentials still connected')
                with lock: shared['users'] = [user]
                self.assertTrue(wait_for(lambda: len(live_users('websocket') or [])==1), 'grant was not restored')
                # Force a sampling failure while the network exchange is
                # blocked, so the independent watchdog detects it. Even if a
                # new core later works, process shutdown must report the loss.
                with lock: shared['delay_reply'] = True
                self.assertTrue(reply_delayed.wait(12), 'fixture did not delay a panel response')
                with lock: shared['delay_reply'] = False
                bad_sample.touch()
                self.assertTrue(wait_for(sample_attempt.exists, 5), 'fixture did not fail accounting')
                self.assertTrue(wait_for(lambda: live_users('websocket') in (None, []), 5), 'sample failure did not stop the core')
                bad_sample.unlink()
                self.assertTrue(wait_for(lambda: len(live_users('websocket') or [])==1, 20), 'node did not recover after accounting failure')
                # Stall a new user addition while an older grant is active. The
                # independent supervisor must revoke the old core at its old
                # deadline, even though the management call sleeps for 30 seconds.
                marker.touch()
                second = {'id':'d'*32, 'uuid':str(uuid.uuid4()), 'expires':0}
                with lock: shared['users'] = [user, second]
                self.assertTrue(wait_for(blocked.exists, 12), 'fixture did not enter stalled reconciliation')
                self.assertTrue(wait_for(lambda: live_users('websocket') in (None, []), 12), 'stalled reconciliation outlived the old lease')
                marker.unlink()
                self.assertTrue(wait_for(lambda: len(live_users('websocket') or [])==2, 25), 'node did not recover after a stalled command')
                with lock: shared['users'] = [user]
                self.assertTrue(wait_for(lambda: len(live_users('websocket') or [])==1), 'node did not reconcile after recovery')
                panel.shutdown(); panel.server_close(); thread.join(timeout=5); panel_open=False
                self.assertTrue(wait_for(lambda: live_users('websocket') in (None, []), 20), 'lease expiry did not revoke access')
                daemon.terminate()
                self.assertNotEqual(daemon.wait(timeout=25), 0, 'shutdown hid the earlier accounting failure')
            finally:
                if daemon.poll() is None:
                    daemon.terminate()
                    try: daemon.wait(timeout=25)
                    except subprocess.TimeoutExpired: daemon.kill(); daemon.wait(timeout=5)
                if client is not None:
                    client.terminate()
                    try: client.wait(timeout=5)
                    except subprocess.TimeoutExpired: client.kill(); client.wait(timeout=5)
                if panel_open: panel.shutdown(); panel.server_close(); thread.join(timeout=5)
                if origin is not None: origin.shutdown(); origin.server_close(); origin_thread.join(timeout=5)
                self.assertFalse(socket_open(api), 'node service left its Xray API running')


def socket_open(target):
    try:
        with socket.create_connection(('127.0.0.1', target), timeout=.2): return True
    except OSError:
        return False
