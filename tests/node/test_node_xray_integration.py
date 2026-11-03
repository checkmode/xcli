"""Real three-transport traffic, counters and revocation in an isolated fixture.

Set XCLI_TEST_XRAY to an official Xray binary; all listeners bind to loopback.
"""
import contextlib
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
from node_agent import XrayController
from node_ledger import Ledger

XRAY = os.environ.get('XCLI_TEST_XRAY', '')
NGINX = os.environ.get('XCLI_TEST_NGINX', '')


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@unittest.skipUnless(XRAY and Path(XRAY).is_file(), 'set XCLI_TEST_XRAY to run the isolated Xray test')
class RealXrayTests(unittest.TestCase):
    def test_three_transports_account_and_revoke(self):
        with tempfile.TemporaryDirectory(prefix='xcli-node-integration-') as directory:
            root = Path(directory)
            cert, key = root/'cert.pem', root/'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=node.test', '-addext', 'subjectAltName=DNS:node.test,DNS:www.bing.com',
                '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', str(key), '-out', str(cert)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            fields = dict(line.split(':', 1) for line in subprocess.check_output([XRAY, 'x25519'], text=True).splitlines() if ':' in line)
            private = fields['PrivateKey'].strip()
            public = next(fields[k].strip() for k in ('Password (PublicKey)', 'Password', 'PublicKey') if k in fields)
            if NGINX and os.environ.get('XCLI_LOCAL_FIXTURE') != '1':
                self.fail('Nginx integration must be enabled explicitly for a loopback-only fixture')
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
            path = root/'core.json'; path.write_text(json.dumps(cfg))
            nginx_process = None
            dummy_tls = None
            if NGINX:
                # Exercise the actual stream SNI routing and WebSocket TLS
                # termination, with every fixture listener bound to loopback.
                sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'deploy'))
                import install_node
                entry, tls_port, http_port, target_port = port(), port(), port(), port()
                cfg['inbounds'][0]['streamSettings']['tcpSettings'] = {'acceptProxyProtocol': True}
                if os.environ.get('XCLI_TEST_REALITY_TARGET') == 'public':
                    cfg['inbounds'][0]['streamSettings']['realitySettings']['target'] = 'www.bing.com:443'
                else:
                    cfg['inbounds'][0]['streamSettings']['realitySettings']['target'] = f'127.0.0.1:{target_port}'
                    dummy_tls = subprocess.Popen(['openssl', 's_server', '-quiet', '-accept', f'127.0.0.1:{target_port}',
                                                 '-cert', str(cert), '-key', str(key)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                cfg['inbounds'][2]['port'] = entry
                hysteria = entry
                path.write_text(json.dumps(cfg))
                settings = {'domain': 'node.test', 'reality_sni': 'www.bing.com', 'public_port': entry, 'ws_path': '/test'}
                nginx = install_node.nginx_config(Path(__file__).resolve().parents[2], settings, True)
                nginx = nginx.replace('listen '+str(entry)+';', 'listen 127.0.0.1:'+str(entry)+';')
                nginx = nginx.replace('listen 80 default_server;', 'listen 127.0.0.1:'+str(http_port)+' default_server;')
                nginx = nginx.replace('127.0.0.1:8443', '127.0.0.1:'+str(tls_port))
                nginx = nginx.replace('127.0.0.1:10443', '127.0.0.1:'+str(reality))
                nginx = nginx.replace('127.0.0.1:10080', '127.0.0.1:'+str(websocket))
                nginx = nginx.replace('/etc/xcli-node/tls/fullchain.pem', str(cert))
                nginx = nginx.replace('/etc/xcli-node/tls/privkey.pem', str(key))
                nginx = nginx.replace('/run/nginx.pid', str(root/'nginx.pid'))
                nginx = nginx.replace('/var/log/nginx/error.log', str(root/'nginx-error.log'))
                nginx_path = root/'nginx.conf'; nginx_path.write_text(nginx)
                nginx_process = subprocess.Popen([NGINX, '-c', str(nginx_path), '-g', 'daemon off;'],
                                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            controller = XrayController(XRAY, path, f'127.0.0.1:{api}')
            ledger = Ledger(root/'ledger.sqlite')
            identity = 'a'*32; user = {'id': identity, 'uuid': str(uuid.uuid4()), 'expires': 0}
            payload = b'x' * 65536
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_): pass
                def do_GET(self):
                    self.send_response(200); self.send_header('Content-Length', str(len(payload))); self.end_headers()
                    with contextlib.suppress(BrokenPipeError, ConnectionResetError): self.wfile.write(payload)
            origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            thread = threading.Thread(target=origin.serve_forever, daemon=True); thread.start()
            processes = []
            requests = {}
            try:
                controller.start(); controller.apply({identity: user})
                for kind in ('reality', 'websocket', 'hysteria2'):
                    socks = port()
                    account = {'id': user['uuid'], 'encryption': 'none'}
                    stream = {'network': 'ws', 'security': 'none', 'wsSettings': {'path': '/test'}}
                    if kind == 'reality':
                        account['flow'] = 'xtls-rprx-vision'
                        stream = {'network': 'tcp', 'security': 'reality', 'realitySettings': {'serverName': 'www.bing.com',
                                  'fingerprint': 'chrome', 'publicKey': public, 'shortId': '0123456789abcdef'}}
                    elif kind == 'websocket' and NGINX:
                        stream = {'network': 'ws', 'security': 'tls', 'wsSettings': {'path': '/test', 'headers': {'Host': 'node.test'}},
                                  'tlsSettings': {'serverName': 'node.test', 'allowInsecure': False, 'disableSystemRoot': True,
                                                  'certificates': [{'certificateFile': str(cert), 'usage': 'verify'}]}}
                    outgoing = {'protocol': 'vless', 'settings': {'vnext': [{'address': '127.0.0.1',
                                'port': entry if NGINX else reality if kind == 'reality' else websocket, 'users': [account]}]}, 'streamSettings': stream}
                    if kind == 'hysteria2':
                        outgoing = {'protocol': 'hysteria', 'settings': {'version': 2, 'address': '127.0.0.1', 'port': hysteria},
                            'streamSettings': {'network': 'hysteria', 'security': 'tls', 'hysteriaSettings': {'version': 2, 'auth': user['uuid']},
                                'tlsSettings': {'serverName': 'node.test', 'allowInsecure': False, 'alpn': ['h3'], 'disableSystemRoot': True,
                                                'certificates': [{'certificateFile': str(cert), 'usage': 'verify'}]}}}
                    client = {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1', 'port': socks,
                              'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True}}], 'outbounds': [outgoing]}
                    client_path = root/(kind+'.json'); client_path.write_text(json.dumps(client))
                    process = subprocess.Popen([XRAY, 'run', '-config', str(client_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    processes.append(process)
                    deadline = time.monotonic()+8
                    while True:
                        try:
                            with socket.create_connection(('127.0.0.1', socks), timeout=.2): break
                        except OSError:
                            if process.poll() is not None or time.monotonic() >= deadline: self.fail(kind+' client did not start')
                            time.sleep(.1)
                    command = ['curl', '--noproxy', '', '--proxy', f'socks5h://127.0.0.1:{socks}', '-fsS', '--max-time', '10',
                               f'http://127.0.0.1:{origin.server_port}/blob']
                    requests[kind] = command
                    response = subprocess.run(command, capture_output=True, timeout=15)
                    self.assertEqual(response.returncode, 0, kind+': '+response.stderr.decode(errors='replace'))
                    self.assertEqual(response.stdout, payload)
                    counters = controller.counters()
                    self.assertTrue(any('@'+kind+'>>>traffic>>>downlink' in c['name'] and int(c.get('value', 0)) >= len(payload) for c in counters), kind)
                    ledger.record(controller.generation, counters)
                report = ledger.pending()
                self.assertEqual(len(report), 1)
                self.assertGreaterEqual(report[0]['download'], 3*len(payload))
                ledger.acknowledge(report)
                ledger.record(controller.generation, controller.counters())
                self.assertEqual(ledger.pending(), [])
                controller.apply({})
                for tag in ('reality', 'websocket', 'hysteria2'):
                    live = json.loads(controller.command('inbounduser', '-tag='+tag, '--timeout=2'))
                    self.assertEqual(live.get('users', []), [])
                    request = list(requests[tag]); request[request.index('--max-time')+1] = '3'
                    self.assertNotEqual(subprocess.run(request, capture_output=True, timeout=6).returncode, 0,
                                        tag+' accepted revoked credentials')
            finally:
                if sys.exc_info()[0] and NGINX and (root/'nginx-error.log').exists():
                    print('Nginx fixture diagnostics:', (root/'nginx-error.log').read_text(errors='replace')[-2000:])
                controller.stop(); ledger.close()
                for process in (nginx_process, dummy_tls):
                    if process is not None and process.poll() is None:
                        process.terminate()
                        try: process.wait(timeout=5)
                        except subprocess.TimeoutExpired: process.kill(); process.wait()
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                        try: process.wait(timeout=5)
                        except subprocess.TimeoutExpired: process.kill(); process.wait()
                origin.shutdown(); origin.server_close(); thread.join(timeout=5)


if __name__ == '__main__': unittest.main()
