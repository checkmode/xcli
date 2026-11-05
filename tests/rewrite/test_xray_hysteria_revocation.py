"""Characterize authenticated Hysteria 2 reuse with disposable loopback Xray."""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

from test_xray_inbound_drain import EchoHandler, EchoServer, free_ports, recv_exact, wait_for_port


XRAY = os.environ.get('XCLI_TEST_XRAY', '')


def socks_stream(port, destination):
    stream = socket.create_connection(('127.0.0.1', port), timeout=4)
    stream.settimeout(4)
    stream.sendall(b'\x05\x01\x00')
    if recv_exact(stream, 2) != b'\x05\x00':
        stream.close()
        raise OSError('SOCKS greeting failed')
    stream.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', destination))
    if recv_exact(stream, 10)[:2] != b'\x05\x00':
        stream.close()
        raise OSError('SOCKS connect failed')
    return stream


@unittest.skipUnless(XRAY and Path(XRAY).is_file(), 'set XCLI_TEST_XRAY to a test Xray binary')
class HysteriaRevocationObservation(unittest.TestCase):
    def test_existing_quic_connection_can_open_new_stream_after_user_removal(self):
        with tempfile.TemporaryDirectory(prefix='xcli-hysteria-revoke-') as directory:
            root = Path(directory)
            cert, key = root / 'cert.pem', root / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-subj', '/CN=node.test', '-addext', 'subjectAltName=DNS:node.test',
                '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', str(key), '-out', str(cert)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            api_port, inbound_port, socks_port, new_socks = free_ports(4)
            identity = str(uuid.uuid4())
            email = 'a' * 32 + '.' + identity[:8] + '@hysteria2'
            core = {'log': {'loglevel': 'none'},
                    'api': {'tag': 'api', 'listen': f'127.0.0.1:{api_port}',
                            'services': ['HandlerService', 'StatsService']},
                    'stats': {}, 'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True}}},
                    'inbounds': [{'tag': 'hysteria2', 'listen': '127.0.0.1', 'port': inbound_port,
                                  'protocol': 'hysteria', 'settings': {'version': 2, 'clients': [{'auth': identity, 'email': email}]},
                                  'streamSettings': {'network': 'hysteria', 'security': 'tls', 'hysteriaSettings': {'version': 2},
                                      'tlsSettings': {'alpn': ['h3'], 'certificates': [{'certificateFile': str(cert), 'keyFile': str(key)}]}}}],
                    'outbounds': [{'protocol': 'freedom', 'settings': {'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32']}]}}]}
            outbound = {'protocol': 'hysteria', 'settings': {'version': 2, 'address': '127.0.0.1', 'port': inbound_port},
                        'streamSettings': {'network': 'hysteria', 'security': 'tls', 'hysteriaSettings': {'version': 2, 'auth': identity},
                            'tlsSettings': {'serverName': 'node.test', 'allowInsecure': False, 'alpn': ['h3'],
                                            'disableSystemRoot': True, 'certificates': [{'certificateFile': str(cert), 'usage': 'verify'}]}}}
            processes = []
            echo = EchoServer(('127.0.0.1', 0), EchoHandler)
            thread = threading.Thread(target=echo.serve_forever, daemon=True)
            thread.start()
            try:
                path = root / 'core.json'
                path.write_text(json.dumps(core))
                core_process = subprocess.Popen([XRAY, 'run', '-config', str(path)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                processes.append(core_process)
                wait_for_port(api_port, core_process)

                def start_client(port):
                    client = {'log': {'loglevel': 'none'},
                              'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'socks', 'settings': {'auth': 'noauth'}}],
                              'outbounds': [outbound]}
                    config = root / f'client-{port}.json'
                    config.write_text(json.dumps(client))
                    process = subprocess.Popen([XRAY, 'run', '-config', str(config)],
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    processes.append(process)
                    wait_for_port(port, process)

                def api(*args):
                    return subprocess.run([XRAY, 'api', *args], capture_output=True, text=True,
                                          timeout=8, check=True).stdout

                def counters():
                    result = json.loads(api('statsquery', f'--server=127.0.0.1:{api_port}', '-pattern', 'user>>>'))
                    return sum(int(entry.get('value', 0)) for entry in result.get('stat', []))

                start_client(socks_port)
                with socks_stream(socks_port, echo.server_address[1]) as existing:
                    existing.sendall(b'before-removal')
                    self.assertEqual(recv_exact(existing, 14), b'before-removal')
                    before = counters()
                    api('rmu', f'--server=127.0.0.1:{api_port}', '-tag=hysteria2', email)
                    users = json.loads(api('inbounduser', f'--server=127.0.0.1:{api_port}', '-tag=hysteria2')).get('users', [])
                    self.assertEqual(users, [])
                    existing.sendall(b'existing-stream')
                    self.assertEqual(recv_exact(existing, 15), b'existing-stream')
                    with socks_stream(socks_port, echo.server_address[1]) as reused:
                        reused.sendall(b'new-stream-same-quic')
                        self.assertEqual(recv_exact(reused, 20), b'new-stream-same-quic')
                    self.assertGreater(counters(), before)
                    start_client(new_socks)
                    fresh_result = b''
                    try:
                        with socks_stream(new_socks, echo.server_address[1]) as fresh:
                            fresh.sendall(b'new-quic')
                            fresh_result = recv_exact(fresh, 8)
                    except (OSError, ConnectionError):
                        pass
                    self.assertNotEqual(fresh_result, b'new-quic')
                    api('rmi', f'--server=127.0.0.1:{api_port}', 'hysteria2')
                    after_close = b''
                    try:
                        existing.sendall(b'after-inbound-close')
                        after_close = recv_exact(existing, 19)
                    except (OSError, ConnectionError):
                        pass
                    self.assertNotEqual(after_close, b'after-inbound-close')
            finally:
                for process in reversed(processes):
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                echo.shutdown()
                echo.server_close()
                thread.join(timeout=2)
