"""Characterize Xray 26.10.21 with disposable loopback processes only.

A closed listener is not sufficient evidence that all prior usage is final.
This test intentionally observes an established WebSocket session continuing
through an inbound removal; it does not implement or authorize a production drain.
"""
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

XRAY = os.environ.get('XCLI_TEST_XRAY', '')


def free_ports(count):
    listeners = []
    try:
        for _ in range(count):
            listener = socket.socket()
            listeners.append(listener)
            listener.bind(('127.0.0.1', 0))
        return [listener.getsockname()[1] for listener in listeners]
    finally:
        for listener in listeners:
            listener.close()


def wait_for_port(port, process):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError('disposable Xray process stopped')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                return
        except OSError:
            time.sleep(.05)
    raise RuntimeError('disposable Xray process did not start')


def recv_exact(sock, size):
    result = b''
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            break
        result += chunk
    return result


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while data := self.request.recv(65536):
                self.request.sendall(data)
        except (ConnectionError, OSError):
            pass


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


@unittest.skipUnless(XRAY and Path(XRAY).is_file(), 'set XCLI_TEST_XRAY to a test Xray binary')
class InboundDrainObservation(unittest.TestCase):
    def test_existing_websocket_stream_survives_inbound_removal(self):
        self.observe('inbound')

    def test_existing_websocket_stream_survives_user_removal(self):
        self.observe('user')

    def observe(self, removal):
        with tempfile.TemporaryDirectory(prefix='xcli-drain-') as directory:
            root = Path(directory)
            processes = []
            echo = EchoServer(('127.0.0.1', 0), EchoHandler)
            thread = threading.Thread(target=echo.serve_forever, daemon=True)
            thread.start()
            try:
                api_port, inbound_port, socks_port = free_ports(3)
                identity = str(uuid.uuid4())
                email = 'a' * 32 + '.' + identity[:8] + '@websocket'
                core = {
                    'log': {'loglevel': 'none'},
                    'api': {'tag': 'api', 'listen': f'127.0.0.1:{api_port}',
                            'services': ['HandlerService', 'StatsService']},
                    'stats': {},
                    'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True}}},
                    'inbounds': [{'tag': 'websocket', 'listen': '127.0.0.1', 'port': inbound_port,
                                  'protocol': 'vless',
                                  'settings': {'clients': [{'id': identity, 'email': email}], 'decryption': 'none'},
                                  'streamSettings': {'network': 'ws'}}],
                    'outbounds': [{'protocol': 'freedom', 'settings': {
                        'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32']}]}}],
                }
                client = {
                    'log': {'loglevel': 'none'},
                    'inbounds': [{'listen': '127.0.0.1', 'port': socks_port, 'protocol': 'socks',
                                  'settings': {'auth': 'noauth'}}],
                    'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [
                        {'address': '127.0.0.1', 'port': inbound_port,
                         'users': [{'id': identity, 'encryption': 'none'}]}]},
                        'streamSettings': {'network': 'ws', 'security': 'none'}}],
                }
                for name, config, listen in [('core', core, api_port), ('client', client, socks_port)]:
                    config_path = root / (name + '.json')
                    config_path.write_text(json.dumps(config))
                    process = subprocess.Popen([XRAY, 'run', '-config', str(config_path)],
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    processes.append(process)
                    wait_for_port(listen, process)

                def api(*args):
                    return subprocess.run([XRAY, 'api', *args], capture_output=True, text=True,
                                          timeout=8, check=True).stdout

                def counters():
                    result = json.loads(api('statsquery', f'--server=127.0.0.1:{api_port}',
                                            '-pattern', 'user>>>'))
                    return sum(int(entry.get('value', 0)) for entry in result.get('stat', []))

                with socket.create_connection(('127.0.0.1', socks_port), timeout=3) as stream:
                    stream.settimeout(4)
                    stream.sendall(b'\x05\x01\x00')
                    self.assertEqual(recv_exact(stream, 2), b'\x05\x00')
                    stream.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' +
                                   struct.pack('!H', echo.server_address[1]))
                    self.assertEqual(recv_exact(stream, 10)[:2], b'\x05\x00')
                    first = b'A' * 16384
                    stream.sendall(first)
                    self.assertEqual(recv_exact(stream, len(first)), first)
                    before = counters()
                    if removal == 'inbound':
                        api('rmi', f'--server=127.0.0.1:{api_port}', 'websocket')
                        with self.assertRaises(OSError):
                            with socket.create_connection(('127.0.0.1', inbound_port), timeout=.5):
                                pass
                    else:
                        api('rmu', f'--server=127.0.0.1:{api_port}', '-tag=websocket', email)
                        users = json.loads(api('inbounduser', f'--server=127.0.0.1:{api_port}',
                                               '-tag=websocket')).get('users', [])
                        self.assertEqual(users, [])
                        received = b''
                        try:
                            with socket.create_connection(('127.0.0.1', socks_port), timeout=3) as fresh:
                                fresh.settimeout(3)
                                fresh.sendall(b'\x05\x01\x00')
                                self.assertEqual(recv_exact(fresh, 2), b'\x05\x00')
                                fresh.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' +
                                              struct.pack('!H', echo.server_address[1]))
                                if recv_exact(fresh, 10)[:2] == b'\x05\x00':
                                    fresh.sendall(b'new-connection')
                                    received = recv_exact(fresh, len(b'new-connection'))
                        except (OSError, ConnectionError):
                            pass
                        self.assertNotEqual(received, b'new-connection')
                    later = b'B' * 32768
                    stream.sendall(later)
                    self.assertEqual(recv_exact(stream, len(later)), later)
                    self.assertGreater(counters(), before)
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
