#!/usr/bin/env python3
"""Run under unshare --net: real DoH, TLS rejection, and no plaintext fallback."""
import base64
import http.server
import os
from pathlib import Path
import select
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import doh


def verify(binary):
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    with tempfile.TemporaryDirectory(prefix='xcli-doh-test-') as directory:
        root = Path(directory)
        cert, key = root / 'cert.pem', root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
            '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', str(key), '-out', str(cert)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        observed = {'doh': 0, 'plaintext': 0, 'fail': False}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                query = self.path.split('dns=', 1)[1]
                self.answer(base64.urlsafe_b64decode(query + '=' * (-len(query) % 4)))

            def do_POST(self):
                self.answer(self.rfile.read(int(self.headers['Content-Length'])))

            def answer(self, request):
                observed['doh'] += 1
                if observed['fail']:
                    self.send_error(503)
                    return
                end = 12
                labels = []
                while request[end]:
                    labels.append(request[end + 1:end + 1 + request[end]].decode())
                    end += request[end] + 1
                question = request[12:end + 5]
                record = struct.unpack('!H', request[end + 1:end + 3])[0]
                exists = '.'.join(labels).endswith('example.com')
                answer = b''
                if record == 1 and exists:
                    answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + socket.inet_aton('8.8.4.4')
                response = request[:2] + struct.pack('!5H', 0x8180 if exists else 0x8183, 1, int(bool(answer)), 0, 0) + question + answer
                self.send_response(200)
                self.send_header('Content-Type', 'application/dns-message')
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.daemon_threads = True
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        # Catch plaintext UDP DNS to every local address, including the host's stub.
        plain = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        plain.bind(('0.0.0.0', 53))
        plain_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        plain_tcp.bind(('0.0.0.0', 53))
        plain_tcp.listen()
        stop = threading.Event()

        def capture():
            while not stop.is_set():
                for listener in select.select([plain, plain_tcp], [], [], .2)[0]:
                    if listener is plain:
                        plain.recvfrom(65535)
                    else:
                        connection, _ = plain_tcp.accept()
                        connection.close()
                    observed['plaintext'] += 1

        thread = threading.Thread(target=capture)
        thread.start()
        try:
            for valid_tls in (True, False):
                observed['fail'] = False
                host = ('localhost' if valid_tls else 'wrong.test') + ':' + str(server.server_port)
                config = root / 'doh.toml'
                address = '127.0.0.1:' + str(server.server_port)
                config.write_text(doh.configuration_for(binary, [('fixture', address, host)])
                    .replace('cache = true', 'cache = false')
                    .replace("netprobe_address = '1.1.1.1:443'", "netprobe_address = '" + address + "'"))
                log = (root / 'proxy.log').open('w')
                process = subprocess.Popen([binary, '-config', str(config)], stdout=log, stderr=log,
                    env={**os.environ, 'SSL_CERT_FILE': str(cert), 'SSL_CERT_DIR': str(root / 'empty')})
                try:
                    if valid_tls:
                        try:
                            doh.ready()
                        except RuntimeError as error:
                            raise RuntimeError((root / 'proxy.log').read_text()[-6000:]) from error
                        observed['fail'] = True
                    else:
                        time.sleep(1)
                    try:
                        doh.query(domain='uncached-' + str(time.monotonic_ns()) + '.example.com')
                    except (OSError, RuntimeError):
                        pass
                    else:
                        raise AssertionError('Failed DoH or invalid certificate returned a successful answer')
                    assert observed['plaintext'] == 0, observed
                finally:
                    process.terminate()
                    process.wait(timeout=10)
                    log.close()
            assert observed['doh'] > 0
        finally:
            stop.set()
            thread.join(timeout=2)
            plain.close()
            plain_tcp.close()
            server.shutdown()
            server.server_close()
        print('PASS: real DoH answers; upstream failure fails closed; wrong TLS name rejected; no plaintext DNS.')


if __name__ == '__main__':
    verify(sys.argv[1] if len(sys.argv) > 1 else '/usr/sbin/dnscrypt-proxy')
