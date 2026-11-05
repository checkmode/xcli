"""Disposable loopback-only TLS server for node transport tests."""
import http.server
import json
import ssl
import sys

certificate, key, mode = sys.argv[1:]


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        auth = 'Xcli-Node ' + 'a' * 32 + '.' + 'B' * 43
        if self.path != '/api/nodes/sync' or self.headers.get('Authorization') != auth or payload != {'revision': '', 'counters': []}:
            self.send_response(403); self.end_headers(); return
        if mode == 'redirect':
            self.send_response(302); self.send_header('Location', 'https://localhost/'); self.end_headers(); return
        body = b'x' * (256 * 1024 + 1) if mode == 'oversize' else b'{"ok":true}'
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain' if mode == 'badtype' else 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certificate, key)
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_port, flush=True)
server.serve_forever()
