"""Disposable loopback-only TLS recipient for the webhook transport test."""
import hashlib
import hmac
import http.server
import ssl
import sys

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_POST(self):
        size = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(size)
        timestamp = self.headers.get('X-Xcli-Timestamp', '')
        expected = 'sha256=' + hmac.new(b'fixture-signing-secret', timestamp.encode() + b'.' + body, hashlib.sha256).hexdigest()
        if (self.headers.get('Authorization') != 'Bearer fixture-bearer' or
            self.headers.get('X-Xcli-Event-Id') != 'fixture-id' or
            not hmac.compare_digest(self.headers.get('X-Xcli-Signature', ''), expected)):
            code, data = 403, b'bad authentication'
        elif self.path == '/redirect':
            self.send_response(302)
            self.send_header('Location', 'https://127.0.0.1/private')
            self.end_headers()
            return
        elif self.path == '/oversize':
            code, data = 200, b'x' * 16385
        elif self.path == '/failed':
            code, data = 503, b'unavailable'
        else:
            code, data = 200, b'ok'
        self.send_response(code)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
server.socket = context.wrap_socket(server.socket, server_side=True)
print(server.server_address[1], flush=True)
server.serve_forever()
