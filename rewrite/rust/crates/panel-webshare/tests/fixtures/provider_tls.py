"""Loopback-only HTTPS provider fixture; contains no user credentials."""
import http.server
import ssl
import sys
from urllib.parse import parse_qs, urlsplit

certificate,key,mode=sys.argv[1:]


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def do_GET(self):
        url=urlsplit(self.path)
        if url.path!='/api/v2/subscription/plan/' or parse_qs(url.query)!={'page':['1'],'page_size':['100']} or self.headers.get('Authorization')!='Token synthetic-api-key-for-test':
            self.send_response(403);self.end_headers();return
        if mode=='redirect':
            self.send_response(302);self.send_header('Location','https://localhost/');self.end_headers();return
        if mode=='unauthorized':self.send_response(401);self.end_headers();return
        if mode=='rate':self.send_response(429);self.end_headers();return
        data=b'x'*(2*1024*1024+1) if mode=='oversize' else b'{invalid' if mode=='badjson' else b'{"results":[]}'
        self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers()
        try:self.wfile.write(data)
        except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass


server=http.server.HTTPServer(('127.0.0.1',0),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certificate,key)
server.socket=context.wrap_socket(server.socket,server_side=True)
print(server.server_port,flush=True);server.serve_forever()
