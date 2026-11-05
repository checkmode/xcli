"""Synthetic authenticated SOCKS or CONNECT proxy, forwarding only loopback TLS."""
import base64
import http.server
import select
import socket
import socketserver
import ssl
import sys
import threading
from urllib.parse import urlsplit

certificate, key, protocol, mode = sys.argv[1:]


class Http(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        if urlsplit(self.path).path == '/trace':
            data = b'ip=127.0.0.1\nloc=US\n' if mode == 'private' else b'ip=8.8.8.8\nloc=US\n'
            if mode == 'oversize': data = b'x' * 8193
        elif urlsplit(self.path).path == '/dns-query':
            data = b'bad' if mode == 'dnsfail' else b'XG\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
        else:
            self.send_response(404);self.end_headers();return
        self.send_response(200);self.send_header('Content-Length', str(len(data)));self.end_headers()
        try:self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):pass


web = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Http)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certificate, key)
web.socket = context.wrap_socket(web.socket, server_side=True)
threading.Thread(target=web.serve_forever, daemon=True).start()


def read_exact(sock, count):
    data=b''
    while len(data) < count:
        part=sock.recv(count-len(data))
        if not part:raise EOFError()
        data+=part
    return data


def relay(peer):
    upstream=socket.create_connection(('127.0.0.1', web.server_port), timeout=5)
    try:
        if protocol == 'socks':peer.sendall(b'\x05\x00\x00\x01'+bytes(6))
        else:peer.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        while True:
            ready,_,_=select.select([peer, upstream],[],[],5)
            if not ready:return
            for source in ready:
                data=source.recv(65536)
                if not data:return
                (upstream if source is peer else peer).sendall(data)
    finally:upstream.close()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        peer=self.request;peer.settimeout(5)
        try:
            if protocol == 'socks':
                version,count=read_exact(peer,2);methods=read_exact(peer,count)
                if version != 5 or 2 not in methods:return
                peer.sendall(b'\x05\x02')
                version,length=read_exact(peer,2);username=read_exact(peer,length)
                length=read_exact(peer,1)[0];password=read_exact(peer,length)
                if version!=1 or username!=b'fixture-user' or password!=b'synthetic-password':
                    peer.sendall(b'\x01\x01');return
                peer.sendall(b'\x01\x00')
                version,command,reserved,kind=read_exact(peer,4)
                if (version,command,reserved,kind)!=(5,1,0,3):return
                host=read_exact(peer,read_exact(peer,1)[0]);port=int.from_bytes(read_exact(peer,2),'big')
                if host!=b'localhost' or port!=web.server_port:return
            else:
                data=b''
                while b'\r\n\r\n' not in data and len(data)<8192:data+=read_exact(peer,1)
                lines=data.split(b'\r\n')
                expected=f'CONNECT localhost:{web.server_port} HTTP/1.1'.encode()
                auth=b'proxy-authorization: basic '+base64.b64encode(b'fixture-user:synthetic-password').lower()
                if lines[0]!=expected or auth not in [line.lower() for line in lines[1:]]:return
            relay(peer)
        except (OSError, EOFError):pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True


proxy=Server(('127.0.0.1',0),Handler)
print(str(proxy.server_address[1])+' '+str(web.server_port),flush=True)
proxy.serve_forever()
