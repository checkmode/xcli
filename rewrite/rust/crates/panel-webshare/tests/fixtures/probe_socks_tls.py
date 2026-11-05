"""Synthetic SOCKS5 and HTTPS endpoints, bound only to loopback."""
import http.server
import select
import socket
import socketserver
import ssl
import sys
import threading
from urllib.parse import urlsplit

certificate,key,mode=sys.argv[1:]


class Http(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def do_GET(self):
        path=urlsplit(self.path).path
        if path=='/trace':
            ip='127.0.0.1' if mode=='private' else '8.8.8.8'
            loc='JP' if mode=='wrong-country' else 'US'
            data=(f'ip={ip}\nloc={loc}\n').encode()
            if mode=='oversize':data=b'x'*32769
        elif path=='/dns-query':
            data=b'bad' if mode=='dnsfail' else b'XG\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
        else:self.send_response(404);self.end_headers();return
        self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers()
        try:self.wfile.write(data)
        except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass


web=http.server.ThreadingHTTPServer(('127.0.0.1',0),Http)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certificate,key)
web.socket=context.wrap_socket(web.socket,server_side=True)
threading.Thread(target=web.serve_forever,daemon=True).start()


def read_exact(sock,size):
    data=b''
    while len(data)<size:
        chunk=sock.recv(size-len(data))
        if not chunk:raise EOFError()
        data+=chunk
    return data


class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        peer=self.request;peer.settimeout(5)
        try:
            version,count=read_exact(peer,2);methods=read_exact(peer,count)
            if version!=5 or 2 not in methods:return
            peer.sendall(b'\x05\x02')
            version,length=read_exact(peer,2);username=read_exact(peer,length);length=read_exact(peer,1)[0];password=read_exact(peer,length)
            if version!=1 or username!=b'fixture-us-1' or password!=b'synthetic-password':peer.sendall(b'\x01\x01');return
            peer.sendall(b'\x01\x00')
            version,command,reserved,kind=read_exact(peer,4)
            if (version,command,reserved,kind)!=(5,1,0,3):return
            length=read_exact(peer,1)[0];host=read_exact(peer,length);port=int.from_bytes(read_exact(peer,2),'big')
            if host!=b'localhost' or port!=web.server_port:return
            upstream=socket.create_connection(('127.0.0.1',port),timeout=5)
            try:
                peer.sendall(b'\x05\x00\x00\x01'+bytes(6))
                while True:
                    ready,_,_=select.select([peer,upstream],[],[],5)
                    if not ready:return
                    for source in ready:
                        data=source.recv(65536)
                        if not data:return
                        (upstream if source is peer else peer).sendall(data)
            finally:upstream.close()
        except (OSError,EOFError):pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True


proxy=Server(('127.0.0.1',0),Socks)
print(str(proxy.server_address[1])+' '+str(web.server_port),flush=True)
proxy.serve_forever()
