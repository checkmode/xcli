#!/usr/bin/env python3
"""Disposable Xray stand-in for local process and authenticated SOCKS tests."""
import json
import select
import socket
import socketserver
import sys

assert sys.argv[1:] == ['run', '-config', 'stdin:']
config = json.load(sys.stdin)
inbound = config['inbounds'][0]
assert inbound['listen'] == '127.0.0.1' and inbound['protocol'] == 'socks'
assert config['outbounds'][0]['protocol'] == 'vmess'
account = inbound['settings']['accounts'][0]


def read_exact(sock, count):
    data=b''
    while len(data)<count:
        part=sock.recv(count-len(data))
        if not part:raise EOFError()
        data+=part
    return data


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        peer=self.request;peer.settimeout(5)
        try:
            version,count=read_exact(peer,2);methods=read_exact(peer,count)
            if version!=5 or 2 not in methods:return
            peer.sendall(b'\x05\x02')
            version,length=read_exact(peer,2);username=read_exact(peer,length)
            length=read_exact(peer,1)[0];password=read_exact(peer,length)
            if version!=1 or username.decode()!=account['user'] or password.decode()!=account['pass']:
                peer.sendall(b'\x01\x01');return
            peer.sendall(b'\x01\x00')
            version,command,reserved,kind=read_exact(peer,4)
            if (version,command,reserved,kind)!=(5,1,0,3):return
            host=read_exact(peer,read_exact(peer,1)[0]);port=int.from_bytes(read_exact(peer,2),'big')
            if host!=b'localhost':return
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


Server(('127.0.0.1',inbound['port']),Handler).serve_forever()
