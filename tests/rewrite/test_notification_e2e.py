"""Exercise the real delivery subprocess only inside an isolated Linux network namespace.

The receiver uses a locally assigned test address and synthetic credentials.
The test refuses to run in the host network namespace.
"""
from contextlib import closing
import hashlib
import hmac
import http.server
import json
import os
from pathlib import Path
import queue
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import unittest

from test_panel_http_integration import PANEL, free_port, request, stop, wait_ready

CERT = os.environ.get('XCLI_TEST_NOTIFY_CERT', '')
KEY = os.environ.get('XCLI_TEST_NOTIFY_KEY', '')
HOST_NET_NS = os.environ.get('XCLI_TEST_HOST_NET_NS', '')


@unittest.skipUnless(PANEL and CERT and KEY and HOST_NET_NS, 'requires the isolated namespace fixture')
class NotificationEndToEnd(unittest.TestCase):
    def test_actual_subprocess_delivers_signed_event_to_isolated_receiver(self):
        self.assertNotEqual(os.readlink('/proc/self/ns/net'), HOST_NET_NS,
                            'refusing to run in the host network namespace')
        addresses = subprocess.check_output(['/usr/sbin/ip', '-o', '-4', 'addr', 'show', 'dev', 'lo'], text=True)
        self.assertIn('1.1.1.1/32', addresses)
        resolved = {entry[4][0] for entry in socket.getaddrinfo('receiver.fixture', 443, type=socket.SOCK_STREAM)}
        self.assertEqual(resolved, {'1.1.1.1'})
        received = queue.Queue()
        bearer, signing = 'synthetic-bearer', 'synthetic-signing-secret'
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
                timestamp = self.headers.get('X-Xcli-Timestamp', '')
                expected = 'sha256=' + hmac.new(signing.encode(), timestamp.encode()+b'.'+body, hashlib.sha256).hexdigest()
                if (self.headers.get('Authorization') != 'Bearer '+bearer or
                    not hmac.compare_digest(self.headers.get('X-Xcli-Signature', ''), expected)):
                    self.send_response(403); self.end_headers(); return
                received.put((self.headers.get('X-Xcli-Event-Id'), json.loads(body)))
                self.send_response(204); self.end_headers()
        server = http.server.ThreadingHTTPServer(('1.1.1.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(CERT, KEY)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        panel = None
        try:
            with tempfile.TemporaryDirectory(prefix='xcli-notify-e2e-') as folder:
                root=Path(folder); key=root/'security.key'; key.write_bytes(bytes(range(32))); key.chmod(0o600)
                db_file=root/'gateway.sqlite'
                with closing(sqlite3.connect(db_file)) as db:
                    db.executescript('''CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL);
                        CREATE TABLE sessions(hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
                        CREATE TABLE mfa(id INTEGER PRIMARY KEY,enabled INTEGER NOT NULL,secret TEXT NOT NULL,last_step INTEGER NOT NULL);
                        CREATE TABLE mfa_sessions(hash TEXT PRIMARY KEY);
                        CREATE TABLE recovery_codes(hash TEXT PRIMARY KEY,used INTEGER NOT NULL DEFAULT 0);
                        CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
                        CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                        CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL,uuid TEXT NOT NULL UNIQUE,token TEXT NOT NULL UNIQUE,
                            enabled INTEGER NOT NULL DEFAULT 1,quota INTEGER NOT NULL DEFAULT 0,expires INTEGER NOT NULL DEFAULT 0,
                            upload INTEGER NOT NULL DEFAULT 0,download INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL,deleted INTEGER NOT NULL DEFAULT 0);
                        INSERT INTO mfa VALUES(1,0,'',-1);
                        INSERT INTO admin VALUES(1,'000102030405060708090a0b0c0d0e0f:afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf');''')
                    db.commit()
                settings=root/'settings.json'; settings.write_text(json.dumps({'origin':'https://testserver','domain':'testserver'}))
                port=free_port()
                panel=subprocess.Popen([PANEL,'--experimental','--db',str(db_file),'--secret-key',str(key),
                    '--origin','https://testserver','--settings',str(settings),'--port',str(port),
                    '--experimental-notification-delivery','true'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                wait_ready(panel,port)
                login=json.dumps({'username':'admin','password':'fixture-password'}).encode()
                status,headers,data=request(port,'/api/login','POST',login)
                self.assertEqual(status,200)
                cookie=headers['set-cookie'].split(';',1)[0]; csrf=json.loads(data)['csrf']
                config={'enabled':False,'url':f'https://receiver.fixture:{server.server_port}/hook?token=synthetic-only',
                    'bearer':bearer,'signing_secret':signing,'current_password':'fixture-password'}
                status,_,_=request(port,'/api/notifications','PUT',json.dumps(config).encode(),cookie,csrf)
                self.assertEqual(status,200)
                status,_,data=request(port,'/api/notifications',cookie=cookie)
                self.assertEqual(status,200);self.assertTrue(json.loads(data)['delivery_active'])
                status,_,data=request(port,'/api/notifications/test','POST',cookie=cookie,csrf=csrf)
                self.assertEqual(status,200); event_id=json.loads(data)['id']
                self.assertEqual(request(port,'/api/notifications/test','POST',cookie=cookie,csrf=csrf)[0],429)
                delivered_id, payload=received.get(timeout=18)
                self.assertEqual(delivered_id,event_id);self.assertEqual(payload['id'],event_id);self.assertEqual(payload['event'],'test')
                deadline=time.monotonic()+8
                while time.monotonic()<deadline:
                    status,_,data=request(port,'/api/notifications',cookie=cookie)
                    row=next((value for value in json.loads(data)['deliveries'] if value['id']==event_id),None)
                    if row and row['status']=='delivered':break
                    time.sleep(.1)
                else:self.fail('successful delivery was not committed')
                self.assertEqual(row['attempts'],1);self.assertEqual(row['http_status'],204)
                for secret in (b'synthetic-only',bearer.encode(),signing.encode()): self.assertNotIn(secret,data)
                with closing(sqlite3.connect(db_file)) as db:
                    stored=''.join(db.execute('SELECT url,bearer,signing FROM notification_config').fetchone())
                    for secret in ('synthetic-only',bearer,signing):self.assertNotIn(secret,stored)
        finally:
            stop(panel);server.shutdown();server.server_close();server_thread.join(timeout=5)
