"""Compare administrator password changes using disposable C++ and Rust panels."""
import hashlib
from contextlib import closing
import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
import unittest

LEGACY = os.environ.get('XCLI_LEGACY_PANEL', '')
RUST = os.environ.get('XCLI_PANEL_SERVICE', '')


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def request(port, path, method='GET', body=None, cookie='', csrf=''):
    headers = {'Origin':'https://testserver', 'Content-Type':'application/json'}
    if cookie: headers['Cookie'] = cookie
    if csrf: headers['X-CSRF-Token'] = csrf
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=20)
    try:
        conn.request(method, path, json.dumps(body).encode() if body is not None else None, headers)
        response = conn.getresponse()
        return response.status, dict((k.lower(),v) for k,v in response.getheaders()), response.read()
    finally:
        conn.close()


def ready(process, port):
    for _ in range(100):
        if process.poll() is not None: raise AssertionError('disposable panel failed to start')
        try:
            if request(port, '/healthz')[0] == 200: return
        except OSError: time.sleep(.05)
    raise AssertionError('disposable panel did not become ready')


def stop(process):
    if process is None: return
    process.terminate()
    try: process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait(timeout=5)
        raise AssertionError('disposable panel did not stop')


@unittest.skipUnless(LEGACY and RUST and Path(LEGACY).is_file() and Path(RUST).is_file(), 'set legacy and Rust panel paths')
class PasswordCompatibility(unittest.TestCase):
    def test_old_and_new_password_hashes_and_session_invalidation(self):
        with tempfile.TemporaryDirectory(prefix='xcli-password-compat-') as folder:
            root=Path(folder); old=root/'old'; new=root/'new'; old.mkdir(); new.mkdir()
            key=root/'key'; key.write_bytes(bytes(range(32))); key.chmod(0o600)
            settings=root/'settings.json'; settings.write_text(json.dumps({'origin':'https://testserver','domain':'testserver',
                'public_ip':'203.0.113.2','reality_sni':'example.com','reality_public':'p'*43,
                'short_id':'aabbccdd','ws_path':'/connect/test'}))
            password='fixture-password'; replacement='new-fixture-password'; salt=bytes(range(16))
            encoded=salt.hex()+':'+hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1,dklen=32).hex()
            with closing(sqlite3.connect(old/'gateway.sqlite')) as db:
                db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)')
                db.execute('INSERT INTO admin VALUES(1,?)',(encoded,))
                db.commit()
            ports=[free_port(),free_port()]; legacy=None; rust=None
            while ports[0] == ports[1]: ports[1] = free_port()
            try:
                legacy=subprocess.Popen([LEGACY,'--state',str(old),'--settings',str(settings),'--static',str(root),
                    '--secret-key',str(key),'--port',str(ports[0]),'--offline','--no-auto-backup'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                ready(legacy,ports[0])
                source=sqlite3.connect(old/'gateway.sqlite'); target=sqlite3.connect(new/'gateway.sqlite')
                try: source.backup(target)
                finally: source.close();target.close()
                rust=subprocess.Popen([RUST,'--experimental','--db',str(new/'gateway.sqlite'),'--secret-key',str(key),
                    '--origin','https://testserver','--port',str(ports[1])],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                ready(rust,ports[1])
                sessions=[]
                for port in ports:
                    per_panel=[]
                    for _ in range(2):
                        status,headers,body=request(port,'/api/login','POST',{'username':'admin','password':password,'code':''})
                        self.assertEqual(status,200)
                        per_panel.append((headers['set-cookie'].split(';',1)[0],json.loads(body)['csrf']))
                    sessions.append(per_panel)
                for port,per_panel in zip(ports,sessions):
                    cookie,csrf=per_panel[0]
                    wrong={'current_password':'wrong','new_password':replacement,'code':''}
                    valid={'current_password':password,'new_password':replacement,'code':''}
                    self.assertEqual(request(port,'/api/password','POST',valid,cookie,'invalid')[0],403)
                    self.assertEqual(request(port,'/api/password','POST',wrong,cookie,csrf)[0],403)
                    self.assertEqual(request(port,'/api/password','POST',{'current_password':password,'new_password':'short'},cookie,csrf)[0],422)
                    self.assertEqual(request(port,'/api/password','POST',valid,cookie,csrf)[0],200)
                    for old_cookie,_ in per_panel:
                        self.assertEqual(request(port,'/api/session',cookie=old_cookie)[0],401)
                hashes=[]
                for directory in (old,new):
                    db=sqlite3.connect(directory/'gateway.sqlite')
                    try:
                        hashes.append(db.execute('SELECT password FROM admin WHERE id=1').fetchone()[0])
                        self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE action='password_changed'").fetchone()[0],1)
                    finally: db.close()
                for directory,other_hash in zip((old,new),reversed(hashes)):
                    with closing(sqlite3.connect(directory/'gateway.sqlite')) as db:
                        db.execute('UPDATE admin SET password=? WHERE id=1',(other_hash,))
                        db.commit()
                for port in ports:
                    self.assertEqual(request(port,'/api/login','POST',{'username':'admin','password':replacement,'code':''})[0],200)
            finally:
                stop(rust);stop(legacy)
