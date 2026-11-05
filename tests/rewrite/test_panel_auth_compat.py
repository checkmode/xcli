"""Compare Rust auth with the actual legacy C++ panel using disposable databases.

Requires XCLI_LEGACY_PANEL and XCLI_AUTH_DRIVER. Never use real credentials.
"""
import base64
import hashlib
import hmac
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

PANEL = os.environ.get('XCLI_LEGACY_PANEL', '')
DRIVER = os.environ.get('XCLI_AUTH_DRIVER', '')


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@unittest.skipUnless(PANEL and DRIVER and Path(PANEL).is_file() and Path(DRIVER).is_file(), 'set XCLI_LEGACY_PANEL and XCLI_AUTH_DRIVER for isolated auth comparison')
class PanelAuthCompatibility(unittest.TestCase):
    def test_login_totp_recovery_session_and_logout(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        with tempfile.TemporaryDirectory(prefix='xcli-auth-compat-') as folder:
            root=Path(folder); old=root/'old'; old.mkdir(); settings=root/'settings.json'; key_file=root/'security.key'
            settings.write_text(json.dumps({'origin':'https://testserver','domain':'testserver','public_ip':'203.0.113.2',
                'reality_sni':'example.com','reality_public':'p'*43,'short_id':'aabbccdd','ws_path':'/connect/test'}))
            key=bytes(range(32)); key_file.write_bytes(key); key_file.chmod(0o600)
            salt=bytes(range(16)); password='fixture-password'
            encoded=salt.hex()+':'+hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1,dklen=32).hex()
            db=sqlite3.connect(old/'gateway.sqlite')
            db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)')
            db.execute('INSERT INTO admin VALUES(1,?)',(encoded,)); db.commit(); db.close()
            listen=free_port()
            panel=subprocess.Popen([PANEL,'--state',str(old),'--settings',str(settings),'--static',str(root),
                '--secret-key',str(key_file),'--port',str(listen),'--offline','--no-auto-backup'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            driver=None
            def request(path,method='GET',body=None,cookie='',csrf=''):
                conn=http.client.HTTPConnection('127.0.0.1',listen,timeout=15)
                headers={'Origin':'https://testserver','Content-Type':'application/json'}
                if cookie: headers['Cookie']='xg_session='+cookie
                if csrf: headers['X-CSRF-Token']=csrf
                try:
                    conn.request(method,path,body=json.dumps(body).encode() if body is not None else None,headers=headers)
                    res=conn.getresponse(); return res.status,dict((k.lower(),v) for k,v in res.getheaders()),json.loads(res.read())
                finally: conn.close()
            def rust(data):
                driver.stdin.write(json.dumps(data)+'\n'); driver.stdin.flush()
                line=driver.stdout.readline(); self.assertTrue(line,'Rust auth driver stopped'); return json.loads(line)
            try:
                for _ in range(100):
                    if panel.poll() is not None: self.fail('disposable legacy panel failed to start')
                    try:
                        if request('/healthz')[0]==200: break
                    except OSError: time.sleep(.05)
                else: self.fail('disposable legacy panel did not become ready')
                secret=b'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; nonce=bytes(range(12)); sealed=AESGCM(key).encrypt(nonce,secret,b'xcli:mfa:v1')
                frame=base64.b64encode(b'XGB1'+nonce+sealed[-16:]+sealed[:-16]).decode()
                recovery='fixture-recovery-code'; recovery_hash=hashlib.sha256(recovery.encode()).hexdigest()
                db=sqlite3.connect(old/'gateway.sqlite')
                db.execute('UPDATE mfa SET enabled=1,secret=?,last_step=-1 WHERE id=1',(frame,))
                db.execute('INSERT INTO recovery_codes(hash,used) VALUES(?,0)',(recovery_hash,)); db.commit()
                new=root/'rust.sqlite'; dst=sqlite3.connect(new); db.backup(dst); dst.close(); db.close()
                driver=subprocess.Popen([DRIVER,str(new),key.hex()],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,text=True,bufsize=1)
                now=int(time.time()); step=now//30
                mac=hmac.new(base64.b32decode(secret),step.to_bytes(8,'big'),hashlib.sha1).digest(); offset=mac[-1]&15
                code=f'{(int.from_bytes(mac[offset:offset+4],"big")&0x7fffffff)%1000000:06d}'
                valid_codes=set()
                for candidate in (step-1,step,step+1):
                    digest=hmac.new(base64.b32decode(secret),candidate.to_bytes(8,'big'),hashlib.sha1).digest(); pos=digest[-1]&15
                    valid_codes.add(f'{(int.from_bytes(digest[pos:pos+4],"big")&0x7fffffff)%1000000:06d}')
                wrong_code=next(f'{value:06d}' for value in range(4) if f'{value:06d}' not in valid_codes)
                def attempt(pwd, factor, tick):
                    status,headers,body=request('/api/login','POST',{'username':'admin','password':pwd,'code':factor})
                    other=rust({'op':'login','username':'admin','password':pwd,'code':factor,'ip':'127.0.0.1','now':now,'monotonic':tick})
                    self.assertEqual(status==200,other['ok'])
                    if status!=200:
                        self.assertEqual(status,401); self.assertEqual(other['error'],'InvalidCredentials'); return None
                    return headers['set-cookie'].split(';')[0].split('=',1)[1],body['csrf'],other['value']
                attempt('wrong','',0); attempt(password,wrong_code,1)
                first=attempt(password,code,2); self.assertIsNotNone(first)
                attempt(password,code,3)
                second=attempt(password,recovery,4); self.assertIsNotNone(second)
                attempt(password,recovery,5)
                old_cookie,old_csrf,new_session=first
                self.assertEqual(request('/api/session',cookie=old_cookie)[0],200)
                self.assertTrue(rust({'op':'session','cookie':new_session['cookie'],'csrf':None,'now':now})['ok'])
                self.assertEqual(request('/api/logout','POST',{},old_cookie,'bad')[0],403)
                self.assertEqual(rust({'op':'logout','cookie':new_session['cookie'],'csrf':'bad','now':now})['error'],'Csrf')
                self.assertEqual(request('/api/logout','POST',{},old_cookie,old_csrf)[0],200)
                self.assertTrue(rust({'op':'logout','cookie':new_session['cookie'],'csrf':new_session['csrf'],'now':now})['ok'])
                self.assertEqual(request('/api/session',cookie=old_cookie)[0],401)
                self.assertEqual(rust({'op':'session','cookie':new_session['cookie'],'csrf':None,'now':now})['error'],'Unauthorized')
                def state(path):
                    con=sqlite3.connect(path)
                    try: return (con.execute('SELECT last_step FROM mfa').fetchone(),con.execute('SELECT used FROM recovery_codes').fetchone(),
                        con.execute('SELECT action FROM events ORDER BY id').fetchall(),con.execute('SELECT count(*) FROM sessions').fetchone())
                    finally: con.close()
                self.assertEqual(state(old/'gateway.sqlite'),state(new))
            finally:
                if driver is not None:
                    driver.stdin.close(); driver.wait(timeout=10); driver.stdout.close()
                panel.terminate()
                try: panel.wait(timeout=15)
                except subprocess.TimeoutExpired: panel.kill(); panel.wait(timeout=5)
