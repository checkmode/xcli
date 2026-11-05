"""Exercise 2FA and its QR through the isolated Node/Rust chain."""
import base64
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

from test_panel_http_integration import PANEL, WEB, free_port, request, stop, wait_ready
from test_panel_security_compat import decode_qr, totp


@unittest.skipUnless(PANEL and Path(PANEL).is_file(), 'set XCLI_PANEL_SERVICE')
class MfaHttpIntegration(unittest.TestCase):
    def test_setup_qr_and_recovery_over_http(self):
        with tempfile.TemporaryDirectory(prefix='xcli-mfa-http-') as folder:
            root=Path(folder);key=root/'key';key.write_bytes(bytes(range(32)));key.chmod(0o600)
            db_file=root/'gateway.sqlite'
            with closing(sqlite3.connect(db_file)) as db:
                db.executescript('''
                    CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL);
                    CREATE TABLE sessions(hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
                    CREATE TABLE mfa(id INTEGER PRIMARY KEY,enabled INTEGER NOT NULL,secret TEXT NOT NULL,last_step INTEGER NOT NULL,
                        pending TEXT NOT NULL DEFAULT '',pending_expires INTEGER NOT NULL DEFAULT 0,pending_session TEXT NOT NULL DEFAULT '');
                    CREATE TABLE mfa_sessions(hash TEXT PRIMARY KEY);
                    CREATE TABLE recovery_codes(hash TEXT PRIMARY KEY,used INTEGER NOT NULL DEFAULT 0);
                    CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
                    CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                    CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL,uuid TEXT NOT NULL UNIQUE,token TEXT NOT NULL UNIQUE,
                        enabled INTEGER NOT NULL DEFAULT 1,quota INTEGER NOT NULL DEFAULT 0,expires INTEGER NOT NULL DEFAULT 0,
                        upload INTEGER NOT NULL DEFAULT 0,download INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL,deleted INTEGER NOT NULL DEFAULT 0);
                    INSERT INTO mfa(id,enabled,secret,last_step) VALUES(1,0,'',-1);
                ''')
                db.execute('INSERT INTO admin VALUES(1,?)',('000102030405060708090a0b0c0d0e0f:afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf',));db.commit()
            settings=root/'settings.json';settings.write_text(json.dumps({'origin':'https://testserver','domain':'testserver'}))
            port=free_port();panel=None;gateway=None
            try:
                panel=subprocess.Popen([PANEL,'--experimental','--db',str(db_file),'--secret-key',str(key),'--origin','https://testserver',
                    '--settings',str(settings),'--port',str(port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                wait_ready(panel,port)
                if WEB:
                    web_port=free_port();env=dict(os.environ,XCLI_CORE_PORT=str(port),XCLI_WEB_PORT=str(web_port))
                    gateway=subprocess.Popen(['node',WEB],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    wait_ready(gateway,web_port);port=web_port
                login=json.dumps({'username':'admin','password':'fixture-password','code':''}).encode()
                status,headers,data=request(port,'/api/login','POST',login)
                self.assertEqual(status,200);cookie=headers['set-cookie'].split(';',1)[0];csrf=json.loads(data)['csrf']
                self.assertEqual(request(port,'/api/security')[0],401)
                setup=json.dumps({'current_password':'fixture-password'}).encode()
                self.assertEqual(request(port,'/api/security/setup','POST',setup,cookie,'bad')[0],403)
                status,_,data=request(port,'/api/security/setup','POST',setup,cookie,csrf)
                self.assertEqual(status,200);bundle=json.loads(data);secret=bundle['secret']
                qr=root/'synthetic.png';qr.write_bytes(base64.b64decode(bundle['qr'].split(',',1)[1]))
                self.assertTrue(qr.read_bytes().startswith(b'\x89PNG\r\n\x1a\n'))
                decoded=decode_qr(qr)
                if os.environ.get('XCLI_REQUIRE_QR_DECODER'):self.assertIsNotNone(decoded,'QR decoder required')
                if decoded is not None:
                    self.assertEqual(decoded,'otpauth://totp/testserver%3Aadmin?secret='+secret+'&issuer=testserver&algorithm=SHA1&digits=6&period=30')
                body=json.dumps({'current_password':'fixture-password','code':totp(secret)}).encode()
                status,_,data=request(port,'/api/security/enable','POST',body,cookie,csrf)
                self.assertEqual(status,200);codes=json.loads(data)['recovery_codes'];self.assertEqual(len(codes),10)
                self.assertTrue(json.loads(request(port,'/api/security',cookie=cookie)[2])['enabled'])
                body=json.dumps({'current_password':'fixture-password','code':codes[0]}).encode()
                status,_,data=request(port,'/api/security/recovery','POST',body,cookie,csrf)
                self.assertEqual(status,200);fresh=json.loads(data)['recovery_codes']
                notification={'current_password':'fixture-password','code':fresh[0],'enabled':False,
                    'url':'https://127.0.0.1/private','bearer':'synthetic-only-token'}
                self.assertEqual(request(port,'/api/notifications','PUT',json.dumps(notification).encode(),cookie,csrf)[0],422)
                notification['url']='https://receiver.example.net/path?key=synthetic-only'
                self.assertEqual(request(port,'/api/notifications','PUT',json.dumps(notification).encode(),cookie,csrf)[0],200)
                status,_,state=request(port,'/api/notifications',cookie=cookie)
                self.assertEqual(status,200);self.assertEqual(json.loads(state)['destination'],'receiver.example.net')
                self.assertNotIn(b'synthetic-only',state)
                body=json.dumps({'current_password':'fixture-password','code':fresh[1]}).encode()
                self.assertEqual(request(port,'/api/security/disable','POST',body,cookie,csrf)[0],200)
                self.assertEqual(request(port,'/api/session',cookie=cookie)[0],401)
            finally:stop(gateway);stop(panel)
