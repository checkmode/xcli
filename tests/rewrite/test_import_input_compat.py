"""Compare disposable fixed-proxy input validation with the legacy panel."""
from contextlib import closing
import http.client
import base64
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest

from test_panel_password_compat import free_port, ready, stop

PANEL = os.environ.get('XCLI_LEGACY_PANEL', '')
DRIVER = os.environ.get('XCLI_IMPORT_DRIVER', '')
REQUEST_DRIVER = os.environ.get('XCLI_IMPORT_REQUEST_DRIVER', '')


@unittest.skipUnless(PANEL and DRIVER and Path(PANEL).is_file() and Path(DRIVER).is_file(),
                     'set legacy panel and import driver paths')
class ImportInputCompatibility(unittest.TestCase):
    def test_fixed_proxy_batch_validation(self):
        with tempfile.TemporaryDirectory(prefix='xcli-import-input-') as folder:
            root = Path(folder); state = root / 'state'; state.mkdir()
            service = root / 'xray-gateway-import'; service.mkdir()
            (service / 'report.json').write_text(json.dumps({'id':'','status':'idle','message':'fixture','rows':[], 'updated':int(time.time())}))
            key = root / 'key'; key.write_bytes(bytes(range(32))); key.chmod(0o600)
            settings = root / 'settings.json'
            settings.write_text(json.dumps({'origin':'https://testserver','domain':'testserver','public_ip':'203.0.113.2',
                'reality_sni':'example.com','reality_public':'p'*43,'short_id':'aabbccdd','ws_path':'/connect/test'}))
            with closing(sqlite3.connect(state / 'gateway.sqlite')) as db:
                db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)')
                db.execute('INSERT INTO admin VALUES(1,?)', ('000102030405060708090a0b0c0d0e0f:'
                    'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf',))
                db.commit()
            port = free_port()
            panel = subprocess.Popen([PANEL,'--state',str(state),'--settings',str(settings),'--static',str(root),
                '--secret-key',str(key),'--port',str(port),'--offline','--no-auto-backup'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            driver = request_driver = None
            def request(path, body, cookie='', csrf=''):
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
                headers = {'Origin':'https://testserver','Content-Type':'application/json'}
                if cookie: headers['Cookie'] = cookie
                if csrf: headers['X-CSRF-Token'] = csrf
                try:
                    conn.request('POST', path, json.dumps(body).encode(), headers)
                    response=conn.getresponse(); return response.status, dict((k.lower(), v) for k,v in response.getheaders()), json.loads(response.read())
                finally: conn.close()
            try:
                ready(panel, port)
                code, headers, result = request('/api/login', {'username':'admin','password':'fixture-password'})
                self.assertEqual(code, 200)
                cookie=headers['set-cookie'].split(';',1)[0]; csrf=result['csrf']
                driver=subprocess.Popen([DRIVER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
                if REQUEST_DRIVER and Path(REQUEST_DRIVER).is_file():
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    request_driver=subprocess.Popen([REQUEST_DRIVER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
                    def decrypt(blob):
                        return json.loads(AESGCM(bytes(range(32))).decrypt(blob[4:16],blob[32:]+blob[16:32],b'xcli:proxy-import:request:v1'))
                cases=['1.1.1.1:80:user:pass', '  \n\t\r\n1.1.1.1:0080:user:pass:extra\r\n8.8.8.8:443:a:b',
                    '', '\n \t', '127.0.0.1:80:u:p', '192.0.2.1:80:u:p', '100.64.0.1:80:u:p',
                    '1.1.1.01:80:u:p', 'example.com:80:u:p', '224.0.0.1:80:u:p', '1.1.1.1:0:u:p',
                    '1.1.1.1:65536:u:p', '1.1.1.1:80:u:', '1.1.1.1:80:u:p\x7f',
                    '1.1.1.1:80:u:p\n1.1.1.1:00080:x:y',
                    ''.join(f'1.1.1.1:{i}:u:p\n' for i in range(1,21)),
                    ''.join(f'1.1.1.1:{i}:u:p\n' for i in range(1,22))]
                for index, text in enumerate(cases):
                    with self.subTest(case=index):
                        driver.stdin.write(json.dumps({'text':text})+'\n'); driver.stdin.flush()
                        parsed=json.loads(driver.stdout.readline())
                        body={'action':'preview','protocol':'socks','label':'fixture','text':text}
                        code,_,_=request('/api/proxy-import', body,cookie,csrf)
                        self.assertEqual(code == 202, parsed['ok'])
                        if request_driver:
                            request_driver.stdin.write(json.dumps(body)+'\n');request_driver.stdin.flush()
                            prepared=json.loads(request_driver.stdout.readline())
                            self.assertEqual(code == 202, prepared['ok'])
                            if code == 202:
                                old=decrypt((state / 'proxy-import/request.xgb').read_bytes())
                                new=decrypt(base64.b64decode(prepared['encrypted']))
                                for value in (old,new):
                                    value.pop('id');value.pop('requested_at')
                                self.assertEqual(old,new)
                        if code == 202:
                            (state / 'proxy-import/request.xgb').unlink()
                if request_driver:
                    controls = [
                        {'action':'manage','operation':'disable','tag':'residential-27'},
                        {'action':'manage','operation':'restore','tag':'residential-27'},
                        {'action':'manage','operation':'edit','tag':'residential-27','changes':{
                            'label':' fixture ', 'address':'8.8.8.8','port':443,'protocol':'socks',
                            'username':'synthetic-user','password':'synthetic-password'}},
                        {'action':'manage','operation':'edit','tag':'residential-27','changes':{
                            'label':'fixture','address':'node.example.com','port':443,'protocol':'vmess',
                            'uuid':'11111111-2222-3333-4444-555555555555','network':'ws','tls':True}},
                        {'action':'manage','operation':'edit','tag':'residential-27','changes':{
                            'label':'fixture','address':'8.8.8.8','port':443,'protocol':'http','uuid':'not-allowed'}},
                        {'action':'manage','operation':'disable','tag':'residential-xx'},
                        {'action':'manage','operation':'disable','tag':'residential-27','extra':True},
                    ]
                    for index, body in enumerate(controls):
                        with self.subTest(control=index):
                            code,_,_=request('/api/proxy-import',body,cookie,csrf)
                            request_driver.stdin.write(json.dumps(body)+'\n');request_driver.stdin.flush()
                            prepared=json.loads(request_driver.stdout.readline())
                            self.assertEqual(code == 202, prepared['ok'])
                            if code == 202:
                                old=decrypt((state / 'proxy-import/request.xgb').read_bytes())
                                new=decrypt(base64.b64decode(prepared['encrypted']))
                                for value in (old,new):
                                    value.pop('id');value.pop('requested_at')
                                self.assertEqual(old,new)
                                (state / 'proxy-import/request.xgb').unlink()
                    preview_id='a'*32
                    (service / 'report.json').write_text(json.dumps({'id':preview_id,'status':'ready',
                        'message':'fixture','rows':[],'updated':int(time.time()),'expires':int(time.time())+600}))
                    body={'action':'apply','preview_id':preview_id}
                    self.assertEqual(request('/api/proxy-import',body,cookie,csrf)[0],202)
                    request_driver.stdin.write(json.dumps(body)+'\n');request_driver.stdin.flush()
                    prepared=json.loads(request_driver.stdout.readline());self.assertTrue(prepared['ok'])
                    old=decrypt((state / 'proxy-import/request.xgb').read_bytes())
                    new=decrypt(base64.b64decode(prepared['encrypted']))
                    for value in (old,new):value.pop('id');value.pop('requested_at')
                    self.assertEqual(old,new)
            finally:
                if driver:
                    driver.stdin.close();driver.wait(timeout=10);driver.stdout.close()
                if request_driver:
                    request_driver.stdin.close();request_driver.wait(timeout=10);request_driver.stdout.close()
                stop(panel)
