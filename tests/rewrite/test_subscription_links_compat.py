"""Compare synthetic connection links and generic subscriptions with C++."""
import http.client
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from test_panel_auth_compat import free_port

PANEL=os.environ.get('XCLI_LEGACY_PANEL','')
DRIVER=os.environ.get('XCLI_LINKS_DRIVER','')
RUST_PANEL=os.environ.get('XCLI_PANEL_SERVICE','')


@unittest.skipUnless(PANEL and DRIVER and Path(PANEL).is_file() and Path(DRIVER).is_file(),
                     'set XCLI_LEGACY_PANEL and XCLI_LINKS_DRIVER')
class SubscriptionLinksCompatibility(unittest.TestCase):
    def test_links_and_generic_subscription_match(self):
        for node_address_ip in (False,True):
            with self.subTest(node_address_ip=node_address_ip):self.scenario(node_address_ip)

    def scenario(self,node_address_ip):
        with tempfile.TemporaryDirectory(prefix='xcli-links-compat-') as folder:
            root=Path(folder);state=root/'state';state.mkdir();key=root/'key';key.write_bytes(bytes(range(32)));key.chmod(0o600)
            ws='/connect/test'
            settings={'origin':'https://testserver','domain':'testserver','public_ip':'203.0.113.2','node_address_ip':node_address_ip,
                'reality_sni':'www.bing.com','reality_public':'p'*43,'short_id':'0123456789abcdef','ws_path':ws,
                'hysteria2_port':443,'vmess_ws_path':ws+'/vmess','vmess_port':10081,
                'residential_exits':[{'tag':'residential-01','label':'住宅 HK','exit_ip':'8.8.8.8','country':'HK',
                    'ws_path':ws+'/residential-01','port':11001,'hysteria2':True},
                    {'tag':'residential-02','label':'住宅 US','exit_ip':'1.1.1.1','country':'US',
                    'ws_path':ws+'/residential-02','port':11002},
                    {'tag':'residential-11','label':'动态 US','exit_ip':'','country':'US',
                    'ws_path':ws+'/residential-11','port':10110,'dynamic':True}]}
            settings_path=root/'settings.json';settings_path.write_text(json.dumps(settings))
            db=sqlite3.connect(state/'gateway.sqlite');db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)')
            db.execute('INSERT INTO admin VALUES(1,?)',('000102030405060708090a0b0c0d0e0f:'
                'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf',));db.commit();db.close()
            listen=free_port();panel=subprocess.Popen([PANEL,'--state',str(state),'--settings',str(settings_path),'--static',str(root),
                '--secret-key',str(key),'--port',str(listen),'--offline','--no-auto-backup'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            driver=None;rust_panel=None
            def request(path,method='GET',data=None,cookie='',csrf='',authorization='',port=None):
                conn=http.client.HTTPConnection('127.0.0.1',port or listen,timeout=15);headers={'Origin':'https://testserver','Content-Type':'application/json'}
                if cookie:headers['Cookie']=cookie
                if csrf:headers['X-CSRF-Token']=csrf
                if authorization:headers['Authorization']=authorization
                try:
                    conn.request(method,path,body=json.dumps(data).encode() if data is not None else None,headers=headers)
                    response=conn.getresponse();return response.status,dict((k.lower(),v) for k,v in response.getheaders()),response.read()
                finally:conn.close()
            def rust(input):
                driver.stdin.write(json.dumps(input,ensure_ascii=False)+'\n');driver.stdin.flush()
                line=driver.stdout.readline();self.assertTrue(line,'Rust links driver stopped');return json.loads(line)
            try:
                for _ in range(100):
                    if panel.poll() is not None:self.fail('disposable legacy panel stopped')
                    try:
                        if request('/healthz')[0]==200:break
                    except OSError:time.sleep(.05)
                else:self.fail('disposable panel did not become ready')
                status,headers,body=request('/api/login','POST',{'username':'admin','password':'fixture-password'})
                self.assertEqual(status,200);cookie=headers['set-cookie'].split(';',1)[0];csrf=json.loads(body)['csrf']
                status,_,body=request('/api/users','POST',{'name':'测试 / A','quota':1000000},cookie,csrf)
                self.assertEqual(status,200);user_id=json.loads(body)['id']
                db=sqlite3.connect(state/'gateway.sqlite');db.row_factory=sqlite3.Row
                row=db.execute('SELECT name,uuid,token,enabled,deleted,quota,expires,upload,download FROM users WHERE id=?',(user_id,)).fetchone()
                user=dict(row);user['enabled']=bool(user['enabled']);user['deleted']=bool(user['deleted']);db.close()
                node_id='a'*32;node_key='B'*43
                registration={'version':1,'id':node_id,'key':node_key,'public_ip':'8.8.4.4','domain':'node.example.com',
                    'public_port':8443,'reality_sni':'www.bing.com','reality_public':'Y'*43,'short_id':'fedcba9876543210',
                    'ws_path':'/connect/'+'b'*24,'hysteria2_port':8443}
                status,_,_=request('/api/remote-nodes','POST',{'name':'远程节点','registration':registration,'users':[user_id]},cookie,csrf)
                self.assertEqual(status,201);authorization=f'Xcli-Node {node_id}.{node_key}'
                status,_,body=request('/api/nodes/sync','POST',{'revision':'','counters':[]},authorization=authorization)
                self.assertEqual(status,200);revision=json.loads(body)['revision']
                self.assertEqual(request('/api/nodes/sync','POST',{'revision':revision,'counters':[]},authorization=authorization)[0],200)
                status,_,body=request('/api/remote-nodes',cookie=cookie);self.assertEqual(status,200);nodes=json.loads(body)['nodes']
                status,_,body=request('/api/users/'+user_id+'/links',cookie=cookie);self.assertEqual(status,200);expected=json.loads(body)
                status,headers,body=request('/s/'+user['token']);self.assertEqual(status,200)
                driver=subprocess.Popen([DRIVER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
                payload={'settings':settings,'user':user,'remote_nodes':nodes,'dynamic_enabled':False,'now':int(time.time())}
                result=rust(payload);self.assertTrue(result['ok']);self.assertEqual(result['value']['links'],expected)
                self.assertEqual(result['value']['body'],body.decode());self.assertEqual(result['value']['info'],headers['subscription-userinfo'])
                if RUST_PANEL:
                    self.assertTrue(Path(RUST_PANEL).is_file())
                    rust_state=root/'rust-state';rust_state.mkdir()
                    with closing(sqlite3.connect(state/'gateway.sqlite')) as source, closing(sqlite3.connect(rust_state/'gateway.sqlite')) as target:
                        source.backup(target)
                    rust_port=free_port()
                    rust_panel=subprocess.Popen([RUST_PANEL,'--experimental','--db',str(rust_state/'gateway.sqlite'),
                        '--settings',str(settings_path),'--secret-key',str(key),'--origin','https://testserver',
                        '--port',str(rust_port)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    for _ in range(100):
                        if rust_panel.poll() is not None:self.fail('disposable Rust panel stopped')
                        try:
                            if request('/healthz',port=rust_port)[0]==200:break
                        except OSError:time.sleep(.05)
                    else:self.fail('disposable Rust panel did not become ready')
                    def compare():
                        old_status,_,old_body=request('/api/users/'+user_id+'/links',cookie=cookie)
                        new_status,_,new_body=request('/api/users/'+user_id+'/links',cookie=cookie,port=rust_port)
                        self.assertEqual((old_status,new_status),(200,200));self.assertEqual(json.loads(old_body),json.loads(new_body))
                        old_status,old_headers,old_body=request('/s/'+user['token'])
                        new_status,new_headers,new_body=request('/s/'+user['token'],port=rust_port)
                        self.assertEqual((old_status,new_status),(200,200));self.assertEqual(old_body,new_body)
                        for header in ('subscription-userinfo','profile-update-interval','content-type','content-disposition'):
                            self.assertEqual(old_headers[header],new_headers[header])
                    self.assertEqual(request('/api/users/'+user_id+'/links',port=rust_port)[0],401)
                    compare()
                    nonce=bytes(range(12));ciphertext=AESGCM(bytes(range(32))).encrypt(nonce,b'{"enabled":true}',b'xcli:webshare:config:v1')
                    frame=b'XGB1'+nonce+ciphertext[-16:]+ciphertext[:-16]
                    for location in (state,rust_state):
                        (location/'webshare').mkdir();(location/'webshare/config.xgb').write_bytes(frame)
                    compare()
                    payload['dynamic_enabled']=True
                    self.assertEqual(rust(payload)['value']['links'],json.loads(request('/api/users/'+user_id+'/links',cookie=cookie)[2]))
                    frame=frame[:20]+bytes([frame[20]^1])+frame[21:]
                    for location in (state,rust_state):(location/'webshare/config.xgb').write_bytes(frame)
                    compare()
                    self.assertEqual(request('/api/users/'+user_id,'PUT',{'name':'测试 / A','enabled':False},cookie,csrf,port=rust_port)[0],200)
                    self.assertEqual(request('/s/'+user['token'],port=rust_port)[0],403)
                self.assertEqual(request('/api/users/'+user_id,'PUT',{'name':'测试 / A','enabled':False},cookie,csrf)[0],200)
                self.assertEqual(request('/s/'+user['token'])[0],403)
                payload['user']['enabled']=False;self.assertEqual(rust(payload)['error'],'Inactive')
            finally:
                if driver is not None:driver.stdin.close();driver.wait(timeout=10);driver.stdout.close()
                if rust_panel is not None:
                    rust_panel.terminate()
                    try:rust_panel.wait(timeout=15)
                    except subprocess.TimeoutExpired:rust_panel.kill();rust_panel.wait(timeout=5)
                panel.terminate()
                try:panel.wait(timeout=15)
                except subprocess.TimeoutExpired:panel.kill();panel.wait(timeout=5)
