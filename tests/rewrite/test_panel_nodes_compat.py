"""Compare node synchronization against the C++ panel with synthetic state."""
import base64
import http.client
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest

from test_panel_auth_compat import free_port

PANEL=os.environ.get('XCLI_LEGACY_PANEL','')
DRIVER=os.environ.get('XCLI_NODE_SYNC_DRIVER','')
NODE='a'*32
KEY='Z'*43
AUTH=f'Xcli-Node {NODE}.{KEY}'


@unittest.skipUnless(PANEL and DRIVER and Path(PANEL).is_file() and Path(DRIVER).is_file(),
                     'set XCLI_LEGACY_PANEL and XCLI_NODE_SYNC_DRIVER')
class PanelNodeCompatibility(unittest.TestCase):
    def test_grants_replay_rollback_and_late_reports(self):
        with tempfile.TemporaryDirectory(prefix='xcli-node-panel-compat-') as folder:
            root=Path(folder);state=root/'state';state.mkdir();settings=root/'settings.json'
            settings.write_text(json.dumps({'origin':'https://testserver','domain':'testserver','public_ip':'203.0.113.2',
                'reality_sni':'example.com','reality_public':'p'*43,'short_id':'aabbccdd','ws_path':'/connect/test'}))
            key_file=root/'security.key';key_file.write_bytes(bytes(range(32)));key_file.chmod(0o600)
            old_db=state/'gateway.sqlite';new_db=root/'new.sqlite'
            db=sqlite3.connect(old_db);db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)')
            db.execute('INSERT INTO admin VALUES(1,?)',('000102030405060708090a0b0c0d0e0f:'
                'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf',));db.commit();db.close()
            listen=free_port()
            panel=subprocess.Popen([PANEL,'--state',str(state),'--settings',str(settings),'--static',str(root),
                '--secret-key',str(key_file),'--port',str(listen),'--offline','--no-auto-backup'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            driver=None
            def request(path,method='GET',body=None,cookie='',csrf='',authorization=''):
                conn=http.client.HTTPConnection('127.0.0.1',listen,timeout=15)
                headers={'Origin':'https://testserver','Content-Type':'application/json'}
                if cookie:headers['Cookie']=cookie
                if csrf:headers['X-CSRF-Token']=csrf
                if authorization:headers['Authorization']=authorization
                try:
                    conn.request(method,path,body=json.dumps(body).encode() if body is not None else None,headers=headers)
                    response=conn.getresponse()
                    return response.status,dict((key.lower(),value) for key,value in response.getheaders()),json.loads(response.read())
                finally:conn.close()
            def rust(body,now,authorization=AUTH):
                driver.stdin.write(json.dumps({'authorization':authorization,'input':body,'now':now})+'\n');driver.stdin.flush()
                line=driver.stdout.readline();self.assertTrue(line,'Rust node sync driver stopped');return json.loads(line)
            def management(op,body=None,id=NODE):
                driver.stdin.write(json.dumps({'op':op,'input':body,'id':id,'now':int(time.time())})+'\n');driver.stdin.flush()
                line=driver.stdout.readline();self.assertTrue(line,'Rust node driver stopped');return json.loads(line)
            def snapshot(path):
                db=sqlite3.connect(path)
                try:
                    raw=db.execute("SELECT value FROM metadata WHERE key='remote_nodes_v1'").fetchone()[0]
                    return (db.execute('SELECT id,enabled,deleted,quota,expires,upload,download FROM users ORDER BY id').fetchall(),
                        json.loads(raw),db.execute('SELECT upload,download FROM samples ORDER BY rowid').fetchall(),
                        db.execute('SELECT ts,upload,download FROM traffic_history ORDER BY ts').fetchall(),
                        db.execute('SELECT action,detail FROM events ORDER BY id').fetchall())
                finally:db.close()
            try:
                for _ in range(100):
                    if panel.poll() is not None:self.fail('disposable legacy panel stopped')
                    try:
                        if request('/healthz')[0]==200:break
                    except OSError:time.sleep(.05)
                else:self.fail('disposable legacy panel did not become ready')
                status,headers,body=request('/api/login','POST',{'username':'admin','password':'fixture-password'})
                self.assertEqual(status,200);cookie=headers['set-cookie'].split(';',1)[0];csrf=body['csrf']
                ids=[]
                for name in ('first','second'):
                    status,_,body=request('/api/users','POST',{'name':name},cookie,csrf)
                    self.assertEqual(status,200);ids.append(body['id'])
                registration={'version':1,'id':NODE,'key':KEY,'public_ip':'8.8.8.8','domain':'node.example.com',
                    'public_port':443,'reality_sni':'www.bing.com','reality_public':'Y'*43,'short_id':'0123456789abcdef',
                    'ws_path':'/connect/'+'b'*24,'hysteria2_port':443}
                source=sqlite3.connect(old_db);dest=sqlite3.connect(new_db);source.backup(dest);dest.close();source.close()
                driver=subprocess.Popen([DRIVER,str(new_db)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,text=True,bufsize=1)
                add={'name':'fixture','registration':registration,'users':ids}
                status,_,expected=request('/api/remote-nodes','POST',add,cookie,csrf)
                self.assertEqual(status,201);actual=management('add',add);self.assertTrue(actual['ok'])
                self.assertEqual(actual['value'],expected);self.assertNotIn(KEY,json.dumps(actual['value']))
                self.assertEqual(snapshot(old_db),snapshot(new_db))
                status,_,_=request('/api/remote-nodes','POST',add,cookie,csrf)
                self.assertEqual(status,409);self.assertEqual(management('add',add)['error'],'Conflict')
                invalid=dict(registration,public_ip='127.0.0.1');bad_add={'name':'fixture','registration':invalid,'users':[]}
                status,_,_=request('/api/remote-nodes','POST',bad_add,cookie,csrf)
                self.assertEqual(status,422);self.assertEqual(management('add',bad_add)['error'],'InvalidInput')
                packed=base64.b64encode(bytes.fromhex(ids[0])).decode()
                update={'name':'renamed','users':packed,'enabled':False}
                status,_,expected=request('/api/remote-nodes/'+NODE,'PUT',update,cookie,csrf)
                self.assertEqual(status,200);actual=management('update',update);self.assertEqual(actual['value'],expected)
                self.assertEqual(snapshot(old_db),snapshot(new_db))
                update={'name':'fixture','users':ids,'enabled':True}
                status,_,expected=request('/api/remote-nodes/'+NODE,'PUT',update,cookie,csrf)
                self.assertEqual(status,200);self.assertEqual(management('update',update)['value'],expected)
                status,_,expected=request('/api/remote-nodes',cookie=cookie)
                self.assertEqual(status,200);self.assertEqual(management('list')['value'],expected)
                self.assertEqual(snapshot(old_db),snapshot(new_db))
                def success(payload):
                    status,_,expected=request('/api/nodes/sync','POST',payload,authorization=AUTH)
                    self.assertEqual(status,200)
                    actual=rust(payload,expected['issued_at']);self.assertTrue(actual['ok'])
                    self.assertEqual(actual['value'],expected);self.assertEqual(snapshot(old_db),snapshot(new_db))
                    return expected
                first=success({'revision':'','counters':[]});revision=first['revision']
                payload={'revision':revision,'counters':[{'id':ids[0],'upload':100,'download':200},{'id':ids[1],'upload':50,'download':25}]}
                second=success(payload);success(payload)
                self.assertEqual(second['ack'],payload['counters'])
                before=snapshot(old_db)
                bad={'revision':revision,'counters':[{'id':ids[0],'upload':150,'download':200},{'id':'f'*32,'upload':1,'download':1}]}
                status,_,_=request('/api/nodes/sync','POST',bad,authorization=AUTH)
                self.assertEqual(status,422);self.assertEqual(rust(bad,int(time.time()))['error'],'InvalidInput')
                self.assertEqual(snapshot(old_db),before);self.assertEqual(snapshot(new_db),before)
                rollback={'revision':revision,'counters':[{'id':ids[0],'upload':99,'download':200}]}
                status,_,_=request('/api/nodes/sync','POST',rollback,authorization=AUTH)
                self.assertEqual(status,409);self.assertEqual(rust(rollback,int(time.time()))['error'],'CounterRollback')
                status,_,_=request('/api/nodes/sync','POST',{'revision':'','counters':[]},authorization=f'Xcli-Node {NODE}.'+'X'*43)
                self.assertEqual(status,401)
                self.assertEqual(rust({'revision':'','counters':[]},int(time.time()),f'Xcli-Node {NODE}.'+'X'*43)['error'],'Unauthorized')
                for path in (old_db,new_db):
                    db=sqlite3.connect(path);db.execute('DELETE FROM users WHERE id=?',(ids[0],));db.commit();db.close()
                late={'revision':revision,'counters':[{'id':ids[0],'upload':150,'download':220},{'id':ids[1],'upload':60,'download':35}]}
                third=success(late);self.assertEqual(len(third['users']),1);self.assertEqual(third['users'][0]['id'],ids[1])
            finally:
                if driver is not None:
                    driver.stdin.close();driver.wait(timeout=10);driver.stdout.close()
                panel.terminate()
                try:panel.wait(timeout=15)
                except subprocess.TimeoutExpired:panel.kill();panel.wait(timeout=5)
