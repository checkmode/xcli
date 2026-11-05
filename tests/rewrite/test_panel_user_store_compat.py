"""Compare user transactions with the real C++ panel using synthetic records."""
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

PANEL = os.environ.get('XCLI_LEGACY_PANEL', '')
DRIVER = os.environ.get('XCLI_USER_STORE_DRIVER', '')


@unittest.skipUnless(PANEL and DRIVER and Path(PANEL).is_file() and Path(DRIVER).is_file(),
                     'set XCLI_LEGACY_PANEL and XCLI_USER_STORE_DRIVER for transaction comparison')
class PanelUserStoreCompatibility(unittest.TestCase):
    def test_create_update_rotate_delete_match(self):
        with tempfile.TemporaryDirectory(prefix='xcli-users-store-') as folder:
            root = Path(folder); state = root / 'state'; state.mkdir()
            settings = root / 'settings.json'
            settings.write_text(json.dumps({'origin':'https://testserver','domain':'testserver','public_ip':'203.0.113.2',
                'reality_sni':'example.com','reality_public':'p'*43,'short_id':'aabbccdd','ws_path':'/connect/test'}))
            key = root / 'security.key'; key.write_bytes(bytes(range(32))); key.chmod(0o600)
            old = state / 'gateway.sqlite'; new = root / 'rust.sqlite'
            db = sqlite3.connect(old)
            db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)')
            db.execute('INSERT INTO admin VALUES(1,?)', ('000102030405060708090a0b0c0d0e0f:'
                       'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf',))
            db.commit(); db.close()
            port = free_port()
            panel = subprocess.Popen([PANEL,'--state',str(state),'--settings',str(settings),'--static',str(root),
                '--secret-key',str(key),'--port',str(port),'--offline','--no-auto-backup'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            driver = None
            def request(path, method='GET', data=None, cookie='', csrf=''):
                conn = http.client.HTTPConnection('127.0.0.1',port,timeout=15)
                headers = {'Origin':'https://testserver','Content-Type':'application/json'}
                if cookie: headers['Cookie'] = cookie
                if csrf: headers['X-CSRF-Token'] = csrf
                try:
                    conn.request(method,path,body=json.dumps(data).encode() if data is not None else None,headers=headers)
                    response = conn.getresponse()
                    return response.status, dict((k.lower(),v) for k,v in response.getheaders()), json.loads(response.read())
                finally: conn.close()
            def call(op, id='', value=None, now=1):
                driver.stdin.write(json.dumps({'op':op,'id':id,'value':value,'now':now})+'\n'); driver.stdin.flush()
                return json.loads(driver.stdout.readline())
            def row(path, id):
                db = sqlite3.connect(path)
                try: return db.execute('SELECT name,enabled,quota,expires,upload,download,deleted,uuid,token FROM users WHERE id=?',(id,)).fetchone()
                finally: db.close()
            def actions(path):
                db = sqlite3.connect(path)
                try: return db.execute("SELECT action,detail FROM events WHERE action LIKE 'user_%' OR action='credentials_rotated' ORDER BY id").fetchall()
                finally: db.close()
            try:
                for _ in range(100):
                    if panel.poll() is not None: self.fail('disposable legacy panel stopped')
                    try:
                        if request('/healthz')[0] == 200: break
                    except OSError: time.sleep(.05)
                else: self.fail('disposable legacy panel did not become ready')
                status, headers, body = request('/api/login','POST',{'username':'admin','password':'fixture-password'})
                self.assertEqual(status,200)
                cookie, csrf = headers['set-cookie'].split(';',1)[0], body['csrf']
                source = sqlite3.connect(old); dest = sqlite3.connect(new); source.backup(dest); dest.close(); source.close()
                driver = subprocess.Popen([DRIVER,str(new)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,text=True,bufsize=1)
                value = {'name':' \u6d4b\u8bd5 ', 'quota':1000, 'enabled':True, 'expires':0}
                status, _, body = request('/api/users','POST',value,cookie,csrf)
                self.assertEqual(status,200); old_id = body['id']
                created = call('create',value=value); self.assertTrue(created['ok']); new_id = created['value']['id']
                self.assertRegex(old_id,r'^[0-9a-f]{32}$'); self.assertRegex(new_id,r'^[0-9a-f]{32}$')
                before_old, before_new = row(old,old_id), row(new,new_id)
                self.assertEqual(before_old[:7],before_new[:7])
                for item in (before_old,before_new):
                    self.assertRegex(item[7],r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
                    self.assertRegex(item[8],r'^[A-Za-z0-9_-]{43}$')
                value = {'name':'updated','quota':500,'enabled':False,'expires':1234567890}
                self.assertEqual(request('/api/users/'+old_id,'PUT',value,cookie,csrf)[0],200)
                self.assertTrue(call('update',new_id,value)['ok'])
                self.assertEqual(row(old,old_id)[:7],row(new,new_id)[:7])
                self.assertEqual(request('/api/users/'+old_id+'/rotate','POST',{},cookie,csrf)[0],200)
                self.assertTrue(call('rotate',new_id)['ok'])
                rotated_old, rotated_new = row(old,old_id), row(new,new_id)
                for before, after in ((before_old,rotated_old),(before_new,rotated_new)):
                    self.assertNotEqual(before[7],after[7]); self.assertNotEqual(before[8],after[8])
                self.assertEqual(request('/api/users/'+old_id,'DELETE',None,cookie,csrf)[0],200)
                self.assertTrue(call('delete',new_id)['ok'])
                deleted_old, deleted_new = row(old,old_id), row(new,new_id)
                self.assertEqual(deleted_old[:7],deleted_new[:7]); self.assertEqual(deleted_old[1],0); self.assertEqual(deleted_old[6],1)
                for before, after in ((rotated_old,deleted_old),(rotated_new,deleted_new)):
                    self.assertEqual(before[7],after[7]); self.assertNotEqual(before[8],after[8])
                self.assertEqual(request('/api/users/'+old_id+'/rotate','POST',{},cookie,csrf)[0],404)
                self.assertEqual(call('rotate',new_id)['error'],'NotFound')
                self.assertEqual(call('list')['value'],[])
                self.assertEqual(actions(old),actions(new))
            finally:
                if driver is not None:
                    driver.stdin.close(); driver.wait(timeout=10); driver.stdout.close()
                panel.terminate()
                try: panel.wait(timeout=15)
                except subprocess.TimeoutExpired: panel.kill(); panel.wait(timeout=5)
