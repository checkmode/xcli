"""Verify C++ and Rust encrypted backups against isolated synthetic state."""
from contextlib import closing
import http.client
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest
from test_panel_auth_compat import free_port

PANEL=os.environ.get('XCLI_LEGACY_PANEL','')
DRIVER=os.environ.get('XCLI_BACKUP_DRIVER','')


@unittest.skipUnless(PANEL and DRIVER and Path(PANEL).is_file() and Path(DRIVER).is_file(),
                     'set XCLI_LEGACY_PANEL and XCLI_BACKUP_DRIVER')
class BackupCompatibility(unittest.TestCase):
    def test_old_and_new_envelopes_are_mutually_inspectable(self):
        with tempfile.TemporaryDirectory(prefix='xcli-backup-compat-') as folder:
            root=Path(folder);state=root/'state';state.mkdir();key=root/'key';key.write_bytes(bytes(range(32)));key.chmod(0o600)
            settings=root/'settings.json';settings.write_text(json.dumps({'origin':'https://testserver','domain':'testserver',
                'public_ip':'203.0.113.2','reality_sni':'www.bing.com','reality_public':'p'*43,
                'short_id':'0123456789abcdef','ws_path':'/connect/test'}))
            db=sqlite3.connect(state/'gateway.sqlite');db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)')
            db.execute('INSERT INTO admin VALUES(1,?)',('000102030405060708090a0b0c0d0e0f:'
                'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf',));db.commit();db.close()
            port=free_port();panel=subprocess.Popen([PANEL,'--state',str(state),'--settings',str(settings),'--static',str(root),
                '--secret-key',str(key),'--port',str(port),'--offline','--no-auto-backup'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            driver=None
            def request(path,method='GET',data=None,cookie='',csrf=''):
                conn=http.client.HTTPConnection('127.0.0.1',port,timeout=15);headers={'Origin':'https://testserver','Content-Type':'application/json'}
                if cookie:headers['Cookie']=cookie
                if csrf:headers['X-CSRF-Token']=csrf
                try:
                    conn.request(method,path,body=json.dumps(data).encode() if data is not None else None,headers=headers)
                    response=conn.getresponse();return response.status,dict((k.lower(),v) for k,v in response.getheaders()),json.loads(response.read())
                finally:conn.close()
            def rust(data):
                driver.stdin.write(json.dumps(data)+'\n');driver.stdin.flush();line=driver.stdout.readline()
                self.assertTrue(line,'disposable backup driver stopped');return json.loads(line)
            try:
                for _ in range(100):
                    if panel.poll() is not None:self.fail('disposable legacy panel stopped')
                    try:
                        if request('/healthz')[0]==200:break
                    except OSError:time.sleep(.05)
                else:self.fail('disposable legacy panel did not become ready')
                status,headers,body=request('/api/login','POST',{'username':'admin','password':'fixture-password'})
                self.assertEqual(status,200);cookie=headers['set-cookie'].split(';',1)[0];csrf=body['csrf']
                self.assertEqual(request('/api/users','POST',{'name':'fixture','quota':10000},cookie,csrf)[0],200)
                status,_,old_created=request('/api/backups','POST',{},cookie,csrf);self.assertEqual(status,200)
                old_id=old_created['id'];status,_,old_inspect=request('/api/backups/'+old_id+'/inspect',cookie=cookie)
                self.assertEqual(status,200);self.assertTrue(old_inspect['same_server'])
                rust_state=root/'rust-state';rust_state.mkdir();(rust_state/'backups').mkdir()
                with closing(sqlite3.connect(state/'gateway.sqlite')) as source,closing(sqlite3.connect(rust_state/'gateway.sqlite')) as target:source.backup(target)
                shutil.copyfile(state/'backups'/old_id,rust_state/'backups'/old_id)
                driver=subprocess.Popen([DRIVER,str(rust_state/'gateway.sqlite'),str(settings),str(key)],stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
                result=rust({'action':'inspect','id':old_id});self.assertTrue(result['ok']);self.assertEqual(result['value'],old_inspect)
                created=rust({'action':'create','stamp':int(time.time())});self.assertTrue(created['ok']);new_id=created['value']['id']
                shutil.copyfile(rust_state/'backups'/new_id,state/'backups'/new_id)
                status,_,legacy_inspect=request('/api/backups/'+new_id+'/inspect',cookie=cookie)
                self.assertEqual(status,200);self.assertTrue(legacy_inspect['same_server'])
                self.assertEqual(rust({'action':'inspect','id':new_id})['value'],legacy_inspect)
                entries=rust({'action':'list'})['value'];self.assertEqual(len(entries),2);self.assertTrue(all(item['valid'] for item in entries))
                self.assertEqual(rust({'action':'inspect','id':'../bad.xgb'})['error'],'NotFound')
                for database in (state/'gateway.sqlite',rust_state/'gateway.sqlite'):
                    with closing(sqlite3.connect(database)) as db:
                        db.execute("UPDATE users SET name='changed',upload=900,download=500 WHERE deleted=0")
                        db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('activity_sample','123')")
                        db.commit()
                restored=rust({'action':'restore-offline','id':old_id,'stamp':int(time.time())})
                self.assertTrue(restored['ok']);self.assertEqual(restored['value']['reason'],'before-restore')
                status,_,body=request('/api/backups/restore','POST',{'id':old_id,'confirm':old_id,
                    'current_password':'fixture-password','code':''},cookie,csrf)
                self.assertEqual(status,200);self.assertEqual(body,{'ok':True})
                def snapshot(database):
                    with closing(sqlite3.connect(database)) as db:
                        users=db.execute('SELECT id,name,uuid,token,enabled,quota,expires,upload,download,created,deleted FROM users ORDER BY id').fetchall()
                        sessions=db.execute('SELECT count(*) FROM sessions').fetchone()[0]
                        mfa_sessions=db.execute('SELECT count(*) FROM mfa_sessions').fetchone()[0]
                        activity=db.execute("SELECT count(*) FROM metadata WHERE key='activity_sample'").fetchone()[0]
                        return users,sessions,mfa_sessions,activity
                old_state=snapshot(state/'gateway.sqlite');new_state=snapshot(rust_state/'gateway.sqlite')
                self.assertEqual(new_state,old_state);self.assertEqual(old_state[0][0][7:9],(900,500))
            finally:
                if driver is not None:driver.stdin.close();driver.wait(timeout=10);driver.stdout.close()
                panel.terminate()
                try:panel.wait(timeout=15)
                except subprocess.TimeoutExpired:panel.kill();panel.wait(timeout=5)
