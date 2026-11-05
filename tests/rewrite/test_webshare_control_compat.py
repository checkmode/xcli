"""Compare encrypted Webshare control files using disposable panel state."""
from contextlib import closing
import importlib.util
import fcntl
import hashlib
import http.client
import json
import os
import select
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from test_panel_password_compat import free_port, ready, stop

LEGACY=os.environ.get('XCLI_LEGACY_PANEL','')
DRIVER=os.environ.get('XCLI_WEBSHARE_DRIVER','')


@unittest.skipUnless(DRIVER and Path(DRIVER).is_file(),'set Webshare driver path')
class WebshareProcessLock(unittest.TestCase):
    def test_configuration_writer_waits_for_another_process(self):
        with tempfile.TemporaryDirectory(prefix='xcli-webshare-lock-') as folder:
            root=Path(folder);directory=root/'webshare';directory.mkdir(mode=0o700)
            settings=root/'settings.json';settings.write_text('{}')
            lock=os.open(directory/'control.lock',os.O_CREAT|os.O_RDWR,0o600)
            driver=None
            try:
                fcntl.flock(lock,fcntl.LOCK_EX)
                driver=subprocess.Popen([DRIVER,str(root),str(settings),bytes(range(32)).hex()],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
                driver.stdin.write(json.dumps({'op':'configure','input':{'api_key':'synthetic-api-key-for-test'},'now':1000})+'\n')
                driver.stdin.flush()
                self.assertEqual(select.select([driver.stdout],[],[],0.2)[0],[])
                fcntl.flock(lock,fcntl.LOCK_UN)
                self.assertTrue(select.select([driver.stdout],[],[],2)[0])
                self.assertTrue(json.loads(driver.stdout.readline())['ok'])
            finally:
                fcntl.flock(lock,fcntl.LOCK_UN);os.close(lock)
                if driver:
                    driver.stdin.close();driver.wait(timeout=10);driver.stdout.close()


@unittest.skipUnless(LEGACY and DRIVER and Path(LEGACY).is_file() and Path(DRIVER).is_file(),'set legacy panel and Webshare driver paths')
class WebshareControlCompatibility(unittest.TestCase):
    def test_configuration_status_and_encrypted_state(self):
        with tempfile.TemporaryDirectory(prefix='xcli-webshare-control-') as folder:
            root=Path(folder);old=root/'old';new=root/'new';old.mkdir();new.mkdir()
            key=bytes(range(32));key_file=root/'key';key_file.write_bytes(key);key_file.chmod(0o600)
            settings={'origin':'https://testserver','domain':'testserver','public_ip':'203.0.113.2',
                'reality_sni':'example.com','reality_public':'p'*43,'short_id':'aabbccdd','ws_path':'/connect/test',
                'residential_exits':[{'tag':'residential-11','label':'动态 US','exit_ip':'','country':'US',
                    'ws_path':'/connect/test/residential-11','port':10110,'dynamic':True}]}
            settings_file=root/'settings.json';settings_file.write_text(json.dumps(settings))
            password='fixture-password';salt=bytes(range(16))
            encoded=salt.hex()+':'+hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1,dklen=32).hex()
            with closing(sqlite3.connect(old/'gateway.sqlite')) as db:
                db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)');db.execute('INSERT INTO admin VALUES(1,?)',(encoded,));db.commit()
            port=free_port();panel=None;driver=None
            def request(path,method='GET',body=None,cookie='',csrf=''):
                headers={'Origin':'https://testserver','Content-Type':'application/json'}
                if cookie:headers['Cookie']=cookie
                if csrf:headers['X-CSRF-Token']=csrf
                conn=http.client.HTTPConnection('127.0.0.1',port,timeout=15)
                try:
                    conn.request(method,path,json.dumps(body).encode() if body is not None else None,headers)
                    response=conn.getresponse();return response.status,dict((k.lower(),v) for k,v in response.getheaders()),json.loads(response.read())
                finally:conn.close()
            def rust(op,input=None):
                driver.stdin.write(json.dumps({'op':op,'input':input,'now':int(time.time())})+'\n');driver.stdin.flush()
                line=driver.stdout.readline();self.assertTrue(line,'disposable driver stopped');return json.loads(line)
            def decrypted(directory):
                raw=(directory/'webshare/config.xgb').read_bytes();self.assertTrue(raw.startswith(b'XGB1'))
                return json.loads(AESGCM(key).decrypt(raw[4:16],raw[32:]+raw[16:32],b'xcli:webshare:config:v1'))
            def same_status(cookie):
                status,_,value=request('/api/webshare',cookie=cookie);self.assertEqual(status,200)
                other=rust('status');self.assertTrue(other['ok']);other=other['value']
                self.assertEqual(len(value['requested_revision']),len(other['requested_revision']))
                value.pop('requested_revision');other.pop('requested_revision');self.assertEqual(value,other)
            try:
                panel=subprocess.Popen([LEGACY,'--state',str(old),'--settings',str(settings_file),'--static',str(root),
                    '--secret-key',str(key_file),'--port',str(port),'--offline','--no-auto-backup'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                ready(panel,port)
                driver=subprocess.Popen([DRIVER,str(new),str(settings_file),key.hex()],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,text=True,bufsize=1)
                status,headers,body=request('/api/login','POST',{'username':'admin','password':password})
                self.assertEqual(status,200);cookie=headers['set-cookie'].split(';',1)[0];csrf=body['csrf']
                same_status(cookie)
                for input in ({'api_key':'short'},{'enabled':True},{'plan_id':17},{'unexpected':True}):
                    self.assertEqual(request('/api/webshare','PUT',input,cookie,csrf)[0],422)
                    self.assertEqual(rust('configure',input)['error'],'invalid')
                secret='fixture-api-key-for-test'
                self.assertEqual(request('/api/webshare','PUT',{'api_key':secret},cookie,csrf)[0],200)
                self.assertTrue(rust('configure',{'api_key':secret})['ok'])
                for directory in (old,new):
                    config=decrypted(directory);self.assertEqual(config['api_key'],secret)
                    self.assertNotIn(secret.encode(),(directory/'webshare/config.xgb').read_bytes())
                old_frame=(old/'webshare/config.xgb').read_bytes();new_frame=(new/'webshare/config.xgb').read_bytes()
                (old/'webshare/config.xgb').write_bytes(new_frame);(new/'webshare/config.xgb').write_bytes(old_frame)
                same_status(cookie)
                report={'updated':int(time.time()),'plans':[{'id':17,'eligible':True,'label':'住宅','password':secret}],
                    'api_key':secret,'pools':[{'country':'US','exit_ip':'8.8.8.8','username':secret}],
                    'events':[{'country':'US','ts':100,'reason':'ready','password':secret}]}
                for directory in (old,new):(directory/'webshare/report.json').write_text(json.dumps(report))
                same_status(cookie)
                selected={'plan_id':17,'enabled':True}
                self.assertEqual(request('/api/webshare','PUT',selected,cookie,csrf)[0],200);self.assertTrue(rust('configure',selected)['ok'])
                same_status(cookie)
                action={'action':'rotate','country':'US'}
                self.assertEqual(request('/api/webshare/action','POST',action,cookie,csrf)[0],200);self.assertTrue(rust('request',action)['ok'])
                for directory in (old,new):
                    config=decrypted(directory);self.assertEqual(config['action'],'rotate');self.assertEqual(config['country'],'US');self.assertTrue(config['enabled'])
                self.assertEqual(request('/api/webshare','PUT',{'clear_key':True},cookie,csrf)[0],200);self.assertTrue(rust('configure',{'clear_key':True})['ok'])
                same_status(cookie)
                source=Path(__file__).resolve().parents[2]/'scripts/webshare.py'
                spec=importlib.util.spec_from_file_location('legacy_webshare_state_fixture',source);worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
                stamp=int(time.time());manager=worker.Manager(old/'webshare',key,regions={'US':'美国','JP':'日本'})
                manager.active={'enabled':True,'plan_id':17,'api_key':secret,'credentials':{'base':'fixture','password':'synthetic-password'}}
                manager.processed_revision='legacy-revision';manager.plans=[{'id':17,'eligible':True}]
                manager.pools={'US':[{'username':'fixture-us-1','expires_at':stamp+600,'last_success':stamp}],
                    'JP':[{'username':'fixture-jp-2','expires_at':stamp-1,'last_success':stamp-10}]}
                manager.save()
                (new/'webshare/active.xgb').write_bytes((old/'webshare/active.xgb').read_bytes());(new/'webshare/active.xgb').chmod(0o600)
                result=rust('active-check',{'password':'synthetic-password'});self.assertTrue(result['ok'])
                self.assertEqual(result['value'],{'password_matches':True,'revision':'legacy-revision','us_count':1,'jp_count':0})
                state={'active':manager.active,'processed_revision':'rust-revision','plans':manager.plans,'pools':manager.pools}
                self.assertTrue(rust('active-save',state)['ok'])
                restored=worker.unseal((new/'webshare/active.xgb').read_bytes(),key,worker.ACTIVE_CONTEXT)
                self.assertEqual(restored['processed_revision'],'rust-revision');self.assertEqual(restored['active']['credentials'],manager.active['credentials'])
                self.assertEqual(len(restored['pools']['US']),1);self.assertEqual(restored['pools']['JP'],[])
            finally:
                if driver:
                    driver.stdin.close();driver.wait(timeout=10);driver.stdout.close()
                stop(panel)
