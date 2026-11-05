"""Exercise the experimental panel worker with disposable users and Xray."""
import contextlib
import http.server
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest

from test_node_service_integration import port, socket_open, wait_for
from test_panel_http_integration import request, stop, wait_ready

XRAY=os.environ.get('XCLI_TEST_XRAY','')
PANEL=os.environ.get('XCLI_PANEL_SERVICE','')
WEB=os.environ.get('XCLI_WEB_GATEWAY','')
NODE=os.environ.get('XCLI_TEST_NODE','node')


@unittest.skipUnless(XRAY and PANEL and Path(XRAY).is_file() and Path(PANEL).is_file(),
                     'set XCLI_TEST_XRAY and XCLI_PANEL_SERVICE')
class PanelControllerService(unittest.TestCase):
    def test_user_lifecycle_accounts_and_revokes_the_real_core(self):
        with tempfile.TemporaryDirectory(prefix='xcli-panel-controller-') as folder:
            root=Path(folder);key=root/'key';key.write_bytes(bytes(range(32)));key.chmod(0o600)
            db_path=root/'gateway.sqlite';db=sqlite3.connect(db_path)
            db.executescript('''
                CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL);
                CREATE TABLE sessions(hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
                CREATE TABLE mfa(id INTEGER PRIMARY KEY,enabled INTEGER NOT NULL,secret TEXT NOT NULL,last_step INTEGER NOT NULL);
                CREATE TABLE mfa_sessions(hash TEXT PRIMARY KEY);
                CREATE TABLE recovery_codes(hash TEXT PRIMARY KEY,used INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
                CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL,uuid TEXT NOT NULL UNIQUE,token TEXT NOT NULL UNIQUE,
                    enabled INTEGER NOT NULL DEFAULT 1,quota INTEGER NOT NULL DEFAULT 0,expires INTEGER NOT NULL DEFAULT 0,
                    upload INTEGER NOT NULL DEFAULT 0,download INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL,deleted INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL,generation TEXT NOT NULL);
                CREATE TABLE device_activity(user_id TEXT NOT NULL,transport TEXT NOT NULL,last_seen INTEGER NOT NULL DEFAULT 0,
                    sampled INTEGER NOT NULL DEFAULT 0,upload_delta INTEGER NOT NULL DEFAULT 0,download_delta INTEGER NOT NULL DEFAULT 0,
                    interval_seconds INTEGER NOT NULL DEFAULT 5,PRIMARY KEY(user_id,transport));
                CREATE TABLE traffic_history(ts INTEGER PRIMARY KEY,upload INTEGER NOT NULL,download INTEGER NOT NULL);
                CREATE TABLE samples(ts INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL);
                INSERT INTO mfa VALUES(1,0,'',-1);
            ''')
            db.execute('INSERT INTO admin VALUES(1,?)',('000102030405060708090a0b0c0d0e0f:'
                'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf',));db.commit();db.close()
            api,websocket=port(),port();cfg={'log':{'loglevel':'none'},
                'api':{'tag':'api','listen':f'127.0.0.1:{api}','services':['HandlerService','StatsService']},
                'stats':{},'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True}}},
                'inbounds':[{'tag':'websocket','listen':'127.0.0.1','port':websocket,'protocol':'vless',
                    'settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':'ws','wsSettings':{'path':'/test'}}}],
                'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1/32']}]}}]}
            core_path=root/'core.json';core_path.write_text(json.dumps(cfg))
            core=subprocess.Popen([XRAY,'run','-config',str(core_path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            pidfile=root/'pids';pidfile.write_text(str(core.pid)+'\n');panel_port=port()
            controller_port=panel_port
            panel=None;gateway=None;client=None;origin=None;origin_thread=None
            try:
                self.assertTrue(wait_for(lambda:socket_open(api),8),'disposable Xray did not start')
                panel=subprocess.Popen([PANEL,'--experimental','--db',str(db_path),'--secret-key',str(key),
                    '--origin','https://testserver','--port',str(panel_port),'--core-binary',XRAY,
                    '--core-api',f'127.0.0.1:{api}','--core-pid-file',str(pidfile),'--core-tags','websocket',
                    '--core-poll-seconds','1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                wait_ready(panel,panel_port)
                if WEB:
                    gateway_port=port()
                    env=dict(os.environ,XCLI_CORE_PORT=str(panel_port),XCLI_WEB_PORT=str(gateway_port))
                    gateway=subprocess.Popen([NODE,WEB],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    wait_ready(gateway,gateway_port)
                    panel_port=gateway_port
                    self.assertEqual(request(panel_port,'/internal/ready')[0],404)
                login=json.dumps({'username':'admin','password':'fixture-password'}).encode()
                status,headers,body=request(panel_port,'/api/login','POST',login)
                self.assertEqual(status,200);cookie=headers['set-cookie'].split(';',1)[0];csrf=json.loads(body)['csrf']
                self.assertEqual(request(panel_port,'/api/core-sync')[0],401)
                status,_,body=request(panel_port,'/api/users','POST',json.dumps({'name':'fixture'}).encode(),cookie,csrf)
                self.assertEqual(status,200);created=json.loads(body);user_id=created['id'];ticket=created['local_core_sync']
                def sync_state():
                    status,_,value=request(panel_port,'/api/core-sync',cookie=cookie)
                    self.assertEqual(status,200)
                    return json.loads(value)
                def created_applied():
                    value=sync_state()
                    return (value['instance']==ticket['instance'] and value['state']=='ready'
                            and value['applied_revision']>=ticket['revision'])
                self.assertTrue(wait_for(created_applied,12),'local core did not acknowledge user creation')
                self.assertEqual(request(controller_port,'/internal/ready')[0],200)
                db=sqlite3.connect(db_path);identity=db.execute('SELECT uuid FROM users WHERE id=?',(user_id,)).fetchone()[0];db.close()
                def live_users():
                    result=subprocess.run([XRAY,'api','inbounduser',f'--server=127.0.0.1:{api}','-tag=websocket','--timeout=1'],
                        capture_output=True,timeout=3)
                    if result.returncode:return None
                    try:return json.loads(result.stdout).get('users',[])
                    except ValueError:return None
                self.assertTrue(wait_for(lambda:len(live_users() or [])==1,12),'panel did not grant the user')
                payload=b'x'*65536
                class Origin(http.server.BaseHTTPRequestHandler):
                    def log_message(self,*_):pass
                    def do_GET(self):
                        self.send_response(200);self.send_header('Content-Length',str(len(payload)));self.end_headers()
                        with contextlib.suppress(BrokenPipeError,ConnectionResetError):self.wfile.write(payload)
                origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),Origin)
                origin_thread=threading.Thread(target=origin.serve_forever,daemon=True);origin_thread.start()
                socks=port();client_path=root/'client.json';client_path.write_text(json.dumps({'log':{'loglevel':'none'},
                    'inbounds':[{'listen':'127.0.0.1','port':socks,'protocol':'socks','settings':{'auth':'noauth'}}],
                    'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':websocket,
                        'users':[{'id':identity,'encryption':'none'}]}]},'streamSettings':{'network':'ws','wsSettings':{'path':'/test'}}}]}))
                client=subprocess.Popen([XRAY,'run','-config',str(client_path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                self.assertTrue(wait_for(lambda:socket_open(socks),8),'fixture client did not start')
                command=['curl','--noproxy','','--proxy',f'socks5h://127.0.0.1:{socks}','-fsS','--max-time','5',
                    f'http://127.0.0.1:{origin.server_port}/blob']
                result=subprocess.run(command,capture_output=True,timeout=8)
                self.assertEqual(result.returncode,0);self.assertEqual(result.stdout,payload)
                def accounted():
                    db=sqlite3.connect(db_path)
                    try:return db.execute('SELECT download FROM users WHERE id=?',(user_id,)).fetchone()[0]>=len(payload)
                    finally:db.close()
                self.assertTrue(wait_for(accounted,10),'panel did not persist Xray traffic')
                reset_path='/api/users/'+user_id+'/reset-traffic'
                self.assertEqual(request(panel_port,reset_path,'POST',None,cookie,'wrong-csrf')[0],403)
                with sqlite3.connect(db_path) as db:
                    db.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES('remote_nodes_v1',?)",
                        (json.dumps([{'history':[user_id]}]),))
                self.assertEqual(request(panel_port,reset_path,'POST',None,cookie,csrf)[0],409)
                self.assertTrue(accounted(),'refused remote-user reset changed the usage')
                with sqlite3.connect(db_path) as db:
                    db.execute("DELETE FROM metadata WHERE key='remote_nodes_v1'")
                self.assertEqual(request(panel_port,reset_path,'POST',None,cookie,csrf)[0],200)
                def usage_and_baseline():
                    with sqlite3.connect(db_path) as db:
                        usage=db.execute('SELECT upload,download FROM users WHERE id=?',(user_id,)).fetchone()
                        names=[f'user>>>{user_id}.{identity[:8]}@websocket>>>traffic>>>{direction}'
                            for direction in ('uplink','downlink')]
                        values=[db.execute('SELECT value FROM counters WHERE name=?',(name,)).fetchone() for name in names]
                        return usage,tuple(value[0] if value else 0 for value in values)
                baseline_usage,baseline_counters=usage_and_baseline()
                self.assertLess(baseline_usage[1],len(payload),'old cumulative download survived reset')
                result=subprocess.run(command,capture_output=True,timeout=8)
                self.assertEqual(result.returncode,0);self.assertEqual(result.stdout,payload)
                def new_usage_accounted():
                    usage,counters=usage_and_baseline()
                    return (usage[1]-baseline_usage[1]>=len(payload) and
                        all(usage[i]-baseline_usage[i]==counters[i]-baseline_counters[i] for i in range(2)))
                self.assertTrue(wait_for(new_usage_accounted,10),'post-reset traffic did not match the new counter deltas')
                # Capture a lower bound from the real core immediately before the
                # controlled revoke. The final checkpoint must preserve at least
                # this much; traffic between that checkpoint and exit can still be lost.
                result=subprocess.run(command,capture_output=True,timeout=8)
                self.assertEqual(result.returncode,0);self.assertEqual(result.stdout,payload)
                observed=json.loads(subprocess.check_output([XRAY,'api','statsquery',f'--server=127.0.0.1:{api}',
                    '-pattern','user>>>'],timeout=5)).get('stat',[])
                email=f'{user_id}.{identity[:8]}@websocket'
                last=tuple(sum(int(item.get('value',0)) for item in observed
                    if item['name']==f'user>>>{email}>>>traffic>>>{direction}') for direction in ('uplink','downlink'))
                self.assertGreater(last[1],baseline_counters[1])
                # A database failure during sampling must not be reported as
                # an applied revoke or send a restart signal. Existing access
                # is still live until sampling can succeed.
                with sqlite3.connect(db_path) as db:
                    db.execute("CREATE TRIGGER fixture_reject_sample BEFORE INSERT ON samples BEGIN SELECT RAISE(ABORT,'fixture'); END")
                status,_,body=request(panel_port,'/api/users/'+user_id,'DELETE',None,cookie,csrf)
                self.assertEqual(status,200);revoke=json.loads(body)['local_core_sync']
                self.assertEqual(revoke['instance'],ticket['instance']);self.assertGreater(revoke['revision'],ticket['revision'])
                def sync_failed():
                    value=sync_state()
                    return (value['instance']==revoke['instance'] and value['revision']>=revoke['revision']
                            and value['state']=='unavailable')
                self.assertTrue(wait_for(sync_failed,8),'sampling failure was not visible in local sync status')
                self.assertEqual(request(controller_port,'/internal/ready')[0],503)
                self.assertIsNone(core.poll(),'core stopped despite the failed sample')
                self.assertEqual(subprocess.run(command,capture_output=True,timeout=8).returncode,0,
                    'fixture old connection was unexpectedly unavailable during failed revoke')
                with sqlite3.connect(db_path) as db:db.execute('DROP TRIGGER fixture_reject_sample')
                self.assertTrue(wait_for(lambda:core.poll() is not None,12),'deleting the user did not stop the old core')
                self.assertNotEqual(sync_state()['state'],'ready','stopped core was falsely reported as synchronized')
                final_usage,_=usage_and_baseline()
                self.assertTrue(all(final_usage[i]-baseline_usage[i]>=last[i]-baseline_counters[i] for i in range(2)),
                    'pre-restart traffic was not persisted before the core stopped')
                def audited():
                    db=sqlite3.connect(db_path)
                    try:return db.execute("SELECT count(*) FROM events WHERE action='core_restart'").fetchone()[0]==1
                    finally:db.close()
                self.assertTrue(wait_for(audited,5),'core restart was not audited')
                self.assertNotEqual(subprocess.run(command,capture_output=True,timeout=8).returncode,0)
                # Simulate the service manager starting the new generation.
                # The revision is applied only after that core is reconciled.
                core=subprocess.Popen([XRAY,'run','-config',str(core_path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                pidfile.write_text(str(core.pid)+'\n')
                self.assertTrue(wait_for(lambda:socket_open(api),8),'replacement fixture core did not start')
                def revoke_applied():
                    value=sync_state()
                    return (value['instance']==revoke['instance'] and value['state']=='ready'
                            and value['applied_revision']>=revoke['revision'])
                self.assertTrue(wait_for(revoke_applied,12),'new core did not acknowledge the revoked user')
                self.assertEqual(request(controller_port,'/internal/ready')[0],200)
                self.assertNotEqual(subprocess.run(command,capture_output=True,timeout=8).returncode,0,
                    'revoked user could still authenticate to the new core')
            finally:
                stop(gateway);stop(panel);stop(client);stop(core)
                if origin is not None:origin.shutdown();origin.server_close();origin_thread.join(timeout=5)
