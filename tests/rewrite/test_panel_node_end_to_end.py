"""Isolated Rust panel and node over TLS, with real loopback Xray traffic."""
import contextlib
import http.client
import http.server
import json
import os
from pathlib import Path
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

from test_node_service_integration import port, socket_open, wait_for
from test_panel_http_integration import request

XRAY=os.environ.get('XCLI_TEST_XRAY','')
NODE=os.environ.get('XCLI_NODE_SERVICE','')
PANEL=os.environ.get('XCLI_PANEL_SERVICE','')
NODE_ID='a'*32
USER_ID='c'*32
TOKEN='B'*43


def stop(process, timeout=10):
    if process is None or process.poll() is not None:return
    process.terminate()
    try:process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)


@unittest.skipUnless(all(value and Path(value).is_file() for value in (XRAY,NODE,PANEL)),
                     'set XCLI_TEST_XRAY, XCLI_NODE_SERVICE and XCLI_PANEL_SERVICE')
class PanelNodeEndToEnd(unittest.TestCase):
    def test_real_grant_lost_ack_accounting_and_revocation(self):
        with tempfile.TemporaryDirectory(prefix='xcli-panel-node-e2e-') as folder:
            root=Path(folder);cert=root/'cert.pem';key=root/'cert-key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:FALSE',
                '-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            secret=root/'security.key';secret.write_bytes(bytes(range(32)));secret.chmod(0o600)
            identity=str(uuid.uuid4());db_path=root/'gateway.sqlite'
            db=sqlite3.connect(db_path)
            db.executescript('''
                CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL);
                CREATE TABLE sessions(hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
                CREATE TABLE mfa(id INTEGER PRIMARY KEY,enabled INTEGER NOT NULL,secret TEXT NOT NULL,last_step INTEGER NOT NULL);
                CREATE TABLE mfa_sessions(hash TEXT PRIMARY KEY);
                CREATE TABLE recovery_codes(hash TEXT PRIMARY KEY,used INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE users(id TEXT PRIMARY KEY,uuid TEXT NOT NULL,enabled INTEGER NOT NULL,deleted INTEGER NOT NULL,
                    quota INTEGER NOT NULL,expires INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL);
                CREATE TABLE traffic_history(ts INTEGER PRIMARY KEY,upload INTEGER NOT NULL,download INTEGER NOT NULL);
                CREATE TABLE samples(ts INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL);
                CREATE TABLE counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL,generation TEXT NOT NULL);
                CREATE TABLE device_activity(user_id TEXT NOT NULL,transport TEXT NOT NULL,last_seen INTEGER NOT NULL DEFAULT 0,
                    sampled INTEGER NOT NULL DEFAULT 0,upload_delta INTEGER NOT NULL DEFAULT 0,download_delta INTEGER NOT NULL DEFAULT 0,
                    interval_seconds INTEGER NOT NULL DEFAULT 5,PRIMARY KEY(user_id,transport));
                CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
                INSERT INTO mfa VALUES(1,0,'',-1);
            ''')
            db.execute('INSERT INTO admin VALUES(1,?)',('000102030405060708090a0b0c0d0e0f:'
                'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf',))
            db.execute('INSERT INTO users VALUES(?,?,1,0,0,0,0,0)',(USER_ID,identity))
            db.commit();db.close()
            local_api,local_websocket=port(),port()
            local_cfg={'log':{'loglevel':'none'},'api':{'tag':'api','listen':f'127.0.0.1:{local_api}',
                'services':['HandlerService','StatsService']},'stats':{},
                'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True}}},
                'inbounds':[{'tag':'websocket','listen':'127.0.0.1','port':local_websocket,'protocol':'vless',
                    'settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':'ws','wsSettings':{'path':'/test'}}}],
                'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1/32']}]}}]}
            local_path=root/'local-core.json';local_path.write_text(json.dumps(local_cfg))
            local_core=subprocess.Popen([XRAY,'run','-config',str(local_path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            local_pids=root/'local-pids';local_pids.write_text(str(local_core.pid)+'\n')
            panel_port=port()
            panel=subprocess.Popen([PANEL,'--experimental','--db',str(db_path),'--secret-key',str(secret),
                '--origin','https://localhost','--port',str(panel_port),'--core-binary',XRAY,
                '--core-api',f'127.0.0.1:{local_api}','--core-pid-file',str(local_pids),'--core-tags','websocket',
                '--core-poll-seconds','1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            lock=threading.Lock();shared={'records':[],'drop_once':False,'dropped':False}
            class Proxy(http.server.BaseHTTPRequestHandler):
                def log_message(self,*_):pass
                def do_POST(self):
                    data=self.rfile.read(int(self.headers['Content-Length']))
                    conn=http.client.HTTPConnection('127.0.0.1',panel_port,timeout=10)
                    try:
                        conn.request('POST',self.path,body=data,headers={'Content-Type':'application/json',
                            'Authorization':self.headers.get('Authorization','')})
                        response=conn.getresponse();body=response.read();status=response.status
                    finally:conn.close()
                    request=json.loads(data)
                    with lock:
                        shared['records'].append(request['counters'])
                        drop=shared['drop_once'] and bool(request['counters']) and not shared['dropped'] and status==200
                        if drop:shared['dropped']=True
                    if drop:
                        self.close_connection=True
                        with contextlib.suppress(OSError):self.connection.shutdown(socket.SHUT_RDWR)
                        return
                    self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers()
                    with contextlib.suppress(BrokenPipeError,ConnectionResetError,ssl.SSLError):self.wfile.write(body)
            proxy=http.server.ThreadingHTTPServer(('127.0.0.1',0),Proxy)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            proxy.socket=context.wrap_socket(proxy.socket,server_side=True)
            proxy_thread=threading.Thread(target=proxy.serve_forever,daemon=True);proxy_thread.start()
            private_fields=dict(line.split(':',1) for line in subprocess.check_output([XRAY,'x25519'],text=True).splitlines() if ':' in line)
            private=private_fields['PrivateKey'].strip()
            reality,websocket,hysteria,api=port(),port(),port(),port()
            cfg={'log':{'loglevel':'warning','access':'none'},'api':{'tag':'api','listen':f'127.0.0.1:{api}',
                'services':['HandlerService','StatsService']},'stats':{},'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True}}},
                'inbounds':[{'tag':'reality','listen':'127.0.0.1','port':reality,'protocol':'vless',
                    'settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':'tcp','security':'reality',
                        'realitySettings':{'target':'www.bing.com:443','serverNames':['www.bing.com'],'privateKey':private,'shortIds':['0123456789abcdef']}}},
                    {'tag':'websocket','listen':'127.0.0.1','port':websocket,'protocol':'vless',
                     'settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':'ws','wsSettings':{'path':'/test'}}},
                    {'tag':'hysteria2','listen':'127.0.0.1','port':hysteria,'protocol':'hysteria','settings':{'version':2,'clients':[]},
                     'streamSettings':{'network':'hysteria','security':'tls','hysteriaSettings':{'version':2},
                        'tlsSettings':{'alpn':['h3'],'certificates':[{'certificateFile':str(cert),'keyFile':str(key)}]}}}],
                'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1/32']}]}}]}
            core_path=root/'core.json';core_path.write_text(json.dumps(cfg))
            node_config=root/'node.json';node_config.write_text(json.dumps({'node_id':NODE_ID,'token':TOKEN,'panel':f'https://localhost:{proxy.server_port}'}))
            state=root/'node-state';state.mkdir()
            daemon=None;client=None;local_client=None;origin=None;origin_thread=None
            def live_users(target=api):
                result=subprocess.run([XRAY,'api','inbounduser',f'--server=127.0.0.1:{target}','-tag=websocket','--timeout=1'],
                    capture_output=True,timeout=3)
                if result.returncode:return None
                try:return json.loads(result.stdout).get('users',[])
                except ValueError:return None
            try:
                self.assertTrue(wait_for(lambda:socket_open(panel_port),8),'Rust panel did not start')
                self.assertTrue(wait_for(lambda:len(live_users(local_api) or [])==1,12),'panel did not grant the local core user')
                status,headers,body=request(panel_port,'/api/login','POST',json.dumps({'username':'admin','password':'fixture-password'}).encode(),origin='https://localhost')
                self.assertEqual(status,200);cookie=headers['set-cookie'].split(';',1)[0];csrf=json.loads(body)['csrf']
                registration={'version':1,'id':NODE_ID,'key':TOKEN,'public_ip':'8.8.8.8','domain':'node.example.com',
                    'public_port':443,'reality_sni':'www.bing.com','reality_public':'Y'*43,'short_id':'0123456789abcdef',
                    'ws_path':'/connect/'+'b'*24,'hysteria2_port':443}
                body=json.dumps({'name':'fixture','registration':registration,'users':[USER_ID]}).encode()
                status,_,data=request(panel_port,'/api/remote-nodes','POST',body,cookie,csrf,origin='https://localhost')
                self.assertEqual(status,201);self.assertNotIn(TOKEN,data.decode())
                daemon=subprocess.Popen([NODE,'--experimental','--config',str(node_config),'--state',str(state),
                    '--core-config',str(core_path),'--xray',XRAY,'--api',f'127.0.0.1:{api}'],
                    env={**os.environ,'SSL_CERT_FILE':str(cert)},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                self.assertTrue(wait_for(lambda:len(live_users() or [])==1,25),'Rust node did not apply the Rust panel grant')
                payload=b'x'*65536
                class Origin(http.server.BaseHTTPRequestHandler):
                    def log_message(self,*_):pass
                    def do_GET(self):
                        self.send_response(200);self.send_header('Content-Length',str(len(payload)));self.end_headers()
                        with contextlib.suppress(BrokenPipeError,ConnectionResetError):self.wfile.write(payload)
                origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),Origin)
                origin_thread=threading.Thread(target=origin.serve_forever,daemon=True);origin_thread.start()
                socks=port();client_path=root/'client.json'
                client_path.write_text(json.dumps({'log':{'loglevel':'none'},'inbounds':[{'listen':'127.0.0.1','port':socks,
                    'protocol':'socks','settings':{'auth':'noauth'}}],
                    'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':websocket,
                        'users':[{'id':identity,'encryption':'none'}]}]},'streamSettings':{'network':'ws','wsSettings':{'path':'/test'}}}]}))
                client=subprocess.Popen([XRAY,'run','-config',str(client_path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                self.assertTrue(wait_for(lambda:socket_open(socks),8),'fixture client did not start')
                with lock:shared['drop_once']=True
                command=['curl','--noproxy','','--proxy',f'socks5h://127.0.0.1:{socks}','-fsS','--max-time','5',
                    f'http://127.0.0.1:{origin.server_port}/blob']
                response=subprocess.run(command,capture_output=True,timeout=8)
                self.assertEqual(response.returncode,0);self.assertEqual(response.stdout,payload)
                def retried():
                    with lock:
                        nonempty=[batch for batch in shared['records'] if batch]
                        return shared['dropped'] and len(nonempty)>=2 and nonempty[0]==nonempty[1] and nonempty[0][0]['download']>=len(payload)
                self.assertTrue(wait_for(retried,25),'lost acknowledgement was not retried')
                with lock:reported=[batch for batch in shared['records'] if batch][-1][0]
                db=sqlite3.connect(db_path)
                self.assertEqual(db.execute('SELECT upload,download FROM users WHERE id=?',(USER_ID,)).fetchone(),
                    (reported['upload'],reported['download']))
                db.close()
                local_socks=port();local_client_path=root/'local-client.json'
                local_client_path.write_text(json.dumps({'log':{'loglevel':'none'},'inbounds':[{'listen':'127.0.0.1','port':local_socks,
                    'protocol':'socks','settings':{'auth':'noauth'}}],
                    'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':local_websocket,
                        'users':[{'id':identity,'encryption':'none'}]}]},'streamSettings':{'network':'ws','wsSettings':{'path':'/test'}}}]}))
                local_client=subprocess.Popen([XRAY,'run','-config',str(local_client_path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                self.assertTrue(wait_for(lambda:socket_open(local_socks),8),'local fixture client did not start')
                local_command=list(command);local_command[local_command.index('--proxy')+1]=f'socks5h://127.0.0.1:{local_socks}'
                response=subprocess.run(local_command,capture_output=True,timeout=8)
                self.assertEqual(response.returncode,0);self.assertEqual(response.stdout,payload)
                def combined_accounted():
                    db=sqlite3.connect(db_path)
                    try:return db.execute('SELECT download FROM users WHERE id=?',(USER_ID,)).fetchone()[0]>=2*len(payload)
                    finally:db.close()
                self.assertTrue(wait_for(combined_accounted,10),'local and node traffic were not combined')
                db=sqlite3.connect(db_path)
                total_up,total_down=db.execute('SELECT upload,download FROM users WHERE id=?',(USER_ID,)).fetchone()
                remote_total=reported['upload']+reported['download'];combined_total=total_up+total_down
                quota=max(remote_total,combined_total-remote_total)+1000
                self.assertLess(quota,combined_total)
                db.execute('UPDATE users SET quota=? WHERE id=?',(quota,USER_ID));db.commit();db.close()
                self.assertTrue(wait_for(lambda:local_core.poll() is not None,15),'combined quota did not revoke the local core')
                self.assertTrue(wait_for(lambda:live_users()==[],25),'quota did not revoke node access')
                def revocation_acknowledged():
                    db=sqlite3.connect(db_path)
                    try:
                        registry=json.loads(db.execute("SELECT value FROM metadata WHERE key='remote_nodes_v1'").fetchone()[0])
                        state=registry[0]
                        return (state['pending_users']==[] and state['applied_users']==[] and
                                state['pending_revision'] and state['pending_revision']==state['applied_revision'])
                    finally:db.close()
                self.assertTrue(wait_for(revocation_acknowledged,20),'node did not acknowledge the revoked grant')
                db=sqlite3.connect(db_path)
                try:self.assertGreaterEqual(db.execute('SELECT download FROM users WHERE id=?',(USER_ID,)).fetchone()[0],2*len(payload))
                finally:db.close()
                self.assertNotEqual(subprocess.run(command,capture_output=True,timeout=8).returncode,0)
                self.assertNotEqual(subprocess.run(local_command,capture_output=True,timeout=8).returncode,0)
            finally:
                stop(daemon,25);stop(client);stop(local_client);stop(panel);stop(local_core)
                proxy.shutdown();proxy.server_close();proxy_thread.join(timeout=5)
                if origin is not None:origin.shutdown();origin.server_close();origin_thread.join(timeout=5)
                self.assertFalse(socket_open(api),'node service left its Xray API running')
