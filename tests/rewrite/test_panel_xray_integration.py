"""Exercise the panel's Rust gRPC adapter against a disposable loopback Xray."""
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
import uuid

XRAY=os.environ.get('XCLI_TEST_XRAY','')
DRIVER=os.environ.get('XCLI_MANAGED_DRIVER','')
USER='a'*32


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0))
        return sock.getsockname()[1]


def stop(process):
    if process is None or process.poll() is not None: return
    process.terminate()
    try: process.wait(timeout=8)
    except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)


@unittest.skipUnless(XRAY and DRIVER and Path(XRAY).is_file() and Path(DRIVER).is_file(),
                     'set XCLI_TEST_XRAY and XCLI_MANAGED_DRIVER for the isolated Xray test')
class PanelXrayIntegration(unittest.TestCase):
    def test_direct_grpc_counters_and_pinned_restart(self):
        with tempfile.TemporaryDirectory(prefix='xcli-managed-xray-') as folder:
            root=Path(folder); cert=root/'cert.pem'; key=root/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                '-subj','/CN=node.test','-keyout',str(key),'-out',str(cert)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            fingerprint=subprocess.check_output(['openssl','x509','-in',str(cert),'-noout','-fingerprint','-sha256'],text=True).strip().split('=',1)[1].replace(':','')
            api=port(); websocket=port(); brutal=port()
            def vless(tag, inbound_port, network):
                return {'tag':tag,'listen':'127.0.0.1','port':inbound_port,'protocol':'vless',
                    'settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':network}}
            config={'log':{'loglevel':'none'},'api':{'tag':'api','listen':f'127.0.0.1:{api}',
                'services':['HandlerService','StatsService']},'stats':{},
                'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True}}},
                'inbounds':[vless('reality',port(),'tcp'),vless('websocket',websocket,'ws'),
                    vless('residential-01',port(),'ws'),
                    {'tag':'vmess','listen':'127.0.0.1','port':port(),'protocol':'vmess',
                     'settings':{'clients':[]},'streamSettings':{'network':'ws'}},
                    {'tag':'hysteria2','listen':'127.0.0.1','port':port(),'protocol':'hysteria',
                     'settings':{'version':2,'clients':[]},'streamSettings':{'network':'hysteria','security':'tls',
                        'hysteriaSettings':{'version':2},'tlsSettings':{'certificates':[{'certificateFile':str(cert),'keyFile':str(key)}]}}},
                    {'tag':'hysteria2-brutal','listen':'127.0.0.1','port':brutal,'protocol':'hysteria',
                     'settings':{'version':2,'clients':[]},'streamSettings':{'network':'hysteria','security':'tls',
                        'hysteriaSettings':{'version':2},'tlsSettings':{'certificates':[{'certificateFile':str(cert),'keyFile':str(key)}]},
                        'finalmask':{'quicParams':{'congestion':'force-brutal','brutalUp':'40 mbps'}}}}],
                'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1/32']}]}}]}
            path=root/'core.json'; path.write_text(json.dumps(config))
            core=subprocess.Popen([XRAY,'run','-config',str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            client=None; brutal_client=None; driver=None
            payload=b'x'*65536
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self,*_): pass
                def do_GET(self):
                    self.send_response(200); self.send_header('Content-Length',str(len(payload))); self.end_headers()
                    with contextlib.suppress(BrokenPipeError,ConnectionResetError): self.wfile.write(payload)
            origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
            thread=threading.Thread(target=origin.serve_forever,daemon=True);thread.start()
            def call(data):
                driver.stdin.write(json.dumps(data)+'\n');driver.stdin.flush()
                line=driver.stdout.readline();self.assertTrue(line,'managed Xray driver stopped');return json.loads(line)
            try:
                for _ in range(80):
                    if core.poll() is not None: self.fail('disposable Xray core stopped')
                    try:
                        with socket.create_connection(('127.0.0.1',api),timeout=.2): break
                    except OSError: time.sleep(.1)
                else: self.fail('disposable Xray API did not start')
                pids=root/'pids';pids.write_text(str(core.pid)+'\n')
                identity=str(uuid.uuid4());db_path=root/'gateway.sqlite'
                db=sqlite3.connect(db_path)
                db.executescript('''
                    CREATE TABLE users(id TEXT PRIMARY KEY,uuid TEXT NOT NULL,enabled INTEGER NOT NULL,deleted INTEGER NOT NULL,
                        quota INTEGER NOT NULL,expires INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL);
                    CREATE TABLE counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL,generation TEXT NOT NULL);
                    CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                    CREATE TABLE device_activity(user_id TEXT NOT NULL,transport TEXT NOT NULL,last_seen INTEGER NOT NULL DEFAULT 0,
                        sampled INTEGER NOT NULL DEFAULT 0,upload_delta INTEGER NOT NULL DEFAULT 0,download_delta INTEGER NOT NULL DEFAULT 0,
                        interval_seconds INTEGER NOT NULL DEFAULT 5,PRIMARY KEY(user_id,transport));
                    CREATE TABLE samples(ts INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL);
                    CREATE TABLE traffic_history(ts INTEGER PRIMARY KEY,upload INTEGER NOT NULL,download INTEGER NOT NULL);
                    CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
                ''')
                db.execute('INSERT INTO users VALUES(?,?,1,0,1,0,0,0)',(USER,identity));db.commit();db.close()
                driver=subprocess.Popen([DRIVER,XRAY,str(pids),f'127.0.0.1:{api}','residential-01-hy2',str(db_path)],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
                generation=call({'op':'generation'});self.assertTrue(generation['ok'])
                self.assertTrue(generation['value'].startswith(str(core.pid)+':'))
                tags=['reality','websocket','vmess','hysteria2','hysteria2-brutal','residential-01','residential-01-hy2']
                for tag in tags:
                    self.assertEqual(call({'op':'users','tag':tag})['value'],{})
                    self.assertTrue(call({'op':'add','tag':tag,'id':USER,'uuid':identity})['ok'],tag)
                for tag in tags:
                    self.assertEqual(call({'op':'users','tag':tag})['value'],{f'{USER}.{identity[:8]}@{tag}':identity})
                socks=port();client_cfg={'log':{'loglevel':'none'},
                    'inbounds':[{'listen':'127.0.0.1','port':socks,'protocol':'socks','settings':{'auth':'noauth'}}],
                    'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':websocket,
                        'users':[{'id':identity,'encryption':'none'}]}]},'streamSettings':{'network':'ws','security':'none'}}]}
                client_path=root/'client.json';client_path.write_text(json.dumps(client_cfg))
                client=subprocess.Popen([XRAY,'run','-config',str(client_path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                for _ in range(80):
                    if client.poll() is not None:self.fail('disposable Xray client stopped')
                    try:
                        with socket.create_connection(('127.0.0.1',socks),timeout=.2):break
                    except OSError:time.sleep(.1)
                else:self.fail('disposable Xray client did not start')
                command=['curl','--noproxy','','--proxy',f'socks5h://127.0.0.1:{socks}','-fsS','--max-time','5',
                    f'http://127.0.0.1:{origin.server_port}/blob']
                response=subprocess.run(command,capture_output=True,timeout=10)
                self.assertEqual(response.returncode,0);self.assertEqual(response.stdout,payload)
                found=False
                for _ in range(30):
                    result=call({'op':'counters'});self.assertTrue(result['ok'])
                    found=any(item['name'].endswith('@websocket>>>traffic>>>downlink') and item['value']>=len(payload) for item in result['value'])
                    if found:break
                    time.sleep(.1)
                self.assertTrue(found,'real WebSocket traffic was not reflected in gRPC stats')
                fast_socks=port()
                fast_cfg={'log':{'loglevel':'none'},
                    'inbounds':[{'listen':'127.0.0.1','port':fast_socks,'protocol':'socks','settings':{'auth':'noauth'}}],
                    'outbounds':[{'protocol':'hysteria','settings':{'version':2,'address':'127.0.0.1','port':brutal},
                        'streamSettings':{'network':'hysteria','security':'tls','hysteriaSettings':{'version':2,'auth':identity},
                            'tlsSettings':{'serverName':'node.test','pinnedPeerCertSha256':fingerprint,'alpn':['h3']}}}]}
                fast_path=root/'fast-client.json';fast_path.write_text(json.dumps(fast_cfg))
                brutal_client=subprocess.Popen([XRAY,'run','-config',str(fast_path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                for _ in range(80):
                    if brutal_client.poll() is not None:self.fail('disposable Brutal client stopped')
                    try:
                        with socket.create_connection(('127.0.0.1',fast_socks),timeout=.2):break
                    except OSError:time.sleep(.1)
                else:self.fail('disposable Brutal client did not start')
                fast_command=['curl','--noproxy','','--proxy',f'socks5h://127.0.0.1:{fast_socks}','-fsS','--max-time','8',
                              f'http://127.0.0.1:{origin.server_port}/blob']
                response=subprocess.run(fast_command,capture_output=True,timeout=12)
                self.assertEqual(response.returncode,0);self.assertEqual(response.stdout,payload)
                for _ in range(30):
                    result=call({'op':'counters'});self.assertTrue(result['ok'])
                    if any(item['name'].endswith('@hysteria2-brutal>>>traffic>>>downlink') and item['value']>=len(payload) for item in result['value']):break
                    time.sleep(.1)
                else:self.fail('real Brutal traffic was not reflected in gRPC stats')
                bad=call({'op':'restart','generation':generation['value']+'x'})
                self.assertEqual(bad['error'],'CoreChanged');self.assertIsNone(core.poll())
                result=call({'op':'poll','tags':tags,'now':int(time.time())})
                self.assertEqual(result,{'ok':True,'value':{'state':'restarting'}})
                core.wait(timeout=8)
                db=sqlite3.connect(db_path)
                try:
                    self.assertGreaterEqual(db.execute('SELECT download FROM users WHERE id=?',(USER,)).fetchone()[0],2*len(payload))
                    self.assertEqual(db.execute("SELECT count(*) FROM events WHERE action='core_restart'").fetchone()[0],1)
                finally:db.close()
                self.assertFalse(call({'op':'generation'})['ok'])
                self.assertNotEqual(subprocess.run(command,capture_output=True,timeout=10).returncode,0)
            finally:
                if driver is not None:
                    driver.stdin.close()
                    try:driver.wait(timeout=10)
                    except subprocess.TimeoutExpired:driver.kill();driver.wait(timeout=5)
                    driver.stdout.close()
                stop(brutal_client);stop(client);stop(core);origin.shutdown();origin.server_close();thread.join(timeout=5)
