"""Exercise a live Xray connection through legacy/Rust panel handovers.

All processes, credentials, database files and network connections are
created by this test and bound to loopback. Xray is never restarted during the
handover; this does not prove the separate core-restart drain problem solved.
"""
import json
import os
from pathlib import Path
import socket
import socketserver
import sqlite3
import struct
import subprocess
import tempfile
import threading
import unittest

from test_node_service_integration import port, socket_open, wait_for
from test_panel_http_integration import request, stop, wait_ready

XRAY=os.environ.get('XCLI_TEST_XRAY','')
OLD=os.environ.get('XCLI_LEGACY_PANEL','')
NEW=os.environ.get('XCLI_PANEL_SERVICE','')
CHECKPOINT=os.environ.get('XCLI_PANEL_CHECKPOINT','')


def read_exact(stream,size):
    result=b''
    while len(result)<size:
        part=stream.recv(size-len(result))
        if not part:break
        result+=part
    return result


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while chunk:=self.request.recv(65536):self.request.sendall(chunk)
        except (OSError,ConnectionError):pass


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads=True
    allow_reuse_address=True


@unittest.skipUnless(XRAY and OLD and NEW and all(Path(p).is_file() for p in (XRAY,OLD,NEW)),
                     'set isolated Xray, legacy panel and experimental panel paths')
class PanelHandoverContinuity(unittest.TestCase):
    def test_same_core_keeps_stream_and_cumulative_usage_across_both_handovers(self):
        with tempfile.TemporaryDirectory(prefix='xcli-handover-') as folder:
            root=Path(folder);state=root/'state';state.mkdir()
            key=root/'security.key';key.write_bytes(bytes(range(32)));key.chmod(0o600)
            settings=root/'settings.json';settings.write_text(json.dumps({'origin':'https://testserver','domain':'testserver',
                'public_ip':'203.0.113.2','reality_sni':'example.com','reality_public':'p'*43,
                'short_id':'aabbccdd','ws_path':'/test'}))
            db_path=state/'gateway.sqlite'
            with sqlite3.connect(db_path) as db:
                db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)')
                db.execute('INSERT INTO admin VALUES(1,?)',('000102030405060708090a0b0c0d0e0f:'
                    'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf',))
            api,websocket,reality=port(),port(),port()
            def inbound(tag,p,network):
                return {'tag':tag,'listen':'127.0.0.1','port':p,'protocol':'vless',
                    'settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':network}}
            core_cfg={'log':{'loglevel':'none'},'api':{'tag':'api','listen':f'127.0.0.1:{api}',
                'services':['HandlerService','StatsService']},'stats':{},
                'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True}}},
                'inbounds':[inbound('reality',reality,'tcp'),inbound('websocket',websocket,'ws')],
                'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1/32']}]}}]}
            core_file=root/'core.json';core_file.write_text(json.dumps(core_cfg))
            core=subprocess.Popen([XRAY,'run','-config',str(core_file)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            pid_file=root/'core.pid';pid_file.write_text(str(core.pid)+'\n')
            echo=EchoServer(('127.0.0.1',0),Echo);echo_thread=threading.Thread(target=echo.serve_forever,daemon=True);echo_thread.start()
            old=new=client=stream=None
            old_port,new_port=port(),port()
            old_args=[OLD,'--state',str(state),'--settings',str(settings),'--static',str(root),'--secret-key',str(key),
                '--port',str(old_port),'--api',f'127.0.0.1:{api}','--core-binary',XRAY,'--core-pid-file',str(pid_file),
                '--poll-seconds','1','--monitor-report',str(root/'missing-report.json'),'--no-auto-backup']
            new_args=[NEW,'--experimental','--db',str(db_path),'--secret-key',str(key),'--settings',str(settings),
                '--origin','https://testserver','--port',str(new_port),'--core-binary',XRAY,'--core-api',f'127.0.0.1:{api}',
                '--core-pid-file',str(pid_file),'--core-tags','auto','--core-poll-seconds','1']
            checkpoint_args=[CHECKPOINT,'--experimental','--db',str(db_path),'--core-binary',XRAY,
                '--core-api',f'127.0.0.1:{api}','--core-pid-file',str(pid_file),'--core-poll-seconds','1']
            try:
                self.assertTrue(wait_for(lambda:socket_open(api),8))
                old=subprocess.Popen(old_args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);wait_ready(old,old_port)
                status,headers,body=request(old_port,'/api/login','POST',json.dumps({'username':'admin','password':'fixture-password'}).encode())
                self.assertEqual(status,200);cookie=headers['set-cookie'].split(';',1)[0];csrf=json.loads(body)['csrf']
                status,_,body=request(old_port,'/api/users','POST',json.dumps({'name':'synthetic-user'}).encode(),cookie,csrf)
                self.assertEqual(status,200);user_id=json.loads(body)['id']
                with sqlite3.connect(db_path) as db:identity=db.execute('SELECT uuid FROM users WHERE id=?',(user_id,)).fetchone()[0]
                def accounts_ready():
                    result=subprocess.run([XRAY,'api','inbounduser',f'--server=127.0.0.1:{api}','-tag=websocket','--timeout=1'],
                        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3)
                    return result.returncode==0 and len(json.loads(result.stdout).get('users',[]))==1
                self.assertTrue(wait_for(accounts_ready,12))
                socks=port();client_cfg={'log':{'loglevel':'none'},
                    'inbounds':[{'listen':'127.0.0.1','port':socks,'protocol':'socks','settings':{'auth':'noauth'}}],
                    'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':websocket,
                        'users':[{'id':identity,'encryption':'none'}]}]},'streamSettings':{'network':'ws','security':'none'}}]}
                client_file=root/'client.json';client_file.write_text(json.dumps(client_cfg))
                client=subprocess.Popen([XRAY,'run','-config',str(client_file)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                self.assertTrue(wait_for(lambda:socket_open(socks),8))
                stream=socket.create_connection(('127.0.0.1',socks),timeout=4);stream.settimeout(5)
                stream.sendall(b'\x05\x01\x00');self.assertEqual(read_exact(stream,2),b'\x05\x00')
                stream.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+struct.pack('!H',echo.server_address[1]))
                self.assertEqual(read_exact(stream,10)[:2],b'\x05\x00')
                def exchange(byte):
                    data=byte*32768;stream.sendall(data);self.assertEqual(read_exact(stream,len(data)),data)
                    self.assertIsNone(core.poll(),'handover unexpectedly stopped Xray')
                def counters():
                    raw=subprocess.check_output([XRAY,'api','statsquery',f'--server=127.0.0.1:{api}','-pattern','user>>>'],timeout=5)
                    values=json.loads(raw).get('stat',[]); email=f'{user_id}.{identity[:8]}@websocket'
                    return tuple(sum(int(item.get('value',0)) for item in values if item['name']==f'user>>>{email}>>>traffic>>>{direction}')
                                 for direction in ('uplink','downlink'))
                def accounted():
                    expected=counters()
                    with sqlite3.connect(db_path) as db:
                        actual=db.execute('SELECT upload,download FROM users WHERE id=?',(user_id,)).fetchone()
                    return expected[0]>0 and expected[1]>0 and actual==expected
                def generation():
                    with sqlite3.connect(db_path) as db:
                        return [row[0] for row in db.execute('SELECT DISTINCT generation FROM counters')]
                def assert_same_generation():
                    generations=generation()
                    self.assertEqual(len(generations),1)
                    self.assertTrue(generations[0].startswith(f'{core.pid}:'))
                exchange(b'A');self.assertTrue(wait_for(accounted,10),'legacy panel failed to sample traffic')
                assert_same_generation()
                if CHECKPOINT:
                    locked=subprocess.run(checkpoint_args,capture_output=True,timeout=10)
                    self.assertNotEqual(locked.returncode,0,'checkpoint ran while the old panel still controlled the database')
                stop(old);old=None
                exchange(b'B')
                if CHECKPOINT:
                    with sqlite3.connect(db_path) as db:
                        db.execute("CREATE TRIGGER fixture_reject_checkpoint BEFORE INSERT ON samples BEGIN SELECT RAISE(ABORT,'fixture'); END")
                    failed=subprocess.run(checkpoint_args,capture_output=True,timeout=10)
                    self.assertNotEqual(failed.returncode,0,'failed checkpoint was reported as successful')
                    self.assertIsNone(core.poll(),'failed checkpoint stopped the core')
                    with sqlite3.connect(db_path) as db:db.execute('DROP TRIGGER fixture_reject_checkpoint')
                    observed=counters()
                    completed=subprocess.run(checkpoint_args,capture_output=True,timeout=10,check=True)
                    self.assertTrue(json.loads(completed.stdout)['generation'].startswith(f'{core.pid}:'))
                    with sqlite3.connect(db_path) as db:
                        saved=db.execute('SELECT upload,download FROM users WHERE id=?',(user_id,)).fetchone()
                    self.assertTrue(all(saved[i]>=observed[i] for i in range(2)),
                        'checkpoint did not persist the traffic observed before handover')
                new=subprocess.Popen(new_args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);wait_ready(new,new_port)
                self.assertTrue(wait_for(accounted,12),'Rust panel missed or duplicated handover traffic')
                exchange(b'C');self.assertTrue(wait_for(accounted,12),'Rust panel failed to account ongoing stream')
                assert_same_generation()
                stop(new);new=None
                exchange(b'D')
                old=subprocess.Popen(old_args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);wait_ready(old,old_port)
                self.assertTrue(wait_for(accounted,12),'legacy rollback missed or duplicated handover traffic')
                exchange(b'E');self.assertTrue(wait_for(accounted,12),'legacy rollback failed to account ongoing stream')
                self.assertIsNone(core.poll());assert_same_generation()
            finally:
                if stream is not None:stream.close()
                stop(new);stop(old);stop(client);stop(core);echo.shutdown();echo.server_close();echo_thread.join(timeout=5)
