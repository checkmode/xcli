"""Real isolated Xray and Nginx across Rust import, restart and rollback.

The service manager, monitor and proxy probe are synthetic. All sockets are in
an isolated network namespace and no production file or service is touched.
"""
from contextlib import closing, suppress
import hashlib
import http.server
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time
import unittest

from test_panel_http_integration import request, stop, wait_ready
from test_node_service_integration import port, socket_open, wait_for

PANEL=os.environ.get('XCLI_PANEL_SERVICE','')
INIT=os.environ.get('XCLI_PANEL_INIT','')
IMPORT=os.environ.get('XCLI_IMPORT_SERVICE','')
WEB=os.environ.get('XCLI_WEB_GATEWAY','')
NODE=os.environ.get('XCLI_TEST_NODE','node')
UID=int(os.environ.get('XCLI_TEST_REPORT_UID','0'))
GID=int(os.environ.get('XCLI_TEST_REPORT_GID','0'))
XRAY='/usr/local/lib/xcli/xray'


def exact(sock, count):
    out=b''
    while len(out)<count:
        data=sock.recv(count-len(out))
        if not data:raise EOFError()
        out+=data
    return out


class Proxy(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            sock=self.request;sock.settimeout(8)
            head=exact(sock,2);methods=exact(sock,head[1])
            if head[0]!=5 or 2 not in methods:return
            sock.sendall(b'\x05\x02')
            auth=exact(sock,2);user=exact(sock,auth[1]);length=exact(sock,1)[0];password=exact(sock,length)
            if user!=b'fixture' or password!=b'synthetic-password':sock.sendall(b'\x01\x01');return
            sock.sendall(b'\x01\x00')
            req=exact(sock,4)
            if req[:3]!=b'\x05\x01\x00':return
            if req[3]==1:host=socket.inet_ntop(socket.AF_INET,exact(sock,4))
            elif req[3]==3:host=exact(sock,exact(sock,1)[0]).decode()
            elif req[3]==4:host=socket.inet_ntop(socket.AF_INET6,exact(sock,16))
            else:return
            target=struct.unpack('!H',exact(sock,2))[0]
            if host!='127.0.0.1':return
            with socket.create_connection((host,target),timeout=3) as upstream:
                sock.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                while True:
                    readable,_,_=select.select([sock,upstream],[],[],8)
                    if not readable:return
                    for source in readable:
                        data=source.recv(65536)
                        if not data:return
                        (upstream if source is sock else sock).sendall(data)
        except (OSError,EOFError,ValueError):pass


class ThreadServer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True


@unittest.skipUnless(os.geteuid()==0 and UID and GID and PANEL and INIT and IMPORT and
                     all(Path(p).is_file() for p in (PANEL,INIT,IMPORT,XRAY)), 'requires isolated fixture binaries')
class RealImportService(unittest.TestCase):
    def test_add_routes_traffic_and_failed_reload_rolls_back(self):
        self.assertNotEqual(os.readlink('/proc/self/ns/mnt'),os.readlink('/proc/1/ns/mnt'))
        self.assertNotEqual(os.readlink('/proc/self/ns/net'),os.readlink('/proc/1/ns/net'))
        with tempfile.TemporaryDirectory(prefix='xcli-real-import-',dir='/var/lib') as folder:
            root=Path(folder);root.chmod(0o755)
            for name,mode in [('state',0o700),('journal',0o700),('report',0o750),('worker-state',0o700),('monitor',0o700)]:
                (root/name).mkdir(mode=mode)
            os.chown(root/'state',UID,GID);os.chown(root/'report',0,GID)
            inbox=root/'state/proxy-import';inbox.mkdir(mode=0o700);os.chown(inbox,UID,GID)
            db=root/'state/gateway.sqlite'
            subprocess.run([INIT,str(db)],check=True,timeout=15,user=UID,group=GID,extra_groups=[])
            key=root/'key';key.write_bytes(bytes(range(32)));key.chmod(0o600);os.chown(key,UID,GID)
            api,ws,reality,webport,nginxport,nginxport2=port(),port(),port(),port(),port(),port()
            core_path=root/'core.json';settings=root/'settings.json';monitor_config=root/'monitor.json';pool=root/'pool.json'
            config={'origin':'https://testserver','domain':'testserver','public_ip':'203.0.113.2',
                    'reality_sni':'example.com','reality_public':'p'*43,'short_id':'aabbccdd',
                    'ws_path':'/connect/fixture','hysteria2_port':0,'residential_exits':[]}
            settings.write_text(json.dumps(config));settings.chmod(0o644)
            monitor_config.write_text(json.dumps({'residential_exits':[]}));monitor_config.chmod(0o644)
            def inbound(tag,p,network):
                return {'tag':tag,'listen':'127.0.0.1','port':p,'protocol':'vless',
                    'settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':network}}
            core={'log':{'loglevel':'none'},'api':{'tag':'api','listen':f'127.0.0.1:{api}',
                    'services':['HandlerService','StatsService']},'stats':{},
                'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True}}},
                'inbounds':[inbound('reality',reality,'tcp'),inbound('websocket',ws,'ws')],
                'outbounds':[{'tag':'direct','protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1/32']}]}},
                             {'tag':'blocked','protocol':'blackhole'}], 'routing':{'rules':[]}}
            core_path.write_text(json.dumps(core));core_path.chmod(0o644)
            nginx_config=Path('/etc/nginx/nginx.conf');locations=Path('/etc/nginx/xcli-import-locations.conf')
            nginx_config.write_text(f'''pid /run/xcli-test/nginx.pid;
error_log {root}/nginx-error.log;
events {{}}
http {{ access_log off; map $http_upgrade $connection_upgrade {{ default upgrade; '' close; }}
server {{ listen 127.0.0.1:{nginxport}; location = /connect/fixture {{ proxy_pass http://127.0.0.1:{ws}; }} }}
server {{ listen 127.0.0.1:{nginxport2}; location = /connect/fixture {{ proxy_pass http://127.0.0.1:{ws}; }} }} }}
''');nginx_config.chmod(0o644)
            probe=Path('/usr/local/lib/xcli/xcli-import-probe')
            probe.write_text(f'''#!/bin/sh
[ "$(id -u)" = "{UID}" ] || exit 1
IFS= read -r input || exit 1
printf '%s\\n' '{{"ok":true,"exit_ip":"8.8.8.8","country":"US","https_ms":1,"doh_ms":1}}'
''');probe.chmod(0o755)
            proxy=ThreadServer(('1.1.1.1',0),Proxy);proxy_thread=threading.Thread(target=proxy.serve_forever,daemon=True);proxy_thread.start()
            payload=b'xcli-fixture-response'*256
            class Origin(http.server.BaseHTTPRequestHandler):
                def log_message(self,*_):pass
                def do_GET(self):
                    self.send_response(200);self.send_header('Content-Length',str(len(payload)));self.end_headers()
                    with suppress(OSError):self.wfile.write(payload)
            origin=http.server.ThreadingHTTPServer(('127.0.0.1',0),Origin)
            origin_thread=threading.Thread(target=origin.serve_forever,daemon=True);origin_thread.start()
            panel_port=port();pidfile=root/'core.pid';report_file=root/'monitor/report.json'
            monitor_stop=threading.Event()
            def monitor_loop():
                while not monitor_stop.is_set():
                    try:
                        value=json.loads(settings.read_text());now=int(time.time())
                        tags=['reality','websocket']+[row['tag'] for row in value.get('residential_exits',[])]
                        checks=[{'transport':tag,'status':'healthy','https_ms':5,'udp_ms':5,'doh_ms':5,
                                 'last_success':now,'error':''} for tag in tags]
                        tmp=root/'monitor/tmp';tmp.write_text(json.dumps({'schema':1,'scope':'server','status':'healthy',
                            'updated':now+1,'checks':checks}));tmp.chmod(0o640);tmp.replace(report_file)
                    except (OSError,ValueError,KeyError):pass
                    monitor_stop.wait(.2)
            monitor_thread=threading.Thread(target=monitor_loop,daemon=True);monitor_thread.start()
            class Manager:
                def __init__(self):self.core=None;self.panel=None;self.fail_reload=False;self.lock=threading.RLock()
                def start_core(self):
                    self.core=subprocess.Popen([XRAY,'run','-config',str(core_path)],user=UID,group=GID,extra_groups=[],
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    pidfile.write_text(str(self.core.pid));pidfile.chmod(0o644)
                    Path('/run/xcli-test/core.pid').write_text(str(self.core.pid))
                    if not wait_for(lambda:socket_open(api),10):raise RuntimeError('core start failed')
                def start_panel(self):
                    args=[PANEL,'--experimental','--db',str(db),'--secret-key',str(key),'--settings',str(settings),
                        '--origin','https://testserver','--port',str(panel_port),'--core-binary',XRAY,
                        '--core-api',f'127.0.0.1:{api}','--core-pid-file',str(pidfile),'--core-tags','auto',
                        '--core-poll-seconds','1','--experimental-import-report-dir',str(root/'report'),
                        '--experimental-import-report-gid',str(GID),'--experimental-import-inbox',str(inbox),
                        '--experimental-import-apply','true']
                    self.panel=subprocess.Popen(args,user=UID,group=GID,extra_groups=[],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    Path('/run/xcli-test/panel.pid').write_text(str(self.panel.pid));wait_ready(self.panel,panel_port)
                def handle(self,args):
                    with self.lock:
                        command=args[0] if args else ''
                        try:
                            if command=='is-active':return 0 if self.core and self.core.poll() is None else 3
                            if command=='stop':
                                for name in args[1:]:
                                    if name=='xcli-panel.service' and self.panel is not None:stop(self.panel);self.panel=None
                                    if name=='xcli-core.service' and self.core is not None:stop(self.core);self.core=None
                                return 0
                            if command=='start':
                                for name in args[1:]:
                                    if name=='xcli-core.service' and self.core is None:self.start_core()
                                    if name=='xcli-panel.service' and self.panel is None:self.start_panel()
                                return 0
                            if command=='reload' and args[1:] == ['nginx.service']:
                                if self.fail_reload:self.fail_reload=False;return 1
                                return subprocess.run(['/usr/sbin/nginx','-s','reload','-c',str(nginx_config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode
                        except (OSError,AssertionError,RuntimeError,subprocess.SubprocessError):return 1
                        return 1
            manager=Manager()
            class ManagerHandler(socketserver.StreamRequestHandler):
                def handle(self):
                    try:result=manager.handle(json.loads(self.rfile.readline(8192)))
                    except Exception:result=1
                    self.wfile.write(f'{result}\n'.encode())
            class UnixServer(socketserver.ThreadingUnixStreamServer):daemon_threads=True
            control=UnixServer('/run/xcli-test/manager.sock',ManagerHandler)
            control_thread=threading.Thread(target=control.serve_forever,daemon=True);control_thread.start()
            gateway=worker=client=None
            try:
                subprocess.run(['/usr/sbin/nginx','-c',str(nginx_config)],check=True,timeout=10,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                manager.start_core();manager.start_panel()
                if WEB:
                    gateway=subprocess.Popen([NODE,WEB],env=dict(os.environ,XCLI_CORE_PORT=str(panel_port),XCLI_WEB_PORT=str(webport)),
                        user=UID,group=GID,extra_groups=[],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);wait_ready(gateway,webport)
                else:webport=panel_port
                service_config=root/'import-service.json'
                service_config.write_text(json.dumps({'mode':'apply','key':str(key),'inbox':str(inbox),
                    'state':str(root/'worker-state'),'journal':str(root/'journal'),'update_lock':str(root/'journal/update.lock'),
                    'report_directory':str(root/'report'),'panel_uid':UID,'panel_gid':GID,'probe_uid':UID,'probe_gid':GID,
                    'targets':{'settings':str(settings),'core':str(core_path),'monitor':str(monitor_config),
                        'nginx':str(nginx_config),'locations':str(locations),'pool':str(pool)},
                    'database':str(db),'core_pid_file':str(pidfile),'core_api':f'127.0.0.1:{api}',
                    'panel_port':panel_port,'monitor_report':str(report_file),'core_unit':'xcli-core.service',
                    'panel_unit':'xcli-panel.service','monitor_unit':'xcli-monitor.service'}));service_config.chmod(0o600)
                worker=subprocess.Popen([IMPORT,'--experimental','--config',str(service_config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                def report_status():
                    try:return json.loads((root/'report/report.json').read_text())
                    except (OSError,ValueError):return {}
                self.assertTrue(wait_for(lambda:report_status().get('status')=='idle',10),'import worker did not start')
                status,headers,_=request(webport,'/api/login','POST',json.dumps({'username':'admin','password':'fixture-password-123'}).encode())
                self.assertEqual(status,200);cookie=headers['set-cookie'].split(';',1)[0]
                csrf=json.loads(request(webport,'/api/session',cookie=cookie)[2])['csrf']
                status,_,body=request(webport,'/api/users','POST',json.dumps({'name':'fixture'}).encode(),cookie,csrf)
                self.assertEqual(status,200);user_id=json.loads(body)['id']
                with sqlite3.connect(db) as connection:identity=connection.execute('SELECT uuid FROM users WHERE id=?',(user_id,)).fetchone()[0]
                self.assertTrue(wait_for(lambda:request(panel_port,'/internal/ready')[0]==200,10))
                def fetch(address,target_port,path):
                    nonlocal client
                    socks=port();client_config=root/'client.json'
                    client_config.write_text(json.dumps({'log':{'loglevel':'none'},'inbounds':[{'listen':'127.0.0.1','port':socks,
                        'protocol':'socks','settings':{'auth':'noauth'}}], 'outbounds':[{'protocol':'vless',
                        'settings':{'vnext':[{'address':address,'port':target_port,'users':[{'id':identity,'encryption':'none'}]}]},
                        'streamSettings':{'network':'ws','wsSettings':{'path':path}}}]}));client_config.chmod(0o644)
                    client=subprocess.Popen([XRAY,'run','-config',str(client_config)],user=UID,group=GID,extra_groups=[],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    self.assertTrue(wait_for(lambda:socket_open(socks),8),'client did not start')
                    result=subprocess.run(['curl','--noproxy','','--proxy',f'socks5h://127.0.0.1:{socks}','-fsS','--max-time','6',
                        f'http://127.0.0.1:{origin.server_port}/fixture'],capture_output=True,timeout=9)
                    stop(client);client=None
                    self.assertEqual(result.returncode,0,'client request failed');self.assertEqual(result.stdout,payload)
                fetch('127.0.0.1',ws,'/')
                before_pid=manager.core.pid
                def usage():
                    with sqlite3.connect(db) as connection:return connection.execute('SELECT upload,download FROM users WHERE id=?',(user_id,)).fetchone()
                self.assertTrue(wait_for(lambda:usage()[1]>=len(payload),8),'traffic was not recorded')
                prior=usage()
                body=json.dumps({'action':'preview','protocol':'socks','label':'fixture',
                    'text':f'1.1.1.1:{proxy.server_address[1]}:fixture:synthetic-password'}).encode()
                status,_,data=request(webport,'/api/proxy-import','POST',body,cookie,csrf);self.assertEqual(status,202)
                preview=json.loads(data)['id']
                self.assertTrue(wait_for(lambda:report_status().get('status')=='ready' and report_status().get('id')==preview,15),'preview failed')
                status,_,data=request(webport,'/api/proxy-import','POST',json.dumps({'action':'apply','preview_id':preview}).encode(),cookie,csrf)
                self.assertEqual(status,202);job=json.loads(data)['id']
                self.assertTrue(wait_for(lambda:report_status().get('id')==job and report_status().get('status') in ('complete','failed'),35),'apply timed out')
                self.assertEqual(report_status()['status'],'complete');self.assertNotEqual(manager.core.pid,before_pid)
                self.assertTrue(all(usage()[i]>=prior[i] for i in range(2)),'pre-restart usage was lost')
                fetch('127.0.0.1',nginxport,'/connect/fixture/residential-27')
                fetch('127.0.0.1',nginxport2,'/connect/fixture/residential-27')
                self.assertEqual(json.loads(settings.read_text())['residential_exits'][0]['tag'],'residential-27')
                protected=[settings,core_path,monitor_config,nginx_config,locations,pool]
                before=[hashlib.sha256(p.read_bytes()).digest() for p in protected]
                status,_,data=request(webport,'/api/proxy-import','POST',json.dumps({'action':'manage','operation':'disable','tag':'residential-27'}).encode(),cookie,csrf)
                self.assertEqual(status,202);preview=json.loads(data)['id']
                self.assertTrue(wait_for(lambda:report_status().get('id')==preview and report_status().get('status')=='ready',15),'disable preview failed')
                manager.fail_reload=True
                status,_,data=request(webport,'/api/proxy-import','POST',json.dumps({'action':'apply','preview_id':preview}).encode(),cookie,csrf)
                self.assertEqual(status,202);job=json.loads(data)['id']
                self.assertTrue(wait_for(lambda:report_status().get('id')==job and report_status().get('status') in ('complete','failed'),45),'rollback timed out')
                self.assertEqual(report_status()['status'],'failed')
                self.assertEqual(before,[hashlib.sha256(p.read_bytes()).digest() for p in protected],'rollback did not restore configs')
                fetch('127.0.0.1',nginxport,'/connect/fixture/residential-27')
                fetch('127.0.0.1',nginxport2,'/connect/fixture/residential-27')
            finally:
                stop(client);stop(worker);stop(gateway)
                with manager.lock:stop(manager.panel);stop(manager.core)
                subprocess.run(['/usr/sbin/nginx','-s','stop','-c',str(nginx_config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
                control.shutdown();control.server_close();control_thread.join(timeout=5)
                monitor_stop.set();monitor_thread.join(timeout=5)
                origin.shutdown();origin.server_close();origin_thread.join(timeout=5)
                proxy.shutdown();proxy.server_close();proxy_thread.join(timeout=5)


if __name__=='__main__':unittest.main()
