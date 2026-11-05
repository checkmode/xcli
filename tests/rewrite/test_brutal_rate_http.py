"""Exercise the authenticated rate update through a disposable privileged worker."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest

from test_panel_http_integration import PANEL, free_port, request, stop, wait_ready

UID = int(os.environ.get('XCLI_TEST_REPORT_UID', '0'))
GID = int(os.environ.get('XCLI_TEST_REPORT_GID', '0'))
WORKER = os.environ.get('XCLI_IMPORT_RUNNER', '')


@unittest.skipUnless(os.geteuid() == 0 and UID and GID and PANEL and Path(PANEL).is_file()
                     and WORKER and Path(WORKER).is_file(), 'requires disposable fixture binaries and root')
class BrutalRateHttp(unittest.TestCase):
    def test_authenticated_rate_update_reaches_worker_and_subscription(self):
        with tempfile.TemporaryDirectory(prefix='xcli-import-fixture-', dir='/var/lib') as folder:
            root = Path(folder); root.chmod(0o755)
            for name, mode in [('bin', 0o755), ('config', 0o755), ('secret', 0o700),
                               ('state', 0o700), ('journal', 0o700), ('report', 0o750), ('panel', 0o700)]:
                (root / name).mkdir(mode=mode)
            os.chown(root / 'report', 0, GID); os.chown(root / 'panel', UID, GID)
            inbox = root / 'panel/inbox'; inbox.mkdir(mode=0o700); os.chown(inbox, UID, GID)
            for path, owner in [(root / 'secret/security.key', 0), (root / 'panel/security.key', UID)]:
                path.write_bytes(bytes(range(32))); path.chmod(0o600); os.chown(path, owner, GID if owner else 0)
            probe = root / 'bin/xcli-import-probe'; probe.write_text('#!/bin/sh\nexit 1\n'); probe.chmod(0o755)
            settings = {'origin':'https://testserver','domain':'testserver','public_ip':'8.8.8.8',
                'reality_sni':'www.example.com','reality_public':'Y'*43,'short_id':'0123456789abcdef',
                'ws_path':'/connect/fixture','hysteria2_port':443,'hysteria2_brutal_port':8443,
                'residential_exits':[]}
            normal = {'tag':'hysteria2','port':443,'protocol':'hysteria',
                      'streamSettings':{'finalmask':{'quicParams':{'congestion':'bbr'}}}}
            fast = {'tag':'hysteria2-brutal','port':8443,'protocol':'hysteria',
                    'streamSettings':{'finalmask':{'quicParams':{'congestion':'force-brutal','brutalUp':'40 mbps'}}}}
            core = {'inbounds':[{'tag':'reality','port':10443},normal,fast],
                    'outbounds':[{'tag':'direct','protocol':'freedom'},{'tag':'blocked','protocol':'blackhole'}],
                    'routing':{'rules':[{'inboundTag':['reality'],'outboundTag':'direct'}]}}
            for name, value in [('settings',settings),('core',core),('monitor',{'residential_exits':[]})]:
                (root / 'config' / name).write_text(json.dumps(value))
            (root / 'config/nginx').write_text('server { location = /connect/fixture {} }')
            db_file = root / 'panel/gateway.sqlite'
            with closing(sqlite3.connect(db_file)) as db:
                db.executescript('''CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL);
                    CREATE TABLE sessions(hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
                    CREATE TABLE mfa(id INTEGER PRIMARY KEY,enabled INTEGER NOT NULL,secret TEXT NOT NULL,last_step INTEGER NOT NULL);
                    CREATE TABLE mfa_sessions(hash TEXT PRIMARY KEY); CREATE TABLE recovery_codes(hash TEXT PRIMARY KEY,used INTEGER NOT NULL DEFAULT 0);
                    CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
                    CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                    CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL,uuid TEXT NOT NULL UNIQUE,token TEXT NOT NULL UNIQUE,
                        enabled INTEGER NOT NULL DEFAULT 1,quota INTEGER NOT NULL DEFAULT 0,expires INTEGER NOT NULL DEFAULT 0,
                        upload INTEGER NOT NULL DEFAULT 0,download INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL,deleted INTEGER NOT NULL DEFAULT 0);
                    INSERT INTO admin VALUES(1,'000102030405060708090a0b0c0d0e0f:afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf');
                    INSERT INTO mfa VALUES(1,0,'',-1);''')
                db.execute('INSERT INTO users VALUES(?,?,?,?,1,0,0,0,0,1,0)',
                    ('a'*32,'fixture','01234567-89ab-4def-8123-456789abcdef','X'*43)); db.commit()
            os.chown(db_file, UID, GID)
            worker = subprocess.Popen([WORKER,'--isolated-apply',str(root),str(GID),str(UID),str(GID)],
                                      stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            panel = None
            try:
                report = root / 'report/report.json'
                for _ in range(200):
                    if report.exists() and json.loads(report.read_text()).get('status') == 'idle': break
                    if worker.poll() is not None: self.fail('fixture worker stopped')
                    time.sleep(.05)
                else: self.fail('fixture worker was not ready')
                port = free_port()
                args = [PANEL,'--experimental','--db',str(db_file),'--secret-key',str(root/'panel/security.key'),
                    '--settings',str(root/'config/settings'),'--origin','https://testserver','--port',str(port),
                    '--experimental-import-report-dir',str(root/'report'),'--experimental-import-report-gid',str(GID),
                    '--experimental-import-inbox',str(inbox),'--experimental-import-apply','true']
                panel = subprocess.Popen(args,user=UID,group=GID,extra_groups=[],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                wait_ready(panel,port)
                login=json.dumps({'username':'admin','password':'fixture-password','code':''}).encode()
                status, headers, body = request(port,'/api/login','POST',login); self.assertEqual(status,200)
                cookie=headers['set-cookie'].split(';',1)[0]; csrf=json.loads(body)['csrf']
                self.assertEqual(json.loads(request(port,'/api/proxy-import',cookie=cookie)[2])['brutal_rate_mbps'],40)
                data=json.dumps({'action':'brutal_rate','mbps':60}).encode()
                self.assertEqual(request(port,'/api/proxy-import','POST',data)[0],401)
                self.assertEqual(request(port,'/api/proxy-import','POST',data,cookie,'wrong')[0],403)
                self.assertEqual(request(port,'/api/proxy-import','POST',data,cookie,csrf,origin='https://evil.example')[0],403)
                self.assertEqual(request(port,'/api/proxy-import','POST',json.dumps({'action':'brutal_rate','mbps':0}).encode(),cookie,csrf)[0],422)
                status,_,body=request(port,'/api/proxy-import','POST',data,cookie,csrf); self.assertEqual(status,202)
                request_id=json.loads(body)['id']
                for _ in range(300):
                    value=json.loads(report.read_text())
                    if value.get('id')==request_id and value.get('status') in ('complete','failed'): break
                    time.sleep(.05)
                self.assertEqual(value.get('status'),'complete')
                changed=json.loads((root/'config/core').read_text()); saved=json.loads((root/'config/settings').read_text())
                self.assertEqual(changed['inbounds'][1],normal)
                self.assertEqual(changed['inbounds'][2]['streamSettings']['finalmask']['quicParams']['brutalUp'],'60 mbps')
                self.assertEqual(saved['hysteria2_brutal_mbps'],60)
                self.assertFalse((root/'config/pool').exists()); self.assertFalse((root/'config/locations').exists())
                with closing(sqlite3.connect(db_file)) as db:
                    self.assertEqual(db.execute("SELECT count(*) FROM events WHERE action='brutal_rate_requested'").fetchone()[0],1)
                stop(panel)
                panel=subprocess.Popen(args,user=UID,group=GID,extra_groups=[],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                wait_ready(panel,port)
                self.assertEqual(json.loads(request(port,'/api/proxy-import',cookie=cookie)[2])['brutal_rate_mbps'],60)
                status,_,body=request(port,'/s/'+'X'*43+'/clash.yaml'); self.assertEqual(status,200)
                self.assertIn(b'"name": "Hysteria 2 Brutal"',body)
                self.assertIn(b'"name": "Hysteria 2 Brutal 40 Mbps"',body)
                self.assertIn(b'"down": "60 Mbps"',body)
            finally:
                stop(panel); stop(worker)


if __name__ == '__main__':
    unittest.main()
