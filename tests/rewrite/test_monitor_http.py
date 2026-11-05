"""Check authenticated, filtered monitor status on the isolated HTTP chain."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest

from test_panel_http_integration import PANEL, WEB, free_port, request, stop, wait_ready


@unittest.skipUnless(PANEL and Path(PANEL).is_file(),'set experimental panel path')
class MonitorHttpIntegration(unittest.TestCase):
    def test_status_requires_login_filters_fields_and_handles_stale_reports(self):
        with tempfile.TemporaryDirectory(prefix='xcli-monitor-http-') as folder:
            root=Path(folder);key=root/'security.key';key.write_bytes(bytes(range(32)));key.chmod(0o600)
            db_file=root/'gateway.sqlite'
            with closing(sqlite3.connect(db_file)) as db:
                db.executescript('''
                    CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL);
                    CREATE TABLE sessions(hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
                    CREATE TABLE mfa(id INTEGER PRIMARY KEY,enabled INTEGER NOT NULL,secret TEXT NOT NULL,last_step INTEGER NOT NULL);
                    CREATE TABLE mfa_sessions(hash TEXT PRIMARY KEY);
                    CREATE TABLE recovery_codes(hash TEXT PRIMARY KEY,used INTEGER NOT NULL DEFAULT 0);
                    CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
                    CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                    CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL,uuid TEXT NOT NULL UNIQUE,
                        token TEXT NOT NULL UNIQUE,enabled INTEGER NOT NULL DEFAULT 1,quota INTEGER NOT NULL DEFAULT 0,
                        expires INTEGER NOT NULL DEFAULT 0,upload INTEGER NOT NULL DEFAULT 0,download INTEGER NOT NULL DEFAULT 0,
                        created INTEGER NOT NULL,deleted INTEGER NOT NULL DEFAULT 0);
                    INSERT INTO admin VALUES(1,'000102030405060708090a0b0c0d0e0f:afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf');
                    INSERT INTO mfa VALUES(1,0,'',-1);
                ''');db.commit()
            settings=root/'settings.json';settings.write_text(json.dumps({'origin':'https://testserver','domain':'testserver',
                'hysteria2_port':443,'residential_exits':[{'tag':'residential-27'}, {'tag':'residential-11','dynamic':True}]}))
            directory=root/'monitor';directory.mkdir(mode=0o700);report=directory/'report.json';stamp=int(time.time())
            def row(kind):
                residential=kind.startswith('residential-')
                return {'transport':kind,'status':'healthy','https_ms':5,'udp_ms':None if residential else 7,
                    'doh_ms':7 if residential else None,'udp_supported':not residential,'last_success':stamp,
                    'error':'','secret':'synthetic-only-secret'}
            raw={'schema':1,'scope':'server','updated':stamp,'status':'healthy','secret':'synthetic-only-secret',
                'checks':[row(kind) for kind in ('reality','websocket','hysteria2','residential-27')]}
            report.write_text(json.dumps(raw));report.chmod(0o640)
            panel_port=free_port();panel=subprocess.Popen([PANEL,'--experimental','--db',str(db_file),'--secret-key',str(key),
                '--settings',str(settings),'--monitor-report',str(report),'--origin','https://testserver','--port',str(panel_port)],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);gateway=None
            try:
                wait_ready(panel,panel_port);port=panel_port
                if WEB:
                    port=free_port();gateway=subprocess.Popen(['node',WEB],env=dict(os.environ,XCLI_CORE_PORT=str(panel_port),XCLI_WEB_PORT=str(port)),
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);wait_ready(gateway,port)
                self.assertEqual(request(port,'/api/monitor')[0],401)
                login=json.dumps({'username':'admin','password':'fixture-password','code':''}).encode()
                status,headers,login_data=request(port,'/api/login','POST',login);self.assertEqual(status,200)
                cookie=headers['set-cookie'].split(';',1)[0]
                csrf=json.loads(login_data)['csrf']
                status,_,data=request(port,'/api/monitor',cookie=cookie);self.assertEqual(status,200)
                self.assertEqual(json.loads(data)['status'],'healthy');self.assertNotIn(b'synthetic-only-secret',data)
                self.assertEqual(request(port,'/api/history')[0],401)
                for _ in range(30):
                    status,_,data=request(port,'/api/history?range=1h',cookie=cookie)
                    self.assertEqual(status,200)
                    history=json.loads(data)
                    if any(row['transport']=='reality' and row['healthy']==1 for row in history['summary']):break
                    time.sleep(.1)
                else:self.fail('history worker did not record the monitor report')
                self.assertNotIn(b'synthetic-only-secret',data)
                self.assertEqual(request(port,'/api/history?range=invalid',cookie=cookie)[0],422)
                with closing(sqlite3.connect(db_file)) as db:
                    self.assertEqual(db.execute("SELECT good,last_sample FROM alarm_state WHERE service='reality'").fetchone(),(1,stamp))
                status,_,data=request(port,'/api/notifications',cookie=cookie)
                self.assertEqual(status,200);self.assertFalse(json.loads(data)['delivery_active'])
                self.assertEqual(request(port,'/api/notifications/test','POST')[0],401)
                self.assertEqual(request(port,'/api/notifications/test','POST',cookie=cookie,csrf='bad')[0],403)
                self.assertEqual(request(port,'/api/notifications/test','POST',cookie=cookie,csrf=csrf)[0],503)
                with closing(sqlite3.connect(db_file)) as db:
                    self.assertEqual(db.execute("SELECT COUNT(*) FROM notifications WHERE kind='test'").fetchone()[0],0)
                raw['updated']=stamp-181;report.write_text(json.dumps(raw))
                self.assertEqual(json.loads(request(port,'/api/monitor',cookie=cookie)[2])['status'],'stale')
                raw['updated']=stamp;raw['checks'].pop();report.write_text(json.dumps(raw))
                self.assertEqual(json.loads(request(port,'/api/monitor',cookie=cookie)[2])['status'],'unknown')
                report.unlink();report.symlink_to(settings)
                self.assertEqual(json.loads(request(port,'/api/monitor',cookie=cookie)[2])['status'],'unknown')
            finally:
                stop(gateway);stop(panel)
