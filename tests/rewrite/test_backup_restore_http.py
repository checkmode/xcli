"""Restore through the web gateway against an isolated, real Xray core."""
import contextlib
import http.server
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import threading
import unittest

from test_node_service_integration import port, socket_open, wait_for
from test_panel_http_integration import request, stop, wait_ready

XRAY = os.environ.get('XCLI_TEST_XRAY', '')
PANEL = os.environ.get('XCLI_PANEL_SERVICE', '')
WEB = os.environ.get('XCLI_WEB_GATEWAY', '')
NODE = os.environ.get('XCLI_TEST_NODE', 'node')


@unittest.skipUnless(all(value and Path(value).is_file() for value in (XRAY, PANEL)),
                     'set XCLI_TEST_XRAY and XCLI_PANEL_SERVICE')
class BackupRestoreHttp(unittest.TestCase):
    def test_restore_samples_traffic_and_accepts_delayed_node_usage(self):
        with tempfile.TemporaryDirectory(prefix='xcli-restore-') as folder:
            root = Path(folder)
            key = root / 'key'; key.write_bytes(bytes(range(32))); key.chmod(0o600)
            db_path = root / 'gateway.sqlite'
            with sqlite3.connect(db_path) as db:
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
                db.execute('INSERT INTO admin VALUES(1,?)', ('000102030405060708090a0b0c0d0e0f:'
                    'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf',))
            settings = root / 'settings.json'
            settings.write_text(json.dumps({'origin':'https://testserver', 'domain':'testserver',
                'public_ip':'203.0.113.2', 'reality_sni':'www.bing.com', 'reality_public':'Y'*43,
                'short_id':'0123456789abcdef', 'ws_path':'/connect/test', 'hysteria2_port':443}))
            api, websocket = port(), port()
            config = {'log':{'loglevel':'none'}, 'api':{'tag':'api','listen':f'127.0.0.1:{api}',
                'services':['HandlerService','StatsService']}, 'stats':{},
                'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True}}},
                'inbounds':[{'tag':'websocket','listen':'127.0.0.1','port':websocket,'protocol':'vless',
                    'settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':'ws','wsSettings':{'path':'/test'}}}],
                'outbounds':[{'protocol':'freedom','settings':{'finalRules':[{'action':'allow','ip':['127.0.0.1/32']}]}}]}
            core_path = root / 'core.json'; core_path.write_text(json.dumps(config))
            core = subprocess.Popen([XRAY, 'run', '-config', str(core_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            pidfile = root / 'pids'; pidfile.write_text(str(core.pid) + '\n')
            panel_port = port(); panel = gateway = client = origin = thread = None
            try:
                self.assertTrue(wait_for(lambda: socket_open(api), 8))
                panel = subprocess.Popen([PANEL, '--experimental', '--db', str(db_path), '--secret-key', str(key),
                    '--origin','https://testserver', '--settings',str(settings), '--port',str(panel_port),
                    '--core-binary',XRAY, '--core-api',f'127.0.0.1:{api}', '--core-pid-file',str(pidfile),
                    '--core-tags','websocket', '--core-poll-seconds','1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                wait_ready(panel, panel_port)
                if WEB:
                    gateway_port = port()
                    gateway = subprocess.Popen([NODE, WEB], env=dict(os.environ, XCLI_CORE_PORT=str(panel_port),
                        XCLI_WEB_PORT=str(gateway_port)), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    wait_ready(gateway, gateway_port); panel_port = gateway_port
                def post(path, value, cookie='', csrf='', extra=None):
                    return request(panel_port, path, 'POST', json.dumps(value).encode(), cookie, csrf, extra=extra)
                login = {'username':'admin','password':'fixture-password'}
                status, headers, body = post('/api/login', login)
                self.assertEqual(status, 200); cookie = headers['set-cookie'].split(';',1)[0]; csrf = json.loads(body)['csrf']
                status, _, body = post('/api/users', {'name':'before'}, cookie, csrf)
                self.assertEqual(status, 200); earlier = json.loads(body)['id']
                status, _, body = post('/api/backups', {}, cookie, csrf)
                self.assertEqual(status, 200); backup_id = json.loads(body)['id']
                status, _, body = post('/api/users', {'name':'after'}, cookie, csrf)
                self.assertEqual(status, 200); later = json.loads(body)['id']
                with sqlite3.connect(db_path) as db:
                    identity, token = db.execute('SELECT uuid,token FROM users WHERE id=?', (later,)).fetchone()
                def live_users():
                    result = subprocess.run([XRAY,'api','inbounduser',f'--server=127.0.0.1:{api}',
                        '-tag=websocket','--timeout=1'], capture_output=True, timeout=3)
                    return len(json.loads(result.stdout).get('users', [])) if result.returncode == 0 else 0
                self.assertTrue(wait_for(lambda: live_users() == 2, 12), 'new user was not granted')
                node_id = 'a'*32; node_key = 'Z'*43
                registration = {'version':1,'id':node_id,'key':node_key,'public_ip':'8.8.8.8','domain':'node.example.com',
                    'public_port':443,'reality_sni':'www.bing.com','reality_public':'Y'*43,'short_id':'0123456789abcdef',
                    'ws_path':'/connect/'+'b'*24,'hysteria2_port':443}
                self.assertEqual(post('/api/remote-nodes', {'name':'fixture','registration':registration,'users':[later]}, cookie, csrf)[0], 201)
                node_auth = {'Authorization':f'Xcli-Node {node_id}.{node_key}'}
                payload = b'x' * 65536
                class Origin(http.server.BaseHTTPRequestHandler):
                    def log_message(self, *_): pass
                    def do_GET(self):
                        self.send_response(200); self.send_header('Content-Length', str(len(payload))); self.end_headers()
                        with contextlib.suppress(BrokenPipeError, ConnectionResetError): self.wfile.write(payload)
                origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
                thread = threading.Thread(target=origin.serve_forever, daemon=True); thread.start()
                socks = port(); client_path = root / 'client.json'
                client_path.write_text(json.dumps({'log':{'loglevel':'none'},
                    'inbounds':[{'listen':'127.0.0.1','port':socks,'protocol':'socks','settings':{'auth':'noauth'}}],
                    'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':websocket,
                        'users':[{'id':identity,'encryption':'none'}]}]},'streamSettings':{'network':'ws','wsSettings':{'path':'/test'}}}]}))
                client = subprocess.Popen([XRAY,'run','-config',str(client_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.assertTrue(wait_for(lambda: socket_open(socks), 8))
                command = ['curl','--noproxy','','--proxy',f'socks5h://127.0.0.1:{socks}','-fsS','--max-time','5',
                    f'http://127.0.0.1:{origin.server_port}/blob']
                response = subprocess.run(command, capture_output=True, timeout=8)
                self.assertEqual(response.returncode, 0); self.assertEqual(response.stdout, payload)
                restore = {'id':backup_id,'confirm':backup_id,'current_password':'fixture-password','code':''}
                self.assertEqual(post('/api/backups/restore', restore, cookie, 'wrong')[0], 403)
                self.assertEqual(post('/api/backups/restore', {**restore,'current_password':'wrong'}, cookie, csrf)[0], 403)
                self.assertEqual(post('/api/backups/restore', {**restore,'confirm':'wrong'}, cookie, csrf)[0], 422)
                pidfile.write_text('0\n')
                self.assertEqual(post('/api/backups/restore', restore, cookie, csrf)[0], 503)
                with sqlite3.connect(db_path) as db:
                    self.assertEqual(db.execute('SELECT enabled,deleted FROM users WHERE id=?',(later,)).fetchone(), (1,0))
                pidfile.write_text(str(core.pid) + '\n')
                status, headers, body = post('/api/backups/restore', restore, cookie, csrf)
                self.assertEqual(status, 200); self.assertEqual(json.loads(body)['safety_backup']['reason'], 'before-restore')
                self.assertIn('Max-Age=0', headers['set-cookie'])
                self.assertEqual(request(panel_port, '/api/session', cookie=cookie)[0], 401)
                with sqlite3.connect(db_path) as db:
                    row = db.execute('SELECT enabled,deleted,upload,download,uuid,token FROM users WHERE id=?',(later,)).fetchone()
                    self.assertEqual(db.execute('SELECT enabled,deleted FROM users WHERE id=?',(earlier,)).fetchone(), (1,0))
                self.assertEqual(row[:2], (0,1)); self.assertGreaterEqual(row[3], len(payload))
                self.assertNotEqual(row[4], identity); self.assertNotEqual(row[5], token)
                report = {'revision':'','counters':[{'id':later,'upload':10,'download':20}]}
                status, _, body = post('/api/nodes/sync', report, extra=node_auth)
                self.assertEqual(status, 200); self.assertEqual(json.loads(body)['ack'][0]['download'], 20)
                with sqlite3.connect(db_path) as db:
                    usage = db.execute('SELECT upload,download FROM users WHERE id=?',(later,)).fetchone()
                self.assertEqual(usage, (row[2]+10,row[3]+20))
                self.assertTrue(wait_for(lambda: core.poll() is not None, 12), 'core was not restarted for revoked user')
                core = subprocess.Popen([XRAY, 'run', '-config', str(core_path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                pidfile.write_text(str(core.pid) + '\n')
                self.assertTrue(wait_for(lambda: socket_open(api), 8))
                self.assertTrue(wait_for(lambda: live_users() == 1, 12), 'restored user was not applied')
                self.assertNotEqual(subprocess.run(command, capture_output=True, timeout=8).returncode, 0,
                                    'post-backup user can still authenticate')
                status, headers, body = post('/api/login', login)
                self.assertEqual(status, 200); cookie = headers['set-cookie'].split(';',1)[0]
                status, _, body = request(panel_port, '/api/users', cookie=cookie)
                self.assertEqual(status, 200); self.assertEqual([item['id'] for item in json.loads(body)['users']], [earlier])
            finally:
                stop(gateway); stop(panel); stop(client); stop(core)
                if origin is not None: origin.shutdown(); origin.server_close(); thread.join(timeout=5)
