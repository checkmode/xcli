"""Exercise the experimental Rust HTTP service, optionally through the Node gateway.

All databases, credentials and network endpoints in this test are disposable.
Set XCLI_PANEL_SERVICE to the built Rust executable; XCLI_WEB_GATEWAY can point
to the compiled Node gateway's main.js to exercise the complete local chain.
"""
import base64
from contextlib import closing
import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
import time
import unittest

PANEL = os.environ.get('XCLI_PANEL_SERVICE', '')
WEB = os.environ.get('XCLI_WEB_GATEWAY', '')
DISK_PROBE = os.environ.get('XCLI_DISK_PROBE', '')
STRICT_SETTINGS = bool(os.environ.get('XCLI_STRICT_SETTINGS', ''))


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def request(port, path, method='GET', body=None, cookie='', csrf='', origin='https://testserver', extra=None):
    headers = {'Origin': origin, 'Content-Type': 'application/json'}
    if cookie:
        headers['Cookie'] = cookie
    if csrf:
        headers['X-CSRF-Token'] = csrf
    headers.update(extra or {})
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
    try:
        conn.request(method, path, body=body, headers=headers)
        res = conn.getresponse()
        return res.status, dict((k.lower(), v) for k, v in res.getheaders()), res.read()
    finally:
        conn.close()


def wait_ready(process, port):
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError('disposable process stopped during startup')
        try:
            if request(port, '/healthz')[0] == 200:
                return
        except OSError:
            time.sleep(.05)
    raise AssertionError('disposable process did not become ready')


def stop(process):
    if process is None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise AssertionError('disposable process did not stop on SIGTERM')


@unittest.skipUnless(PANEL and Path(PANEL).is_file(), 'set XCLI_PANEL_SERVICE to the experimental executable')
class PanelHttpIntegration(unittest.TestCase):
    def test_automatic_backup_runs_once_and_does_not_repeat_after_restart(self):
        with tempfile.TemporaryDirectory(prefix='xcli-panel-backup-') as folder:
            root = Path(folder)
            key_file = root / 'security.key'
            key_file.write_bytes(bytes(range(32)))
            key_file.chmod(0o600)
            db_file = root / 'gateway.sqlite'
            db = sqlite3.connect(db_file)
            try:
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
                    INSERT INTO admin VALUES(1,'fixture-hash');INSERT INTO mfa VALUES(1,0,'',-1);
                ''')
                db.commit()
            finally:
                db.close()
            settings = root / 'settings.json'
            settings.write_text(json.dumps({'origin':'https://testserver','domain':'testserver',
                'public_ip':'203.0.113.2','reality_sni':'example.com','reality_public':'p'*43,
                'short_id':'aabbccdd','ws_path':'/connect/test'}))
            port = free_port()
            args = [PANEL, '--experimental', '--db', str(db_file), '--secret-key', str(key_file),
                    '--origin', 'https://testserver', '--settings', str(settings), '--port', str(port),
                    '--automatic-backups', 'true', '--backup-interval', '60', '--backup-retention', '2']
            if STRICT_SETTINGS:
                args.extend(['--experimental-strict-settings', 'true'])
            process = None
            try:
                process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                wait_ready(process, port)
                for _ in range(100):
                    with closing(sqlite3.connect(db_file)) as db:
                        count = db.execute("SELECT COUNT(*) FROM events WHERE action='backup_created'").fetchone()[0]
                    if count:
                        break
                    time.sleep(.05)
                self.assertEqual(count, 1)
                backups = list((root / 'backups').glob('*.xgb'))
                self.assertEqual(len(backups), 1)
                self.assertTrue(backups[0].read_bytes().startswith(b'XGB1'))
                stop(process)
                process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                wait_ready(process, port)
                time.sleep(.5)
                with closing(sqlite3.connect(db_file)) as db:
                    count = db.execute("SELECT COUNT(*) FROM events WHERE action='backup_created'").fetchone()[0]
                self.assertEqual(count, 1)
            finally:
                stop(process)

    def test_authentication_through_local_http_chain(self):
        with tempfile.TemporaryDirectory(prefix='xcli-panel-http-') as folder:
            root = Path(folder)
            key_file = root / 'security.key'
            key_file.write_bytes(bytes(range(32)))
            key_file.chmod(0o600)
            db_file = root / 'gateway.sqlite'
            password = 'fixture-password'
            encoded = ('000102030405060708090a0b0c0d0e0f:'
                       'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf')
            db = sqlite3.connect(db_file)
            db.executescript('''
                CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL);
                CREATE TABLE sessions(hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
                CREATE TABLE mfa(id INTEGER PRIMARY KEY,enabled INTEGER NOT NULL,secret TEXT NOT NULL,last_step INTEGER NOT NULL);
                CREATE TABLE mfa_sessions(hash TEXT PRIMARY KEY);
                CREATE TABLE recovery_codes(hash TEXT PRIMARY KEY,used INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
                CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE traffic_history(ts INTEGER PRIMARY KEY,upload INTEGER NOT NULL,download INTEGER NOT NULL);
                CREATE TABLE samples(ts INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL);
                CREATE TABLE device_activity(user_id TEXT NOT NULL,transport TEXT NOT NULL,last_seen INTEGER NOT NULL DEFAULT 0,
                    sampled INTEGER NOT NULL DEFAULT 0,upload_delta INTEGER NOT NULL DEFAULT 0,download_delta INTEGER NOT NULL DEFAULT 0,
                    interval_seconds INTEGER NOT NULL DEFAULT 5,PRIMARY KEY(user_id,transport));
                CREATE TABLE users(id TEXT PRIMARY KEY,name TEXT NOT NULL,uuid TEXT NOT NULL UNIQUE,
                    token TEXT NOT NULL UNIQUE,enabled INTEGER NOT NULL DEFAULT 1,quota INTEGER NOT NULL DEFAULT 0,
                    expires INTEGER NOT NULL DEFAULT 0,upload INTEGER NOT NULL DEFAULT 0,download INTEGER NOT NULL DEFAULT 0,
                    created INTEGER NOT NULL,deleted INTEGER NOT NULL DEFAULT 0);
            ''')
            db.execute('INSERT INTO admin VALUES(1,?)', (encoded,))
            db.execute("INSERT INTO mfa VALUES(1,0,'',-1)")
            db.commit()
            db.close()
            settings_file = root / 'settings.json'
            settings_file.write_text(json.dumps({'origin':'https://testserver', 'domain':'testserver',
                'public_ip':'203.0.113.2', 'reality_sni':'www.bing.com', 'reality_public':'Y'*43,
                'short_id':'0123456789abcdef', 'ws_path':'/connect/test', 'hysteria2_port':443}))
            port = free_port()
            panel_args = [PANEL, '--experimental', '--db', str(db_file), '--secret-key', str(key_file),
                '--origin', 'https://testserver:443/', '--settings', str(settings_file), '--port', str(port)]
            if DISK_PROBE:
                panel_args.extend(['--experimental-disk-probe', DISK_PROBE])
            if STRICT_SETTINGS:
                panel_args.extend(['--experimental-strict-settings', 'true'])
            panel = subprocess.Popen(panel_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            gateway = None
            try:
                wait_ready(panel, port)
                duplicate = subprocess.run([PANEL, '--experimental', '--db', str(db_file), '--secret-key', str(key_file),
                    '--origin', 'https://testserver', '--port', str(free_port())], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=10)
                self.assertNotEqual(duplicate.returncode, 0, 'two panels acquired the same state lock')
                if WEB:
                    self.assertTrue(Path(WEB).is_file(), 'XCLI_WEB_GATEWAY does not exist')
                    web_port = free_port()
                    env = dict(os.environ, XCLI_CORE_PORT=str(port), XCLI_WEB_PORT=str(web_port))
                    gateway = subprocess.Popen(['node', WEB], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    wait_ready(gateway, web_port)
                    port = web_port
                self.assertEqual(request(port, '/api/session')[0], 401)
                self.assertEqual(request(port, '/api/users')[0], 401)
                login = json.dumps({'username': 'admin', 'password': password, 'code': ''}).encode()
                self.assertEqual(request(port, '/api/login', 'POST', login, origin='https://evil.example')[0], 403)
                self.assertEqual(request(port, '/api/login', 'POST', b'{')[0], 422)
                self.assertEqual(request(port, '/api/login', 'POST', b' ' * (16 * 1024 + 1))[0], 413)
                bad = json.dumps({'username': 'admin', 'password': 'wrong', 'code': ''}).encode()
                self.assertEqual(request(port, '/api/login', 'POST', bad)[0], 401)
                status, headers, data = request(port, '/api/login', 'POST', login, extra={'X-Forwarded-For': '203.0.113.9'})
                self.assertEqual(status, 200)
                self.assertEqual(headers['cache-control'], 'no-store')
                self.assertEqual(headers['x-frame-options'], 'DENY')
                self.assertIn('HttpOnly', headers['set-cookie'])
                self.assertIn('Secure', headers['set-cookie'])
                cookie = headers['set-cookie'].split(';', 1)[0]
                csrf = json.loads(data)['csrf']
                status, _, data = request(port, '/api/session', cookie=cookie)
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(data)['csrf'], csrf)
                self.assertEqual(request(port, '/api/host')[0], 401)
                host = None
                for _ in range(100):
                    status, _, data = request(port, '/api/host', cookie=cookie)
                    self.assertEqual(status, 200)
                    host = json.loads(data)
                    if (not host['stale'] and host['host'] is not None and
                            (not DISK_PROBE or host['host']['disk'] is not None)):
                        break
                    time.sleep(.05)
                self.assertEqual(host['scope'], 'server')
                self.assertFalse(host['stale'])
                self.assertGreater(host['sampled'], 0)
                self.assertGreater(host['host']['memory']['total'], 0)
                if DISK_PROBE:
                    self.assertGreater(host['host']['disk']['total'], 0)
                    self.assertEqual(host['host']['disk']['path'], str(root.resolve()))
                else:
                    self.assertIsNone(host['host']['disk'])
                self.assertEqual(request(port, '/api/activity')[0], 401)
                self.assertEqual(json.loads(request(port, '/api/activity', cookie=cookie)[2]), {'scope':'local','activity':{}})
                self.assertEqual(request(port, '/api/events')[0], 401)
                status, _, data = request(port, '/api/events', cookie=cookie)
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(data)['events'][0]['action'], 'login')
                self.assertEqual(request(port,'/api/rule-templates')[0],401)
                status,_,data=request(port,'/api/rule-templates',cookie=cookie)
                self.assertEqual(status,200)
                catalog=json.loads(data)
                self.assertEqual([item['id'] for item in catalog['templates']],['standard','independent'])
                visible=[item['value'] for item in catalog['group_order_catalog']['independent']]
                self.assertTrue({'PROXY','直连','故障转移','自动选择','独立 · Google'}.issubset(visible))
                rule_spec={'base':'independent','ai_outbound':'proxy','rules':'DOMAIN-SUFFIX,google.com,独立 · Google',
                    'groups':[{'name':'工作','default':'故障转移'}],
                    'group_order':['自动选择','故障转移','直连','PROXY','独立 · Google','工作']}
                rule_body=json.dumps({'name':'  fixture  ','spec':rule_spec},ensure_ascii=False).encode()
                self.assertEqual(request(port,'/api/rule-templates/validate','POST',rule_body)[0],401)
                self.assertEqual(request(port,'/api/rule-templates/validate','POST',rule_body,cookie,'wrong')[0],403)
                self.assertEqual(request(port,'/api/rule-templates/validate','POST',rule_body,cookie,csrf,origin='https://evil.example')[0],403)
                status,_,data=request(port,'/api/rule-templates/validate','POST',rule_body,cookie,csrf)
                self.assertEqual(status,200);self.assertEqual(json.loads(data),{'name':'fixture','spec':rule_spec})
                self.assertEqual(request(port,'/api/rule-templates','POST',rule_body)[0],401)
                self.assertEqual(request(port,'/api/rule-templates','POST',rule_body,cookie,'wrong')[0],403)
                status,_,data=request(port,'/api/rule-templates','POST',rule_body,cookie,csrf)
                self.assertEqual(status,200);template_id=json.loads(data)['id']
                update=json.dumps({'name':'updated draft','spec':rule_spec,'expected_revision':1},ensure_ascii=False).encode()
                self.assertEqual(request(port,'/api/rule-templates/'+template_id,'PUT',update,cookie,csrf)[0],200)
                self.assertEqual(request(port,'/api/rule-templates/'+template_id,'PUT',update,cookie,csrf)[0],409)
                catalog=json.loads(request(port,'/api/rule-templates',cookie=cookie)[2])
                draft=next(item for item in catalog['templates'] if item['id']==template_id)
                self.assertEqual(draft['revision'],2);self.assertIsNone(draft['published_spec'])
                user = json.dumps({'name':'fixture', 'quota':1000}).encode()
                self.assertEqual(request(port, '/api/users', 'POST', user)[0], 401)
                self.assertEqual(request(port, '/api/users', 'POST', user, cookie, 'wrong')[0], 403)
                self.assertEqual(request(port, '/api/users', 'POST', user, cookie, csrf, origin='https://evil.example')[0], 403)
                status, _, data = request(port, '/api/users', 'POST', user, cookie, csrf)
                self.assertEqual(status, 200)
                user_id = json.loads(data)['id']
                reset_path = '/api/users/' + user_id + '/reset-traffic'
                self.assertEqual(request(port, reset_path, 'POST', b'{}')[0], 401)
                self.assertEqual(request(port, reset_path, 'POST', b'{}', cookie, 'wrong')[0], 403)
                self.assertEqual(request(port, reset_path, 'POST', b'{}', cookie, csrf, origin='https://evil.example')[0], 403)
                self.assertEqual(request(port, reset_path, 'POST', b'{}', cookie, csrf)[0], 503)
                assignment=json.dumps({'template_id':template_id}).encode()
                self.assertEqual(request(port,'/api/users/'+user_id+'/rule-template','POST',assignment,cookie,csrf)[0],409)
                published=json.dumps({'expected_revision':2}).encode()
                self.assertEqual(request(port,'/api/rule-templates/'+template_id+'/publish','POST',published,cookie,csrf)[0],200)
                self.assertEqual(request(port,'/api/users/'+user_id+'/rule-template','POST',assignment,cookie,csrf)[0],200)
                status, _, data = request(port, '/api/users', cookie=cookie)
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(data)['users'][0]['id'], user_id)
                self.assertEqual(json.loads(data)['users'][0]['quota'], '1000')
                self.assertNotIn('uuid', json.loads(data)['users'][0])
                self.assertNotIn('token', json.loads(data)['users'][0])
                self.assertEqual(request(port,'/api/backups')[0],401)
                self.assertEqual(request(port,'/api/backups','POST',b'{}',cookie,'wrong')[0],403)
                status,_,data=request(port,'/api/backups','POST',b'{}',cookie,csrf)
                self.assertEqual(status,200);backup_id=json.loads(data)['id']
                status,_,data=request(port,'/api/backups/'+backup_id+'/inspect',cookie=cookie)
                self.assertEqual(status,200);self.assertTrue(json.loads(data)['same_server'])
                status,headers,data=request(port,'/api/backups/'+backup_id+'/download',cookie=cookie)
                self.assertEqual(status,200);self.assertEqual(headers['content-type'],'application/octet-stream');self.assertTrue(data.startswith(b'XGB1'))
                status,_,data=request(port,'/api/backups',cookie=cookie)
                self.assertEqual(status,200);self.assertFalse(json.loads(data)['automatic']);self.assertTrue(json.loads(data)['retention_enforced'])
                self.assertEqual(request(port, '/api/users/'+user_id+'/links')[0], 401)
                status, _, data = request(port, '/api/users/'+user_id+'/links', cookie=cookie)
                self.assertEqual(status, 200)
                links = json.loads(data)
                token = links['subscription'].rsplit('/', 1)[1]
                self.assertEqual(request(port,'/api/users/'+user_id+'/shadowrocket')[0],401)
                status,_,data=request(port,'/api/users/'+user_id+'/shadowrocket',cookie=cookie)
                self.assertEqual(status,200);clash_link=json.loads(data)['clash'];self.assertTrue(clash_link.endswith('/clash.yaml'))
                self.assertEqual(request(port,'/api/users/'+user_id+'/qr/clash')[0],401)
                status,qr_headers,qr=request(port,'/api/users/'+user_id+'/qr/clash',cookie=cookie)
                self.assertEqual(status,200);self.assertEqual(qr_headers['content-type'],'image/png');self.assertTrue(qr.startswith(b'\x89PNG\r\n\x1a\n'))
                if os.environ.get('XCLI_REQUIRE_QR_DECODER'):
                    from test_panel_security_compat import decode_qr
                    qr_file=root/'synthetic-clash.png';qr_file.write_bytes(qr)
                    self.assertEqual(decode_qr(qr_file),clash_link)
                status,dns_headers,dns=request(port,'/shadowrocket-dns.sgmodule')
                self.assertEqual(status,200);self.assertIn(b'testserver = 203.0.113.2',dns)
                status, sub_headers, data = request(port, '/s/'+token)
                self.assertEqual(status, 200)
                self.assertEqual(sub_headers['cache-control'], 'no-store')
                self.assertEqual(sub_headers['profile-update-interval'], '6')
                self.assertIn('total=1000', sub_headers['subscription-userinfo'])
                self.assertIn(links['reality'], base64.b64decode(data).decode())
                self.assertEqual(request(port, '/s/invalid')[0], 404)
                status,clash_headers,clash=request(port,'/s/'+token+'/clash.yaml')
                self.assertEqual(status,200);self.assertEqual(clash_headers['content-type'],'application/yaml; charset=utf-8')
                self.assertEqual(clash_headers['subscription-userinfo'],sub_headers['subscription-userinfo'])
                self.assertIn(b'oracle-cloud',clash);self.assertIn(b'"PROXY"',clash)
                self.assertIn('独立 · Google'.encode(),clash)
                status,_,data=request(port,'/s/'+token+'/shadowrocket.json')
                self.assertEqual(status,200);self.assertTrue(json.loads(data)['service_routing'])
                status,_,data=request(port,'/s/'+token+'/shadowrocket.conf')
                self.assertEqual(status,200);self.assertIn('XCLI-独立 · Google'.encode(),data)
                shadow=data.decode()
                positions=[shadow.index('XCLI-'+name+' = ') for name in ['自动选择','故障转移','直连','PROXY','独立 · Google','工作']]
                self.assertEqual(positions,sorted(positions))
                large = json.dumps({'name':'fixture', 'quota':10_000_000_000_000_000}).encode()
                self.assertEqual(request(port, '/api/users/'+user_id, 'PUT', large, cookie, csrf)[0], 200)
                self.assertEqual(json.loads(request(port, '/api/users', cookie=cookie)[2])['users'][0]['quota'], '10000000000000000')
                db = sqlite3.connect(db_file)
                try: before = db.execute('SELECT uuid,token FROM users WHERE id=?', (user_id,)).fetchone()
                finally: db.close()
                updated = json.dumps({'name':'updated', 'enabled':False, 'quota':500}).encode()
                self.assertEqual(request(port, '/api/users/'+user_id, 'PUT', updated, cookie, csrf)[0], 200)
                self.assertEqual(request(port, '/s/'+token)[0], 403)
                self.assertEqual(request(port, '/s/'+token+'/clash.yaml')[0], 403)
                self.assertEqual(request(port, '/s/'+token+'/shadowrocket.json')[0], 403)
                self.assertEqual(request(port, '/api/users/'+user_id+'/rotate', 'POST', b'{}', cookie, csrf)[0], 200)
                self.assertEqual(request(port, '/s/'+token)[0], 404)
                self.assertEqual(request(port, '/s/'+token+'/clash.yaml')[0], 404)
                self.assertEqual(request(port, '/s/'+token+'/shadowrocket.json')[0], 404)
                db = sqlite3.connect(db_file)
                try:
                    after = db.execute('SELECT uuid,token,name,enabled,quota FROM users WHERE id=?', (user_id,)).fetchone()
                    self.assertNotEqual(before[0], after[0]); self.assertNotEqual(before[1], after[1])
                    self.assertEqual(after[2:], ('updated', 0, 500))
                finally: db.close()
                node_id='a'*32;node_key='Z'*43
                registration={'version':1,'id':node_id,'key':node_key,'public_ip':'8.8.8.8','domain':'node.example.com',
                    'public_port':443,'reality_sni':'www.bing.com','reality_public':'Y'*43,'short_id':'0123456789abcdef',
                    'ws_path':'/connect/'+'b'*24,'hysteria2_port':443}
                node_body=json.dumps({'name':'fixture','registration':registration,'users':[user_id]}).encode()
                self.assertEqual(request(port,'/api/remote-nodes')[0],401)
                self.assertEqual(request(port,'/api/remote-nodes','POST',node_body,cookie,'bad')[0],403)
                status,_,data=request(port,'/api/remote-nodes','POST',node_body,cookie,csrf)
                self.assertEqual(status,201);self.assertNotIn(node_key,data.decode())
                status,_,data=request(port,'/api/remote-nodes',cookie=cookie)
                self.assertEqual(status,200);self.assertEqual(json.loads(data)['nodes'][0]['id'],node_id)
                self.assertNotIn(node_key,data.decode())
                update_node=json.dumps({'name':'new node','users':[user_id],'enabled':True}).encode()
                self.assertEqual(request(port,'/api/remote-nodes/'+node_id,'PUT',update_node,cookie,csrf)[0],200)
                report=json.dumps({'revision':'','counters':[{'id':user_id,'upload':10,'download':20}]}).encode()
                node_auth={'Authorization':f'Xcli-Node {node_id}.{node_key}'}
                self.assertEqual(request(port,'/api/nodes/sync','POST',report,extra={'Authorization':'bad'})[0],401)
                status,_,data=request(port,'/api/nodes/sync','POST',report,origin='https://unrelated.example',extra=node_auth)
                self.assertEqual(status,200);self.assertEqual(json.loads(data)['ack'][0]['upload'],10)
                self.assertEqual(request(port,'/api/nodes/sync','POST',report,extra=node_auth)[0],200)
                db=sqlite3.connect(db_file)
                try:self.assertEqual(db.execute('SELECT upload,download FROM users WHERE id=?',(user_id,)).fetchone(),(10,20))
                finally:db.close()
                self.assertEqual(request(port, '/api/users/'+user_id, 'DELETE', None, cookie, csrf)[0], 200)
                self.assertEqual(request(port, '/api/users/'+user_id+'/links', cookie=cookie)[0], 404)
                self.assertEqual(json.loads(request(port, '/api/users', cookie=cookie)[2])['users'], [])
                self.assertEqual(request(port, '/api/users/'+user_id+'/rotate', 'POST', b'{}', cookie, csrf)[0], 404)
                change = json.dumps({'current_password':password, 'new_password':'new-fixture-password', 'code':''}).encode()
                self.assertEqual(request(port, '/api/password', 'POST', change)[0], 401)
                self.assertEqual(request(port, '/api/password', 'POST', change, cookie, 'wrong')[0], 403)
                self.assertEqual(request(port, '/api/password', 'POST', change, cookie, csrf, origin='https://evil.example')[0], 403)
                incorrect = json.dumps({'current_password':'wrong', 'new_password':'new-fixture-password'}).encode()
                self.assertEqual(request(port, '/api/password', 'POST', incorrect, cookie, csrf)[0], 403)
                status, headers, _ = request(port, '/api/password', 'POST', change, cookie, csrf)
                self.assertEqual(status, 200);self.assertIn('Max-Age=0', headers['set-cookie'])
                self.assertEqual(request(port, '/api/session', cookie=cookie)[0], 401)
                login = json.dumps({'username':'admin','password':'new-fixture-password','code':''}).encode()
                status, headers, data = request(port, '/api/login', 'POST', login, extra={'X-Forwarded-For': '203.0.113.9'})
                self.assertEqual(status, 200);cookie=headers['set-cookie'].split(';',1)[0];csrf=json.loads(data)['csrf']
                self.assertEqual(request(port, '/api/logout', 'POST', b'{}', cookie, 'wrong')[0], 403)
                status, headers, _ = request(port, '/api/logout', 'POST', b'{}', cookie, csrf)
                self.assertEqual(status, 200)
                self.assertIn('Max-Age=0', headers['set-cookie'])
                self.assertEqual(request(port, '/api/session', cookie=cookie)[0], 401)
                db = sqlite3.connect(db_file)
                try:
                    self.assertEqual(db.execute("SELECT detail FROM events WHERE action='login'").fetchone()[0], '203.0.113.9')
                    self.assertEqual(db.execute('SELECT count(*) FROM sessions').fetchone()[0], 0)
                finally:
                    db.close()
            finally:
                stop(gateway)
                stop(panel)
