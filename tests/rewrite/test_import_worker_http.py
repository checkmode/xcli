"""Real processes and privilege boundary inside a disposable protected fixture."""
from contextlib import closing
import http.server
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import threading
import time
import unittest

from test_panel_http_integration import PANEL, WEB, free_port, request, stop, wait_ready


UID = int(os.environ.get('XCLI_TEST_REPORT_UID', '0'))
GID = int(os.environ.get('XCLI_TEST_REPORT_GID', '0'))
WORKER = os.environ.get('XCLI_IMPORT_RUNNER', '')
APPLY = os.environ.get('XCLI_TEST_IMPORT_APPLY', '') == '1'
SERVICE = os.environ.get('XCLI_IMPORT_SERVICE', '')


@unittest.skipUnless(os.geteuid() == 0 and UID and GID and PANEL and Path(PANEL).is_file()
                     and WORKER and Path(WORKER).is_file(), 'requires root and isolated fixture binaries')
class ImportWorkerHttp(unittest.TestCase):
    def test_preview_flows_from_authenticated_http_to_dropped_privilege_worker(self):
        with tempfile.TemporaryDirectory(prefix='xcli-import-fixture-', dir='/var/lib') as folder:
            root = Path(folder)
            root.chmod(0o755)
            for name, mode in [('bin', 0o755), ('config', 0o755), ('secret', 0o700),
                               ('state', 0o700), ('journal', 0o700), ('report', 0o750), ('panel', 0o700)]:
                (root / name).mkdir(mode=mode)
            os.chown(root / 'report', 0, GID)
            os.chown(root / 'panel', UID, GID)
            inbox = root / 'panel/inbox'
            inbox.mkdir(mode=0o700)
            os.chown(inbox, UID, GID)
            key = bytes(range(32))
            for path, owner in [(root / 'secret/security.key', 0), (root / 'panel/security.key', UID)]:
                path.write_bytes(key)
                path.chmod(0o600)
                os.chown(path, owner, GID if owner else 0)
            helper = root / 'bin/xcli-import-probe'
            helper.write_text(f'''#!/bin/sh
test "$(id -u)" = "{UID}" || exit 10
IFS= read -r data || exit 11
case "$data" in *synthetic-fail*) exit 12;; esac
printf '%s\\n' '{{"ok":true,"exit_ip":"8.8.8.8","country":"US","https_ms":1,"doh_ms":2}}'
''')
            helper.chmod(0o755)
            configs = {
                'settings': {'origin': 'https://testserver', 'domain': 'testserver', 'public_ip': '8.8.8.8',
                             'ws_path': '/connect/fixture', 'residential_exits': []},
                'core': {'inbounds': [{'tag': 'reality', 'port': 10443}],
                         'outbounds': [{'tag': 'direct', 'protocol': 'freedom'},
                                       {'tag': 'blocked', 'protocol': 'blackhole'}],
                         'routing': {'rules': [{'inboundTag': ['reality'], 'outboundTag': 'direct'}]}},
                'monitor': {'residential_exits': []},
            }
            for name, value in configs.items():
                (root / 'config' / name).write_text(json.dumps(value))
            (root / 'config/nginx').write_text('server { location = /connect/fixture {} }')
            paths = [root / 'config' / name for name in ('settings', 'core', 'monitor', 'nginx', 'locations', 'pool')]
            before = {path.name: path.read_bytes() if path.exists() else None for path in paths}
            db_file = root / 'panel/gateway.sqlite'
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
                ''')
                db.commit()
            os.chown(db_file, UID, GID)
            readiness = readiness_thread = monitor_thread = None
            stop_monitor = threading.Event()
            if SERVICE:
                self.assertNotEqual(os.readlink('/proc/self/ns/mnt'), os.readlink('/proc/1/ns/mnt'))
                self.assertNotEqual(os.readlink('/proc/self/ns/net'), os.readlink('/proc/1/ns/net'))
                probe = Path('/usr/local/lib/xcli/xcli-import-probe')
                probe.write_bytes(helper.read_bytes()); probe.chmod(0o755)
                class Ready(http.server.BaseHTTPRequestHandler):
                    protocol_version = 'HTTP/1.1'
                    def log_message(self, *_): pass
                    def do_GET(self):
                        self.send_response(200 if self.path == '/internal/ready' else 404)
                        self.send_header('Content-Length','0'); self.send_header('Connection','close'); self.end_headers()
                readiness = http.server.ThreadingHTTPServer(('127.0.0.1',0), Ready)
                readiness_thread = threading.Thread(target=readiness.serve_forever, daemon=True);readiness_thread.start()
                monitor = root/'monitor'; monitor.mkdir(mode=0o700)
                def publish_monitor():
                    while not stop_monitor.is_set():
                        current = json.loads((root/'config/settings').read_text())
                        tags = ['reality','websocket'] + [v['tag'] for v in current.get('residential_exits',[])]
                        now = int(time.time())
                        checks = [{'transport':tag,'status':'healthy','https_ms':5,'udp_ms':5,'doh_ms':5,
                                   'last_success':now,'error':''} for tag in tags]
                        temporary = monitor/'tmp';temporary.write_text(json.dumps({'schema':1,'scope':'server',
                            'status':'healthy','updated':now+1,'checks':checks}));temporary.chmod(0o640)
                        temporary.replace(monitor/'report.json')
                        stop_monitor.wait(.25)
                monitor_thread = threading.Thread(target=publish_monitor,daemon=True);monitor_thread.start()
                service_config = root/'import-service.json'
                service_config.write_text(json.dumps({'mode':'apply','key':str(root/'secret/security.key'),
                    'inbox':str(inbox),'state':str(root/'state'),'journal':str(root/'journal'),
                    'update_lock':str(root/'journal/update.lock'),'report_directory':str(root/'report'),
                    'panel_uid':UID,'panel_gid':GID,'probe_uid':UID,'probe_gid':GID,
                    'targets':{name:str(root/'config'/name) for name in ('settings','core','monitor','nginx','locations','pool')},
                    'database':str(db_file),'core_pid_file':str(root/'pid'),'core_api':'127.0.0.1:10085',
                    'panel_port':readiness.server_port,'monitor_report':str(monitor/'report.json'),
                    'core_unit':'xcli-core.service','panel_unit':'xcli-panel.service','monitor_unit':'xcli-monitor.service'}))
                service_config.chmod(0o600)
                worker_args = [SERVICE, '--experimental', '--config', str(service_config)]
            else:
                worker_args = [WORKER, '--isolated-apply' if APPLY else '--isolated-fixture',
                               str(root), str(GID), str(UID), str(GID)]
            worker = subprocess.Popen(worker_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            panel = gateway = None
            report_file = root / 'report/report.json'

            def wait_for(predicate):
                deadline = time.monotonic() + 15
                last = None
                while time.monotonic() < deadline:
                    try:
                        value = json.loads(report_file.read_text())
                        last = (value.get('status'), value.get('reason'))
                        if predicate(value):
                            return value
                    except (OSError, json.JSONDecodeError):
                        pass
                    if worker.poll() is not None:
                        self.fail('isolated worker stopped unexpectedly')
                    time.sleep(.05)
                self.fail(f'isolated worker status did not reach the expected state: {last}')

            try:
                wait_for(lambda value: value['status'] == 'idle')
                duplicate = subprocess.run(worker_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
                self.assertNotEqual(duplicate.returncode, 0)
                port = free_port()
                panel_args = [PANEL, '--experimental', '--db', str(db_file),
                    '--secret-key', str(root / 'panel/security.key'), '--settings', str(root / 'config/settings'),
                    '--origin', 'https://testserver', '--port', str(port),
                    '--experimental-import-report-dir', str(root / 'report'), '--experimental-import-report-gid', str(GID),
                    '--experimental-import-inbox', str(inbox)]
                if APPLY:
                    panel_args.extend(['--experimental-import-apply', 'true'])
                panel = subprocess.Popen(panel_args, user=UID, group=GID, extra_groups=[],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                wait_ready(panel, port)
                if WEB:
                    gateway_port = free_port()
                    gateway = subprocess.Popen([os.environ.get('XCLI_TEST_NODE', 'node'), WEB], env=dict(os.environ, XCLI_CORE_PORT=str(port),
                        XCLI_WEB_PORT=str(gateway_port)), user=UID, group=GID, extra_groups=[],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    wait_ready(gateway, gateway_port)
                    port = gateway_port
                login = json.dumps({'username': 'admin', 'password': 'fixture-password', 'code': ''}).encode()
                status, headers, data = request(port, '/api/login', 'POST', login)
                self.assertEqual(status, 200)
                cookie = headers['set-cookie'].split(';', 1)[0]
                csrf = json.loads(data)['csrf']
                body = json.dumps({'action': 'preview', 'protocol': 'socks', 'label': 'fixture',
                                   'text': '1.1.1.1:80:fixture:synthetic-password'}).encode()
                status, _, data = request(port, '/api/proxy-import', 'POST', body, cookie, csrf)
                self.assertEqual(status, 202)
                request_id = json.loads(data)['id']
                ready = wait_for(lambda value: value['status'] == 'ready' and value['id'] == request_id)
                self.assertEqual(ready['rows'][0]['exit_ip'], '8.8.8.8')
                self.assertNotIn('synthetic-password', json.dumps(ready))
                status, _, data = request(port, '/api/proxy-import', cookie=cookie)
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(data)['rows'][0]['tag'], 'residential-27')
                self.assertEqual(json.loads(data)['apply_enabled'], APPLY)
                self.assertNotIn(b'synthetic-password', data)
                apply = json.dumps({'action': 'apply', 'preview_id': request_id}).encode()
                status, _, data = request(port, '/api/proxy-import', 'POST', apply, cookie, csrf)
                if APPLY:
                    self.assertEqual(status, 202)
                    apply_id = json.loads(data)['id']
                    wait_for(lambda value: value['status'] == 'complete' and value['id'] == apply_id)
                    updated = json.loads((root / 'config/settings').read_text())
                    self.assertEqual(updated['residential_exits'][0]['tag'], 'residential-27')
                    self.assertNotEqual(before['core'], (root / 'config/core').read_bytes())
                    self.assertTrue((root / 'config/pool').exists())
                    status, _, data = request(port, '/api/proxy-import', cookie=cookie)
                    catalog = json.loads(data)['items']
                    self.assertEqual(status, 200)
                    self.assertEqual(catalog[0]['tag'], 'residential-27')
                    self.assertTrue(catalog[0]['enabled'])
                    self.assertNotIn('synthetic-password', json.dumps(catalog))
                    for operation, enabled, deleted in [('disable', False, False), ('delete', False, True),
                                                        ('restore', False, False), ('enable', True, False)]:
                        manage = json.dumps({'action':'manage','operation':operation,'tag':'residential-27'}).encode()
                        status, _, data = request(port, '/api/proxy-import', 'POST', manage, cookie, csrf)
                        self.assertEqual(status, 202)
                        preview_id = json.loads(data)['id']
                        wait_for(lambda value: value['status'] == 'ready' and value['id'] == preview_id)
                        apply = json.dumps({'action':'apply','preview_id':preview_id}).encode()
                        status, _, data = request(port, '/api/proxy-import', 'POST', apply, cookie, csrf)
                        self.assertEqual(status, 202)
                        apply_id = json.loads(data)['id']
                        wait_for(lambda value: value['status'] == 'complete' and value['id'] == apply_id)
                        status, _, data = request(port, '/api/proxy-import', cookie=cookie)
                        row = json.loads(data)['items'][0]
                        self.assertEqual(row['enabled'], enabled)
                        self.assertEqual(bool(row['deleted_at']), deleted)
                        exits = json.loads((root / 'config/settings').read_text())['residential_exits']
                        self.assertEqual(bool(exits), enabled)
                    edit = {'action':'manage','operation':'edit','tag':'residential-27',
                            'changes':{'label':'更新后的住宅','address':'1.1.1.1','port':80,
                                       'protocol':'socks','username':'','password':''}}
                    status, _, data = request(port, '/api/proxy-import', 'POST', json.dumps(edit).encode(), cookie, csrf)
                    self.assertEqual(status, 202);preview_id = json.loads(data)['id']
                    wait_for(lambda value: value['status'] == 'ready' and value['id'] == preview_id)
                    status, _, data = request(port, '/api/proxy-import', 'POST',
                        json.dumps({'action':'apply','preview_id':preview_id}).encode(), cookie, csrf)
                    self.assertEqual(status, 202);apply_id = json.loads(data)['id']
                    wait_for(lambda value: value['status'] == 'complete' and value['id'] == apply_id)
                    catalog = json.loads(request(port, '/api/proxy-import', cookie=cookie)[2])['items']
                    self.assertEqual(catalog[0]['label'], '更新后的住宅')
                    saved = json.loads((root/'config/pool').read_text())['proxies'][0]
                    self.assertEqual(saved['username'], 'fixture');self.assertEqual(saved['password'], 'synthetic-password')
                    self.assertNotIn('synthetic-password', json.dumps(catalog))
                    return
                self.assertEqual(status, 409)
                stop(worker)
                self.assertEqual(json.loads(report_file.read_text())['status'], 'unavailable')
                worker = subprocess.Popen(worker_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                interrupted = wait_for(lambda value: value['status'] == 'failed' and value['id'] == request_id)
                self.assertEqual(interrupted['reason'], 'interrupted')
                self.assertNotIn('rows', interrupted)
                body = json.dumps({'action': 'preview', 'protocol': 'socks', 'label': 'fixture',
                                   'text': '1.1.1.1:80:fixture:synthetic-fail'}).encode()
                status, _, data = request(port, '/api/proxy-import', 'POST', body, cookie, csrf)
                self.assertEqual(status, 202)
                failed_id = json.loads(data)['id']
                failed = wait_for(lambda value: value['status'] == 'failed' and value['id'] == failed_id)
                self.assertEqual(failed['reason'], 'probe')
                self.assertNotIn('synthetic-fail', json.dumps(failed))
                after = {path.name: path.read_bytes() if path.exists() else None for path in paths}
                self.assertEqual(before, after)
            finally:
                for process in (gateway, panel, worker):
                    if process is not None and process.poll() is None:
                        stop(process)
                stop_monitor.set()
                if monitor_thread is not None: monitor_thread.join(timeout=5)
                if readiness is not None: readiness.shutdown(); readiness.server_close(); readiness_thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
