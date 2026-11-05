"""Run a fresh installer with real daemons and a simulated service manager.

The shell wrapper provides a disposable mount and network namespace. Package
downloads, firewall application and systemd are simulated; Xray, Nginx,
Rust services, Node and the generated configurations are real.
"""
import argparse
from contextlib import closing, suppress
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import unittest
import zipfile
from unittest.mock import patch

from test_panel_http_integration import request
from test_node_service_integration import socket_open

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = os.environ.get('XCLI_TEST_FIXTURE', '')
ROLE = os.environ.get('XCLI_TEST_ROLE', '')
RELEASE = os.environ.get('XCLI_TEST_RELEASE', '')
NODE = os.environ.get('XCLI_TEST_NODE', '')
REPLACE = os.environ.get('XCLI_TEST_REPLACE', '') == '1'


def wait_for(test, seconds=20):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        with suppress(OSError, ValueError, json.JSONDecodeError):
            if test():
                return True
        time.sleep(.1)
    return False


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Services:
    def __init__(self, fixture):
        self.fixture = fixture
        self.processes = {}
        self.enabled = set()

    def start(self, name):
        if name == 'xcli-firewall':
            self.enabled.add(name)
            return
        old = self.processes.get(name)
        if old and old.poll() is None:
            return
        if name == 'nginx':
            args = ['/usr/sbin/nginx', '-c', '/etc/nginx/nginx.conf', '-g', 'daemon off;']
            user = group = None
            groups = None
            env = None
        else:
            unit = Path('/etc/systemd/system') / (name + '.service')
            lines = unit.read_text().splitlines()
            values = dict(line.split('=', 1) for line in lines if line.startswith(('User=', 'Group=', 'EnvironmentFile=', 'ExecStart=')))
            env = dict(os.environ)
            for line in lines:
                if line.startswith('Environment='):
                    key, value = line.removeprefix('Environment=').split('=', 1)
                    env[key] = value
            if 'EnvironmentFile' in values:
                for line in Path(values['EnvironmentFile']).read_text().splitlines():
                    key, value = line.split('=', 1)
                    env[key] = value
            args = shlex.split(values['ExecStart'])
            args = [env.get(item[2:-1], item) if item.startswith('${') and item.endswith('}') else item for item in args]
            if 'User' in values:
                user = pwd.getpwnam(values['User']).pw_uid
                import grp
                group = grp.getgrnam(values['Group']).gr_gid
                groups = [grp.getgrnam('xgmonitor').gr_gid] if name == 'xcli-panel' else []
            else:
                user = group = None
                groups = None
        with (self.fixture / (name + '.log')).open('ab') as log:
            child = subprocess.Popen(args, user=user, group=group, extra_groups=groups,
                                     env=env, stdout=log, stderr=log)
        self.processes[name] = child
        (self.fixture / (name + '.pid')).write_text(str(child.pid))
        if name == 'xcli-core':
            Path('/sys/fs/cgroup/system.slice/xcli-core.service/cgroup.procs').write_text(str(child.pid) + '\n')
        time.sleep(.15)
        if child.poll() is not None:
            raise RuntimeError(f'{name} exited during startup; see fixture log')

    def systemctl(self, args):
        if args[0] == 'daemon-reload':
            return 0
        if args[0] == 'stop':
            for name in args[1:]:
                self.stop(name)
            return 0
        if args[0] == 'start':
            for name in args[1:]:
                self.start(name)
            return 0
        if args[:2] == ['disable', '--now']:
            for name in args[2:]:
                self.enabled.discard(name)
                self.stop(name)
            return 0
        if args[:2] == ['enable', '--now']:
            for name in args[2:]:
                if name == 'certbot.timer':
                    self.enabled.add(name)
                    continue
                self.start(name)
            return 0
        if args[:2] == ['reload', 'nginx']:
            self.processes['nginx'].send_signal(signal.SIGHUP)
            return 0
        if args[:2] == ['is-active', '--quiet']:
            name = args[2]
            child = self.processes.get(name)
            return 0 if name in self.enabled or child is not None and child.poll() is None else 3
        raise RuntimeError('unexpected simulated systemctl action: ' + repr(args))

    def stop(self, name):
        child = self.processes.get(name)
        if child and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)

    def close(self):
        # Terminate the node before its Xray child, then stop the remaining services.
        for name in ('xcli-node', 'xcli-import', 'xcli-monitor', 'xcli-webshare', 'xcli-web', 'xcli-panel', 'xcli-core', 'nginx'):
            child = self.processes.get(name)
            if child and child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)


@unittest.skipUnless(FIXTURE and ROLE in ('panel', 'node') and RELEASE and NODE,
                     'run through run_fresh_install_namespace.sh')
class FreshInstall(unittest.TestCase):
    def test_install_and_start(self):
        self.assertEqual(os.geteuid(), 0)
        self.assertNotEqual(os.readlink('/proc/self/ns/net'), os.readlink('/proc/1/ns/net'))
        fixture = Path(FIXTURE)
        sys.path.insert(0, str(ROOT / 'rewrite/deploy'))
        spec = importlib.util.spec_from_file_location('rewrite_installer', ROOT / 'rewrite/deploy/install-experimental.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if REPLACE:
            replace_spec = importlib.util.spec_from_file_location('rewrite_replacement', ROOT / 'rewrite/deploy/reinstall-legacy.py')
            replacement = importlib.util.module_from_spec(replace_spec)
            replace_spec.loader.exec_module(replacement)
            for command in (['groupadd','--system','xgateway'], ['useradd','--system','--no-create-home',
                '--home-dir','/nonexistent','--shell','/usr/sbin/nologin','--gid','xgateway','xgateway'],
                ['groupadd','--system','xgmonitor'], ['useradd','--system','--no-create-home',
                '--home-dir','/nonexistent','--shell','/usr/sbin/nologin','--gid','xgmonitor','xgprobe']):
                subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            Path('/usr/local/lib/xray-gateway').mkdir(parents=True)
            shutil.copyfile(fixture / 'xray', '/usr/local/lib/xray-gateway/xray')
            Path('/usr/local/lib/xray-gateway/xray').chmod(0o755)
            Path('/etc/xcli-monitor').mkdir()
            Path('/etc/xcli-monitor/monitor.json').write_text('old monitor config')
            for name in ('xcli-import-locations.conf','xcli-webshare-locations.conf'):
                Path('/etc/nginx', name).write_text('old locations')
            Path('/etc/systemd/system/nginx.service.d').mkdir()
            Path('/etc/systemd/system/nginx.service.d/90-xcli.conf').write_text('old dropin')
            Path('/opt/xcli/releases/old').mkdir(parents=True)
            Path('/opt/xcli/current').symlink_to('/opt/xcli/releases/old')
        domain = 'panel.example.com' if ROLE == 'panel' else 'node.example.com'
        cert, key = fixture / 'cert.pem', fixture / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                        '-subj', '/CN=' + domain, '-addext', 'subjectAltName=DNS:' + domain,
                        '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', str(key), '-out', str(cert)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        live = Path('/etc/letsencrypt/live') / domain
        archive_dir = Path('/etc/letsencrypt/archive') / domain
        live.mkdir(parents=True); archive_dir.mkdir(parents=True)
        shutil.copyfile(cert, archive_dir / 'fullchain1.pem')
        shutil.copyfile(key, archive_dir / 'privkey1.pem')
        (archive_dir / 'privkey1.pem').chmod(0o600)
        (live / 'fullchain.pem').symlink_to(archive_dir / 'fullchain1.pem')
        (live / 'privkey.pem').symlink_to(archive_dir / 'privkey1.pem')
        archive = fixture / 'xray.zip'
        with zipfile.ZipFile(archive, 'w') as zipped:
            zipped.write(fixture / 'xray', 'xray')
        module.XRAY_ASSETS = {'x86_64': ('fixture.zip', hashlib.sha256(archive.read_bytes()).hexdigest())}
        services = Services(fixture)

        def update_existing(info, release=None, revision='b' * 40):
            spec = importlib.util.spec_from_file_location('rewrite_updater', ROOT / 'rewrite/deploy/upgrade-rust.py')
            updater = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(updater)

            def fake_run(*command, check=True, timeout=120):
                if command[0] != 'systemctl':
                    return subprocess.run(command, check=check, timeout=timeout, capture_output=True, text=True)
                if command[1] == 'show':
                    if 'KillMode' in command:
                        value = 'mixed\n'
                    else:
                        child = services.processes.get('xcli-node')
                        value = 'success\n' if child is not None and child.returncode == 0 else 'exit-code\n'
                    return subprocess.CompletedProcess(command, 0, value, '')
                code = services.systemctl(list(command[1:]))
                if check and code:
                    raise subprocess.CalledProcessError(code, command)
                return subprocess.CompletedProcess(command, code, '', '')

            def running(name):
                child = services.processes.get(name)
                return child is not None and child.poll() is None

            with patch.object(updater, 'run', side_effect=fake_run), patch.object(updater, 'active', side_effect=running):
                updater.apply(info, release or Path(RELEASE), Path(NODE), revision)

        def broken_release(component):
            destination = fixture / ('broken-' + component)
            shutil.copytree(RELEASE, destination)
            if component == 'node':
                binary = destination / 'bin/xcli-node-service'
                binary.write_text('#!/bin/sh\nexit 23\n')
                binary.chmod(0o755)
            else:
                (destination / 'web/gateway/main.js').write_text('process.exit(23)\n')
            return destination

        def check_wrapper(role):
            checkout = fixture / 'wrapper-checkout'
            (checkout / 'rewrite/deploy').mkdir(parents=True)
            (checkout / 'rewrite/rust').mkdir()
            shutil.copyfile(ROOT / 'upgrade.sh', checkout / 'upgrade.sh')
            shutil.copyfile(ROOT / 'rewrite/deploy/upgrade-rust.py', checkout / 'rewrite/deploy/upgrade-rust.py')
            runtime = checkout / 'rewrite/rust/fixture.txt'
            runtime.write_text('first\n')
            subprocess.run(['git', 'init', '-q', str(checkout)], check=True, capture_output=True)
            subprocess.run(['git', '-C', str(checkout), 'add', '.'], check=True, capture_output=True)
            subprocess.run(['git', '-C', str(checkout), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                            'commit', '-qm', 'first'], check=True, capture_output=True)
            first = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
            marker = Path('/opt/xcli/current/COMMIT') if role == 'panel' else Path('/etc/xcli-node/revision')
            marker.write_text(first + '\n')
            runtime.write_text('second\n')
            subprocess.run(['git', '-C', str(checkout), 'add', '.'], check=True, capture_output=True)
            subprocess.run(['git', '-C', str(checkout), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                            'commit', '-qm', 'second'], check=True, capture_output=True)
            second = subprocess.check_output(['git', '-C', str(checkout), 'rev-parse', 'HEAD'], text=True).strip()
            commands = fixture / 'wrapper-bin'
            commands.mkdir()
            systemctl = commands / 'systemctl'
            systemctl.write_text('#!/bin/sh\ncase "$1" in\n  is-active) exit 0;;\n  cat) cat "/etc/systemd/system/$2";;\n  *) exit 1;;\nesac\n')
            systemctl.chmod(0o755)
            env = dict(os.environ, PATH=str(commands) + ':' + os.environ['PATH'])
            check = subprocess.run(['bash', str(checkout / 'upgrade.sh'), '--check'], env=env,
                                   capture_output=True, text=True, timeout=20)
            self.assertEqual(check.returncode, 0, check.stderr)
            self.assertIn('可以更新到当前 Git 提交', check.stdout)
            marker.write_text(second + '\n')
            same = subprocess.run(['bash', str(checkout / 'upgrade.sh')], env=env,
                                  capture_output=True, text=True, timeout=20)
            self.assertEqual(same.returncode, 0, same.stderr)
            self.assertIn('当前业务版本已经安装', same.stdout)

        base_installer = replacement.Replacement if REPLACE else module.Installer
        class FixtureInstaller(base_installer):
            def run(self, command, capture=False, timeout=1800, check=True):
                command = list(map(str, command))
                if command[0] == 'apt-get':
                    return b'' if capture else 0
                if command[0] == 'systemctl':
                    result = services.systemctl(command[1:])
                    if check and result:
                        raise RuntimeError('fixture service action failed')
                    return b'' if capture else result
                if command[0] == 'curl' and '-o' in command:
                    shutil.copyfile(archive, command[command.index('-o') + 1])
                    return b'' if capture else 0
                if command[0] == 'curl' and '--resolve' in command:
                    command[1:1] = ['--cacert', str(cert)]
                return super().run(command, capture=capture, timeout=timeout, check=check)

            def install_configuration(self, key_output):
                super().install_configuration(key_output)
                # Avoid starting one worker for every CPU on the shared test host.
                self.nginx_text = self.nginx_text.replace('worker_processes auto;', 'worker_processes 1;')

        args = argparse.Namespace(coexist=False, source=ROOT, commit='a' * 40, domain=domain,
                                  public_ip='8.8.8.8', reality_sni='www.bing.com', public_port=19443,
                                  panel='https://panel.example.com', certificate=live / 'fullchain.pem',
                                  private_key=live / 'privkey.pem',
                                  no_email=True, email=None, ipv6=True)
        installer = FixtureInstaller(args, 'x86_64', ['1.1.1.1'], ROLE, Path(RELEASE), Path(NODE))
        try:
            self.assertEqual(installer.execute(), 0)
            if not REPLACE:
                revision_path = Path('/opt/xcli/current/COMMIT' if ROLE == 'panel' else '/etc/xcli-node/revision')
                self.assertEqual(revision_path.read_text().strip(), 'a' * 40)
            if REPLACE:
                self.assertTrue((installer.backup / 'old-current').is_symlink())
                self.assertTrue((installer.backup / 'old-monitor-config/monitor.json').is_file())
                self.assertFalse(Path('/etc/systemd/system/nginx.service.d/90-xcli.conf').exists())
            hook = Path('/etc/letsencrypt/renewal-hooks/deploy/xcli-rust').read_text()
            self.assertIn('/usr/local/lib/xcli/xcli-cert-renew', hook)
            self.assertIn(str(live), hook)
            units = list(map(str, Path('/etc/systemd/system').glob('xcli-*.service')))
            result = subprocess.run(['systemd-analyze', 'verify', *units], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            old_update = subprocess.run(['bash', str(ROOT / 'update.sh'), '--check'],
                                        capture_output=True, text=True, timeout=10)
            self.assertNotEqual(old_update.returncode, 0)
            self.assertIn('Rust 测试版', old_update.stderr)
            if ROLE == 'panel':
                firewall = '/usr/local/lib/xcli/firewall.sh'
                subprocess.run([firewall, 'start'], check=True, timeout=15)
                try:
                    response = subprocess.run(['curl','-fsS','--noproxy','*','--max-time','5',
                        'http://127.0.0.1:8080/healthz'],capture_output=True,timeout=8)
                    self.assertEqual(response.returncode, 0, 'gateway could not reach panel with firewall enabled')
                finally:
                    subprocess.run([firewall, 'stop'], check=True, timeout=15)
            ipv6 = subprocess.run(['curl','-6','--noproxy','*','--cacert',str(cert),'--resolve',
                domain+':19443:[2001:db8::8]','--max-time','8','-sS','-o','/dev/null','-w','%{http_code}',
                'https://'+domain+':19443/healthz'], capture_output=True, text=True, timeout=10)
            self.assertEqual(ipv6.returncode, 0, ipv6.stderr)
            self.assertEqual(ipv6.stdout, '200' if ROLE == 'panel' else '404')
            if ROLE == 'node':
                registration = json.loads(Path('/etc/xcli-node/registration.json').read_text())
                config = json.loads(Path('/etc/xcli-node/node.json').read_text())
                self.assertEqual(registration['id'], config['node_id'])
                self.assertEqual(registration['key'], config['token'])
                self.assertTrue(wait_for(lambda: subprocess.run(['/usr/local/lib/xcli/xray', 'api', 'inboundusercount',
                    '--server=127.0.0.1:10085', '-tag=reality', '--timeout=1'], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=3).returncode == 0), 'node core did not start')
                node_info = {'role': 'node', 'db': Path('/var/lib/xcli-node/traffic.sqlite'),
                             'config': Path('/etc/xcli-node/node.json'), 'core': Path('/etc/xcli-node/core.json')}
                update_existing(node_info)
                self.assertEqual(json.loads(Path('/etc/xcli-node/registration.json').read_text()), registration)
                self.assertEqual(json.loads(Path('/etc/xcli-node/node.json').read_text()), config)
                self.assertEqual(Path('/etc/xcli-node/revision').read_text().strip(), 'b' * 40)
                self.assertTrue(wait_for(lambda: subprocess.run(['/usr/local/lib/xcli/xray', 'api', 'inboundusercount',
                    '--server=127.0.0.1:10085', '-tag=reality', '--timeout=1'], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=3).returncode == 0), 'updated node core did not start')
                with self.assertRaises(RuntimeError):
                    update_existing(node_info, broken_release('node'), 'c' * 40)
                self.assertEqual(Path('/etc/xcli-node/revision').read_text().strip(), 'b' * 40)
                self.assertEqual(json.loads(Path('/etc/xcli-node/registration.json').read_text()), registration)
                self.assertTrue(wait_for(lambda: subprocess.run(['/usr/local/lib/xcli/xray', 'api', 'inboundusercount',
                    '--server=127.0.0.1:10085', '-tag=reality', '--timeout=1'], stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=3).returncode == 0), 'node did not recover after failed update')
                check_wrapper('node')
                return
            origin = 'https://' + domain + ':19443'
            self.assertTrue(wait_for(lambda: request(18080, '/internal/ready', origin=origin)[0] == 200),
                            'panel did not synchronize its core')
            password = Path('/etc/xcli/initial-admin.txt').read_text().split('Password: ', 1)[1].strip()
            status, headers, body = request(8080, '/api/login', 'POST',
                json.dumps({'username': 'admin', 'password': password}).encode(), origin=origin)
            self.assertEqual(status, 200)
            cookie = headers['set-cookie'].split(';', 1)[0]
            csrf = json.loads(body)['csrf']
            def disk_ready():
                status, _, body = request(8080, '/api/host', cookie=cookie, origin=origin)
                return status == 200 and isinstance((json.loads(body).get('host') or {}).get('disk'), dict)
            self.assertTrue(wait_for(disk_ready, 10), 'panel did not sample disk usage')
            status, _, body = request(8080, '/api/webshare', cookie=cookie, origin=origin)
            self.assertEqual(status, 200)
            residential = json.loads(body)
            self.assertTrue(residential['installed']); self.assertFalse(residential['enabled'])
            self.assertEqual(len(residential['regions']), 16)
            status, _, body = request(8080, '/api/users', 'POST', json.dumps({'name': 'fixture'}).encode(),
                                      cookie, csrf, origin=origin)
            self.assertEqual(status, 200)
            user_id = json.loads(body)['id']
            with closing(sqlite3.connect('/var/lib/xcli/gateway.sqlite')) as database:
                uuid = database.execute('SELECT uuid FROM users WHERE id=?', (user_id,)).fetchone()[0]
            def user_ready():
                result = subprocess.run(['/usr/local/lib/xcli/xray', 'api', 'inbounduser',
                    '--server=127.0.0.1:10085', '-tag=websocket', '--timeout=1'], capture_output=True, timeout=3)
                return result.returncode == 0 and uuid.encode() in result.stdout
            self.assertTrue(wait_for(user_ready), 'new user was not synchronized')

            with closing(sqlite3.connect('/var/lib/xcli/gateway.sqlite')) as database:
                token = database.execute('SELECT token FROM users WHERE id=?', (user_id,)).fetchone()[0]
            subscription_before = request(8080, '/s/' + token + '/clash.yaml', origin=origin)
            self.assertEqual(subscription_before[0], 200)
            core_pid = services.processes['xcli-core'].pid
            panel_info = {'role': 'panel', 'db': Path('/var/lib/xcli/gateway.sqlite'),
                          'settings': Path('/etc/xcli/settings.json'), 'key': Path('/etc/xcli/security.key'),
                          'core_pid': Path('/sys/fs/cgroup/system.slice/xcli-core.service/cgroup.procs'),
                          'import_report': Path('/var/lib/xcli-import/report/report.json')}
            update_existing(panel_info)
            self.assertEqual(services.processes['xcli-core'].pid, core_pid)
            with closing(sqlite3.connect('/var/lib/xcli/gateway.sqlite')) as database:
                self.assertEqual(database.execute('SELECT uuid,token FROM users WHERE id=?', (user_id,)).fetchone(),
                                 (uuid, token))
            self.assertEqual(request(8080, '/s/' + token + '/clash.yaml', origin=origin)[2], subscription_before[2])
            self.assertEqual(request(8080, '/api/users', cookie=cookie, origin=origin)[0], 200)
            self.assertEqual(Path('/opt/xcli/current/COMMIT').read_text().strip(), 'b' * 40)
            with self.assertRaises(RuntimeError):
                update_existing(panel_info, broken_release('web'), 'c' * 40)
            self.assertEqual(services.processes['xcli-core'].pid, core_pid)
            self.assertEqual(Path('/opt/xcli/current/COMMIT').read_text().strip(), 'b' * 40)
            self.assertEqual(request(8080, '/s/' + token + '/clash.yaml', origin=origin)[2], subscription_before[2])
            self.assertEqual(request(8080, '/api/users', cookie=cookie, origin=origin)[0], 200)
            check_wrapper('panel')

            payload = b'fresh-install-traffic' * 100
            class Origin(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_): pass
                def do_GET(self):
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
            server = http.server.ThreadingHTTPServer(('1.1.1.1', 0), Origin)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            socks = port()
            settings = json.loads(Path('/etc/xcli/settings.json').read_text())
            client_config = {'log': {'loglevel': 'none'},
                'inbounds': [{'listen': '127.0.0.1', 'port': socks, 'protocol': 'socks', 'settings': {'auth': 'noauth'}}],
                'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{'address': '127.0.0.1', 'port': 19443,
                    'users': [{'id': uuid, 'encryption': 'none'}]}]},
                    'streamSettings': {'network': 'ws', 'security': 'tls',
                        'wsSettings': {'path': settings['ws_path']},
                        'tlsSettings': {'serverName': domain, 'disableSystemRoot': True,
                                        'certificates': [{'certificateFile': str(cert), 'usage': 'verify'}]}}}]}
            client_path = fixture / 'client.json'
            client_path.write_text(json.dumps(client_config))
            client = subprocess.Popen(['/usr/local/lib/xcli/xray', 'run', '-config', str(client_path)],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                def socks_ready():
                    with socket.create_connection(('127.0.0.1', socks), timeout=1):
                        return True
                self.assertTrue(wait_for(socks_ready, 8), 'client did not start')
                fetched = subprocess.run(['curl', '-fsS', '--noproxy', '', '--proxy', f'socks5h://127.0.0.1:{socks}',
                                          '--max-time', '8', f'http://1.1.1.1:{server.server_port}/'], capture_output=True, timeout=10)
                self.assertEqual(fetched.returncode, 0, fetched.stderr.decode(errors='replace'))
                self.assertEqual(fetched.stdout, payload)
            finally:
                client.terminate()
                client.wait(timeout=10)
            try:
                for address in ('127.0.0.1', '2001:db8::8'):
                    hy_socks = port()
                    hy = {'log':{'loglevel':'none'},
                        'inbounds':[{'listen':'127.0.0.1','port':hy_socks,'protocol':'socks','settings':{'auth':'noauth'}}],
                        'outbounds':[{'protocol':'hysteria','settings':{'version':2,'address':address,'port':19443},
                            'streamSettings':{'network':'hysteria','security':'tls','hysteriaSettings':{'version':2,'auth':uuid},
                                'tlsSettings':{'serverName':domain,'alpn':['h3'],'disableSystemRoot':True,
                                    'certificates':[{'certificateFile':str(cert),'usage':'verify'}]}}}]}
                    hy_path = fixture / 'hy-client.json'; hy_path.write_text(json.dumps(hy))
                    hy_client = subprocess.Popen(['/usr/local/lib/xcli/xray','run','-config',str(hy_path)],
                                                 stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    try:
                        self.assertTrue(wait_for(lambda: socket_open(hy_socks), 8), 'Hysteria client did not start')
                        result = subprocess.run(['curl','-fsS','--noproxy','','--proxy',f'socks5h://127.0.0.1:{hy_socks}',
                            '--max-time','8',f'http://1.1.1.1:{server.server_port}/'],capture_output=True,timeout=10)
                        self.assertEqual(result.returncode, 0, 'Hysteria failed over '+address)
                        self.assertEqual(result.stdout, payload)
                    finally:
                        hy_client.terminate(); hy_client.wait(timeout=10)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=3)
        except Exception:
            if installer.log.exists():
                print('Install fixture log:')
                print(installer.log.read_text(errors='replace')[-6000:])
            raise
        finally:
            services.close()
            if any(child.returncode not in (0, -signal.SIGTERM) for child in services.processes.values()):
                for name, child in services.processes.items():
                    if child.returncode not in (0, -signal.SIGTERM):
                        print(f'{name} exited with {child.returncode}; fixture log:')
                        print((fixture / (name + '.log')).read_text(errors='replace')[-2000:])


if __name__ == '__main__':
    unittest.main()
