"""Optional real-binary checks using private temporary files and unused loopback ports."""
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request

SOURCE = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE / 'deploy'))
import provision


@unittest.skipUnless(os.environ.get('XG_TEST_BINARY') and os.environ.get('XG_TEST_XRAY'), 'Requires test binary paths')
class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix='xcli-installer-check-')
        self.addCleanup(self.work.cleanup)
        self.root = pathlib.Path(self.work.name)
        keys = subprocess.check_output([os.environ['XG_TEST_XRAY'], 'x25519']).decode()
        self.settings = provision.settings_for('panel.example.com', '8.8.4.4', 'www.bing.com', keys)

    def test_xray_accepts_generated_core_config(self):
        config = self.root / 'core.json'
        provision.write_json(config, provision.core_config(self.settings))
        subprocess.run([os.environ['XG_TEST_XRAY'], 'run', '-test', '-config', str(config)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def test_nginx_accepts_generated_tls_and_acme_configs(self):
        if not os.environ.get('XG_TEST_NGINX'):
            self.skipTest('Requires Nginx path')
        cert, key = self.root / 'cert.pem', self.root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=panel.example.com', '-keyout', str(key), '-out', str(cert)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        for tls in (False, True):
            config = self.root / ('tls.conf' if tls else 'acme.conf')
            content = provision.render_nginx(SOURCE, self.settings, str(cert) if tls else None, str(key) if tls else None)
            content = content.replace('/run/nginx.pid', str(self.root / 'nginx.pid'))
            content = content.replace('/var/log/nginx/error.log', str(self.root / 'error.log'))
            # Some Nginx builds also validate binds during -t. Avoid host ports.
            for original in ('listen 80 ', 'listen 443;', 'listen 127.0.0.1:8443 '):
                with socket.socket() as listener:
                    listener.bind(('127.0.0.1', 0))
                    port = listener.getsockname()[1]
                content = content.replace(original, 'listen 127.0.0.1:' + str(port) + (';' if original.endswith(';') else ' '))
            config.write_text(content)
            result = subprocess.run([os.environ['XG_TEST_NGINX'], '-t', '-c', str(config), '-e', str(self.root / 'early.log')],
                                    capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_cpp_accepts_generated_administrator(self):
        state = self.root / 'state'
        state.mkdir(mode=0o700)
        credential = self.root / 'admin.txt'
        provision.initialize_admin(state / 'gateway.sqlite', credential, self.settings['domain'])
        provision.write_json(self.root / 'settings.json', self.settings)
        provision.private_file(self.root / 'security.key', os.urandom(32))
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        process = subprocess.Popen([os.environ['XG_TEST_BINARY'], '--offline', '--no-auto-backup',
            '--state', str(state), '--settings', str(self.root / 'settings.json'), '--secret-key', str(self.root / 'security.key'),
            '--static', str(SOURCE / 'static'), '--port', str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            for attempt in range(50):
                try:
                    with client.open(f'http://127.0.0.1:{port}/healthz', timeout=.5) as response:
                        self.assertEqual(response.status, 200)
                    break
                except OSError:
                    self.assertIsNone(process.poll(), 'C++ server exited before login check')
                    time.sleep(.1)
            else:
                self.fail('C++ server did not start')
            fields = dict(line.split(': ', 1) for line in credential.read_text().splitlines())
            request = urllib.request.Request(f'http://127.0.0.1:{port}/api/login',
                data=json.dumps({'username': 'admin', 'password': fields['Password']}).encode(),
                headers={'Content-Type': 'application/json', 'Origin': self.settings['origin']})
            with client.open(request, timeout=5) as response:
                self.assertTrue(json.load(response)['csrf'])
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == '__main__':
    unittest.main()
