"""Test Xray certificate reload failure modes on loopback with synthetic keys."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import threading
import unittest
import uuid

from test_node_service_integration import port, wait_for
from test_panel_http_integration import stop
from test_xray_hysteria_revocation import socks_stream
from test_xray_inbound_drain import EchoHandler, EchoServer, recv_exact

XRAY = os.environ.get('XCLI_TEST_XRAY', '')
BUNDLE = os.environ.get('XCLI_CERT_BUNDLE_DRIVER', '')
RENEWAL = os.environ.get('XCLI_CERT_RENEWAL_DRIVER', '')


def certificate_hash(path):
    der = subprocess.check_output(['openssl', 'x509', '-in', str(path), '-outform', 'DER'], timeout=5)
    return hashlib.sha256(der).digest()


def atomic_copy(source, target):
    staged = target.with_name(target.name + '.next')
    shutil.copyfile(source, staged)
    os.replace(staged, target)


def peer_hash(listen):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection(('127.0.0.1', listen), timeout=2) as raw:
            with context.wrap_socket(raw, server_hostname='localhost') as stream:
                return hashlib.sha256(stream.getpeercert(binary_form=True)).digest()
    except (OSError, ssl.SSLError):
        return None


@unittest.skipUnless(XRAY and Path(XRAY).is_file(), 'set XCLI_TEST_XRAY to an isolated binary')
class CertificateReload(unittest.TestCase):
    def test_mismatched_pair_recovers_but_missing_file_stops_reloader(self):
        with tempfile.TemporaryDirectory(prefix='xcli-cert-reload-') as folder:
            root = Path(folder)
            certs = []
            keys = []
            for number in (1, 2):
                cert = root / f'cert{number}.pem'
                key = root / f'key{number}.pem'
                subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-keyout', str(key),
                    '-out', str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
                certs.append(cert); keys.append(key)
            first, second = map(certificate_hash, certs)
            self.assertNotEqual(first, second)
            live_cert, live_key = root / 'fullchain.pem', root / 'privkey.pem'
            shutil.copyfile(certs[0], live_cert); shutil.copyfile(keys[0], live_key)
            listen = port(); log = root / 'xray.log'
            config = {'log': {'loglevel': 'warning', 'error': str(log)}, 'inbounds': [
                {'listen': '127.0.0.1', 'port': listen, 'protocol': 'vless',
                 'settings': {'clients': [], 'decryption': 'none'},
                 'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {'certificates': [
                    {'certificateFile': str(live_cert), 'keyFile': str(live_key), 'ocspStapling': 1}]}}}],
                'outbounds': [{'protocol': 'freedom'}]}
            config_file = root / 'config.json'; config_file.write_text(json.dumps(config))
            subprocess.run([XRAY, 'run', '-test', '-config', str(config_file)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            core = None
            try:
                core = subprocess.Popen([XRAY, 'run', '-config', str(config_file)],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.assertTrue(wait_for(lambda: peer_hash(listen) == first, 8), 'initial TLS certificate unavailable')
                atomic_copy(certs[1], live_cert)
                time.sleep(2.5)
                self.assertEqual(peer_hash(listen), first, 'mismatched pair unexpectedly replaced the old certificate')
                atomic_copy(keys[1], live_key)
                self.assertTrue(wait_for(lambda: peer_hash(listen) == second, 8), 'valid pair was not hot reloaded')
                live_cert.unlink()
                self.assertTrue(wait_for(lambda: log.exists() and 'failed to parse certificate' in log.read_text(), 8),
                                'fixture did not exercise a certificate read failure')
                atomic_copy(certs[0], live_cert); atomic_copy(keys[0], live_key)
                time.sleep(2.5)
                self.assertEqual(peer_hash(listen), second, 'fixture reloader unexpectedly continued after file failure')
                stop(core); core = subprocess.Popen([XRAY, 'run', '-config', str(config_file)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.assertTrue(wait_for(lambda: peer_hash(listen) == first, 8), 'new core did not load the recovered pair')
            finally:
                stop(core)

    def test_atomic_single_pem_reload_with_tcp_and_hysteria(self):
        if not BUNDLE or not Path(BUNDLE).is_file() or not RENEWAL or not Path(RENEWAL).is_file():
            self.skipTest('set Rust publisher and renewal fixture paths')
        with tempfile.TemporaryDirectory(prefix='xcli-combined-cert-') as folder:
            root = Path(folder); certs = []; keys = []
            for number in (1, 2):
                cert = root / f'cert{number}.pem'; key = root / f'key{number}.pem'
                subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                    '-addext', 'basicConstraints=critical,CA:TRUE', '-keyout', str(key), '-out', str(cert)],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
                certs.append(cert); keys.append(key)
            trust = root / 'trust.pem'; trust.write_bytes(certs[0].read_bytes() + certs[1].read_bytes())
            live = root / 'live.pem'
            subprocess.run([BUNDLE, str(certs[0]), str(keys[0]), str(live)], check=True, timeout=15)
            certbot = root / 'certbot'; archive = certbot / 'archive' / 'localhost'; lineage = certbot / 'live' / 'localhost'
            archive.mkdir(parents=True); lineage.mkdir(parents=True)
            for index in range(2):
                shutil.copyfile(certs[index], archive / f'fullchain{index+1}.pem')
                shutil.copyfile(keys[index], archive / f'privkey{index+1}.pem')
                (archive / f'privkey{index+1}.pem').chmod(0o600)
            (lineage / 'fullchain.pem').symlink_to('../../archive/localhost/fullchain1.pem')
            (lineage / 'privkey.pem').symlink_to('../../archive/localhost/privkey1.pem')
            hook = [RENEWAL, str(certbot), str(lineage), str(live), 'localhost']
            original = live.read_bytes()
            subprocess.run([RENEWAL, str(certbot), str(certbot / 'live' / 'other'), str(live), 'localhost'], check=True, timeout=15)
            self.assertEqual(live.read_bytes(), original, 'an unrelated lineage changed the certificate')
            (lineage / 'fullchain.pem').unlink(); (lineage / 'fullchain.pem').symlink_to('../../archive/localhost/fullchain2.pem')
            result = subprocess.run(hook, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
            self.assertNotEqual(result.returncode, 0, 'mismatched renewal was accepted')
            self.assertEqual(live.read_bytes(), original, 'invalid renewal changed the active certificate')
            (lineage / 'privkey.pem').unlink(); (lineage / 'privkey.pem').symlink_to('../../archive/localhost/privkey2.pem')
            tcp, hy2 = port(), port(); identity = str(uuid.uuid4())
            cert_config = {'certificateFile': str(live), 'keyFile': str(live), 'ocspStapling': 1}
            core_config = {'log': {'loglevel': 'none'}, 'inbounds': [
                {'listen': '127.0.0.1', 'port': tcp, 'protocol': 'vless',
                 'settings': {'clients': [], 'decryption': 'none'},
                 'streamSettings': {'network': 'tcp', 'security': 'tls', 'tlsSettings': {'certificates': [cert_config]}}},
                {'listen': '127.0.0.1', 'port': hy2, 'protocol': 'hysteria',
                 'settings': {'version': 2, 'clients': [{'auth': identity}]},
                 'streamSettings': {'network': 'hysteria', 'security': 'tls', 'hysteriaSettings': {'version': 2},
                                    'tlsSettings': {'alpn': ['h3'], 'certificates': [cert_config]}}}],
                'outbounds': [{'protocol': 'freedom', 'settings': {'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1/32']}]}}]}
            config = root / 'core.json'; config.write_text(json.dumps(core_config))
            core = None; clients = []
            echo = EchoServer(('127.0.0.1', 0), EchoHandler)
            thread = threading.Thread(target=echo.serve_forever, daemon=True); thread.start()
            def connection():
                socks = port()
                client = {'log': {'loglevel': 'none'}, 'inbounds': [
                    {'listen': '127.0.0.1', 'port': socks, 'protocol': 'socks', 'settings': {'auth': 'noauth'}}],
                    'outbounds': [{'protocol': 'hysteria', 'settings': {'version': 2, 'address': '127.0.0.1', 'port': hy2},
                        'streamSettings': {'network': 'hysteria', 'security': 'tls', 'hysteriaSettings': {'version': 2, 'auth': identity},
                        'tlsSettings': {'serverName': 'localhost', 'allowInsecure': False, 'alpn': ['h3'],
                                        'disableSystemRoot': True, 'certificates': [{'certificateFile': str(trust), 'usage': 'verify'}]}}}]}
                path = root / f'client-{socks}.json'; path.write_text(json.dumps(client))
                process = subprocess.Popen([XRAY, 'run', '-config', str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                clients.append(process)
                self.assertTrue(wait_for(lambda: process.poll() is None and can_connect(socks), 8), 'fixture client did not start')
                with socks_stream(socks, echo.server_address[1]) as stream:
                    stream.sendall(b'hello-hy2'); self.assertEqual(recv_exact(stream, 9), b'hello-hy2')
            def can_connect(p):
                try:
                    with socket.create_connection(('127.0.0.1', p), timeout=.2): return True
                except OSError: return False
            try:
                core = subprocess.Popen([XRAY, 'run', '-config', str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                first, second = map(certificate_hash, certs)
                self.assertTrue(wait_for(lambda: peer_hash(tcp) == first, 8), 'first combined certificate unavailable')
                connection()
                observed = []; done = threading.Event()
                def handshake_while_publishing():
                    while not done.is_set():
                        observed.append(peer_hash(tcp))
                        time.sleep(.02)
                observer = threading.Thread(target=handshake_while_publishing, daemon=True); observer.start()
                try:
                    for index, expected in ((1, second), (0, first), (1, second)):
                        if index == 1:
                            subprocess.run(hook, check=True, timeout=15)
                        else:
                            subprocess.run([BUNDLE, str(certs[index]), str(keys[index]), str(live)], check=True, timeout=15)
                        self.assertTrue(wait_for(lambda: peer_hash(tcp) == expected, 8), 'single PEM update was not observed')
                finally:
                    done.set(); observer.join(timeout=5)
                self.assertTrue(observed, 'no handshake was sampled during publication')
                self.assertTrue(all(value in (first, second) for value in observed), 'a handshake failed or exposed an unexpected certificate')
                connection()
                stop(core); core = subprocess.Popen([XRAY, 'run', '-config', str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                self.assertTrue(wait_for(lambda: peer_hash(tcp) == second, 8), 'restart did not load complete combined PEM')
                connection()
            finally:
                for process in clients: stop(process)
                stop(core); echo.shutdown(); echo.server_close(); thread.join(timeout=5)
