"""Exercise the experimental worker without real credentials or upstream traffic."""
import json
import os
import signal
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


SERVICE = os.environ.get('XCLI_WEBSHARE_SERVICE', '')
REGIONS = [('US', 'residential-11', 10110, 10120),
           ('JP', 'residential-12', 10111, 10121),
           ('SG', 'residential-13', 10112, 10122),
           ('HK', 'residential-15', 10200, 10300),
           ('TW', 'residential-16', 10201, 10301)]


def available(region):
    with socket.socket() as sock:
        try:
            sock.bind(('127.0.0.1', region[3]))
            return True
        except OSError:
            return False


def listening(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=0.2):
            return True
    except OSError:
        return False


def ready(process, port):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError('synthetic worker exited before it was ready')
        if listening(port):
            return
        time.sleep(0.05)
    raise AssertionError('synthetic worker did not listen')


@unittest.skipUnless(SERVICE and Path(SERVICE).is_file(), 'set experimental worker path')
class WebshareServiceIntegration(unittest.TestCase):
    def test_unconfigured_worker_rejects_a_second_process_and_stops_cleanly(self):
        regions = [region for region in REGIONS if available(region)]
        if len(regions) < 2:
            self.skipTest('two fixture loopback ports are unavailable')
        with tempfile.TemporaryDirectory(prefix='xcli-webshare-worker-') as folder:
            root = Path(folder)
            key = root / 'security.key'
            key.write_bytes(bytes(range(32)))
            key.chmod(0o600)

            def settings(region):
                country, tag, port, _ = region
                path = root / (country + '.json')
                path.write_text(json.dumps({'residential_exits': [
                    {'country': country, 'tag': tag, 'port': port, 'dynamic': True}]}))
                return path

            def start(region):
                return subprocess.Popen(
                    [SERVICE, '--experimental', '--state', str(root), '--settings', str(settings(region)),
                     '--secret-key', str(key)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            first = second = None
            try:
                first = start(regions[0])
                ready(first, regions[0][3])
                second = start(regions[1])
                self.assertNotEqual(second.wait(timeout=8), 0)
                self.assertFalse(listening(regions[1][3]))
                first.send_signal(signal.SIGTERM)
                self.assertEqual(first.wait(timeout=8), 0)
                self.assertFalse(listening(regions[0][3]))
                first = start(regions[1])
                ready(first, regions[1][3])
                first.send_signal(signal.SIGTERM)
                self.assertEqual(first.wait(timeout=8), 0)
                self.assertFalse(listening(regions[1][3]))
            finally:
                for process in (first, second):
                    if process and process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
