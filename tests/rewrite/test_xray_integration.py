"""Run the existing loopback-only three-protocol test against the Rust adapter.

Requires XCLI_TEST_XRAY and XCLI_XRAY_DRIVER. No production configuration is used.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests' / 'node'))
import test_node_xray_integration as legacy


class RustController:
    def __init__(self, binary, config_path, api):
        self.binary, self.api = binary, api
        self.process = subprocess.Popen([os.environ['XCLI_XRAY_DRIVER'], str(binary), str(config_path), api],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.generation = ''

    def call(self, payload):
        self.process.stdin.write(json.dumps(payload) + '\n')
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError('Rust Xray adapter driver stopped')
        result = json.loads(line)
        if not result['ok']:
            raise RuntimeError('Rust Xray adapter rejected test operation')
        self.generation = result['generation']
        return result['value']

    def start(self):
        self.call({'op': 'start'})

    def apply(self, users):
        self.call({'op': 'apply', 'users': list(users.values())})

    def counters(self):
        return self.call({'op': 'counters'})

    def command(self, *args, input_data=None, timeout=30):
        return subprocess.run([self.binary, 'api', args[0], '--server=' + self.api, *args[1:]],
            input=input_data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=True).stdout

    def stop(self):
        if self.process.poll() is None:
            self.call({'op': 'stop'})
            self.process.stdin.close()
            self.process.wait(timeout=15)
        self.process.stdout.close()
        self.process.stderr.close()
        if self.process.returncode:
            raise RuntimeError('Rust Xray adapter driver exited unsuccessfully')


legacy.XrayController = RustController


class RustXrayIntegration(legacy.RealXrayTests):
    pass
