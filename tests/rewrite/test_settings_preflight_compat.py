"""Compare experimental startup validation with the old C++ panel on synthetic settings."""
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

from test_panel_http_integration import free_port, stop

OLD = os.environ.get('XCLI_LEGACY_PANEL', '')
NEW = os.environ.get('XCLI_PANEL_SERVICE', '')
PROVISION = os.environ.get('XCLI_PROVISION_FIXTURE', '')


def accepts(args, port):
    process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return False
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1):
                    return True
            except OSError:
                time.sleep(.02)
        raise AssertionError('panel did not accept connections or exit in time')
    finally:
        if process.poll() is None:
            stop(process)


def cases():
    base = {'origin':'https://testserver', 'domain':'testserver', 'public_ip':'203.0.113.2',
            'reality_sni':'example.com', 'reality_public':'p'*43, 'short_id':'aabbccdd',
            'ws_path':'/connect/test', 'hysteria2_port':443}
    fixed = {'tag':'residential-27', 'label':'住宅', 'exit_ip':'8.8.8.8', 'country':'US',
             'ws_path':'/connect/test/residential-27', 'port':10401, 'hysteria2':True}
    dynamic = {'tag':'residential-11', 'label':'美国', 'exit_ip':'', 'country':'US',
               'ws_path':'/connect/test/residential-11', 'port':10110, 'dynamic':True}
    user = 'a'*32
    route = {'name':'WORK', 'outbound':'hysteria2', 'domains':['work.example.com'], 'udp':'proxy'}
    result = [('basic', base, True)]
    def case(name, expected, change):
        value = copy.deepcopy(base)
        change(value)
        result.append((name, value, expected))
    case('valid vmess', True, lambda v: v.update(vmess_ws_path='/connect/test/vmess', vmess_port=10081))
    case('bad vmess path', False, lambda v: v.update(vmess_ws_path='/bad', vmess_port=10081))
    case('bad vmess port', False, lambda v: v.update(vmess_ws_path='/connect/test/vmess', vmess_port=1))
    case('missing required', False, lambda v: v.pop('reality_public'))
    case('invalid public port', False, lambda v: v.update(public_port=0))
    case('invalid node address option', False, lambda v: v.update(node_address_ip='true'))
    case('valid fixed', True, lambda v: v.update(residential_exits=[fixed]))
    case('valid dynamic', True, lambda v: v.update(residential_exits=[dynamic]))
    case('duplicate exit', False, lambda v: v.update(residential_exits=[fixed, fixed]))
    case('private exit', False, lambda v: v.update(residential_exits=[dict(fixed, exit_ip='10.0.0.1')]))
    case('exit path mismatch', False, lambda v: v.update(residential_exits=[dict(fixed, ws_path='/bad')]))
    case('exit unknown field', False, lambda v: v.update(residential_exits=[dict(fixed, unknown=1)]))
    case('exit bad tag', False, lambda v: v.update(residential_exits=[dict(fixed, tag='residential-zz')]))
    case('exit bad label', False, lambda v: v.update(residential_exits=[dict(fixed, label=' \t')]))
    case('dynamic invalid port', False, lambda v: v.update(residential_exits=[dict(dynamic, port=10111)]))
    case('dynamic hysteria', False, lambda v: v.update(residential_exits=[dict(dynamic, hysteria2=True)]))
    case('hysteria disabled', False, lambda v: v.update(hysteria2_port=0, residential_exits=[fixed]))
    case('valid route', True, lambda v: v.update(clash_service_routes={user:[route]}))
    case('invalid owner', False, lambda v: v.update(clash_service_routes={'not-an-id':[route]}))
    case('reserved route', False, lambda v: v.update(clash_service_routes={user:[dict(route, name='DIRECT')]}))
    case('route invalid domain', False, lambda v: v.update(clash_service_routes={user:[dict(route, domains=['Bad.example'])]}))
    case('route overlap', False, lambda v: v.update(clash_service_routes={user:[dict(route, domains=['a.example', 'b.a.example'])]}))
    case('residential udp leak', False, lambda v: v.update(clash_service_routes={user:[dict(route, outbound='residential-27')]}))
    case('valid residential route', True, lambda v: v.update(clash_service_routes={user:[dict(route, outbound='residential-27', udp='reject')]}))
    case('missing policy base', False, lambda v: v.update(client_policies={user:{'ai_outbound':'proxy'}}))
    case('valid policy', True, lambda v: v.update(client_policies={user:{'ai_outbound':'proxy'}}, shadowrocket_base_profiles={user:'[General]'}))
    case('bad policy outbound', False, lambda v: v.update(client_policies={user:{'ai_outbound':'invalid'}}, shadowrocket_base_profiles={user:'[General]'}))
    case('orphan shadow base', False, lambda v: v.update(shadowrocket_base_profiles={user:'[General]'}))
    case('valid shadow service', True, lambda v: v.update(clash_service_routes={user:[route]}, shadowrocket_service_users=[user], shadowrocket_base_profiles={user:'[General]'}))
    case('duplicate shadow user', False, lambda v: v.update(clash_service_routes={user:[route]}, shadowrocket_service_users=[user,user], shadowrocket_base_profiles={user:'[General]'}))
    case('shadow tcp-only exit', False, lambda v: v.update(residential_exits=[dict(fixed, hysteria2=False)], clash_service_routes={user:[dict(route, outbound='residential-27', udp='reject')]}, shadowrocket_service_users=[user], shadowrocket_base_profiles={user:'[General]'}))
    return result


@unittest.skipUnless(OLD and NEW and PROVISION and all(Path(p).is_file() for p in (OLD, NEW, PROVISION)),
                     'set legacy panel, experimental panel and provision fixture')
class SettingsPreflightCompatibility(unittest.TestCase):
    def test_startup_acceptance_matches_legacy(self):
        with tempfile.TemporaryDirectory(prefix='xcli-settings-compat-') as folder:
            root = Path(folder); state = root/'state'; state.mkdir()
            db = state/'gateway.sqlite'
            subprocess.run([PROVISION, str(db)], check=True, timeout=15)
            key = root/'key'; key.write_bytes(bytes(range(32))); key.chmod(0o600)
            settings = root/'settings.json'
            for name, value, expected in cases():
                with self.subTest(name=name):
                    settings.write_text(json.dumps(value, ensure_ascii=False))
                    old_port = free_port()
                    old = accepts([OLD, '--state', str(state), '--settings', str(settings), '--static', str(root),
                                   '--secret-key', str(key), '--port', str(old_port), '--offline', '--no-auto-backup'], old_port)
                    new_port = free_port()
                    new = accepts([NEW, '--experimental', '--db', str(db), '--secret-key', str(key),
                                   '--settings', str(settings), '--experimental-strict-settings', 'true',
                                   '--origin', 'https://testserver', '--port', str(new_port)], new_port)
                    self.assertEqual(old, expected, 'unexpected legacy result')
                    self.assertEqual(new, old, 'new and legacy startup disagree')

    def test_invalid_settings_rejected_before_opening_database(self):
        with tempfile.TemporaryDirectory(prefix='xcli-settings-reject-') as folder:
            root = Path(folder); config = root/'settings.json'; database = root/'absent.sqlite'
            config.write_text(json.dumps({'origin':'https://testserver'}))
            proc = subprocess.run([NEW, '--experimental', '--db', str(database), '--secret-key', str(root/'missing-key'),
                                   '--settings', str(config), '--experimental-strict-settings', 'true',
                                   '--origin', 'https://testserver'], capture_output=True, timeout=10)
            self.assertNotEqual(proc.returncode, 0)
            self.assertFalse(database.exists())
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['settings.json'])
            config.unlink()
            os.mkfifo(config)
            proc = subprocess.run([NEW, '--experimental', '--db', str(database), '--secret-key', str(root/'missing-key'),
                                   '--settings', str(config), '--experimental-strict-settings', 'true',
                                   '--origin', 'https://testserver'], capture_output=True, timeout=5)
            self.assertNotEqual(proc.returncode, 0, 'a FIFO is not a valid settings file')
            self.assertFalse(database.exists())


if __name__ == '__main__':
    unittest.main()
