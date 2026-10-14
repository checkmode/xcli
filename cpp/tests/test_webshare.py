"""HTTP authorization, C++/Python encrypted-state interoperability, and safe status output."""
import importlib.util
import json
from pathlib import Path
import time

from test_http import fixture

spec = importlib.util.spec_from_file_location('webshare_worker', Path(__file__).resolve().parents[2] / 'scripts/webshare.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


def test_api_key_encryption_and_control_authorization(fixture):
    client = fixture['client']
    assert client.call('/api/webshare')[0] == 401
    client.login()
    secret = 'fixture-api-key-for-test'
    client.json('/api/webshare', 'PUT', {'api_key': secret}, expected=403, headers={'X-CSRF-Token': 'wrong'})
    client.json('/api/webshare', 'PUT', {'api_key': secret})
    state = client.json('/api/webshare')
    assert state['key_saved'] and secret not in json.dumps(state)
    encrypted = (fixture['state'] / 'webshare/config.xgb').read_bytes()
    assert encrypted[:4] == b'XGB1' and secret.encode() not in encrypted
    key = (fixture['state'] / 'security.key').read_bytes()
    value = worker.unseal(encrypted, key, worker.CONFIG_CONTEXT)
    assert value['api_key'] == secret
    client.json('/api/webshare', 'PUT', {'enabled': True}, expected=422)
    client.json('/api/webshare', 'PUT', {'plan_id': 17}, expected=422)
    client.json('/api/webshare/action', 'POST', {'action': 'rotate', 'country': 'US'}, expected=422)
    report = {'updated': int(time.time()), 'plans': [{'id': 17, 'eligible': True, 'label': '住宅', 'password': secret}],
              'api_key': secret, 'pools': [{'country': 'US', 'exit_ip': '8.8.8.8', 'username': secret}], 'events': []}
    worker.atomic_write(fixture['state'] / 'webshare/report.json', json.dumps(report).encode())
    assert secret not in json.dumps(client.json('/api/webshare'))
    client.json('/api/webshare', 'PUT', {'plan_id': 17, 'enabled': True})
    client.json('/api/webshare/action', 'POST', {'action': 'rotate', 'country': 'XX'}, expected=422)
    client.json('/api/webshare/action', 'POST', {'action': 'sync'})
    client.json('/api/webshare', 'PUT', {'clear_key': True})
    state = client.json('/api/webshare')
    assert not state['key_saved'] and not state['enabled'] and state['plan_id'] == 0
