"""Read-only diagnostics describe generated subscriptions without exposing credentials."""
import base64
import hashlib
import json

import pytest
import yaml

from test_http import fixture
from test_client_policy import POLICY


def test_diagnostics_requires_login_and_preserves_unmanaged_subscriptions(fixture):
    client = fixture['client']; uid = fixture['uid']; token = fixture['token']
    endpoint = '/api/users/' + uid + '/subscription-diagnostics'
    client.json(endpoint, expected=401)
    client.login()
    original = {suffix: client.call('/s/' + token + suffix) for suffix in ('', '/clash.yaml', '/shadowrocket.conf')}
    result = client.json(endpoint)
    assert result['origin'] == 'https://testserver'
    assert result['last_fetch'] == result['client_enabled'] == 'unknown'
    assert result['template']['name'] == '沿用原配置'
    assert result['formats']['shadowrocket']['status'] == 'unavailable'
    nodes = result['formats']['nodes']
    assert nodes['node_count'] == len(base64.b64decode(original[''][2]).splitlines())
    assert nodes['sha256'] == hashlib.sha256(original[''][2]).hexdigest()
    clash = yaml.safe_load(original['/clash.yaml'][2])
    assert result['formats']['clash']['groups'] == [g['name'] for g in clash['proxy-groups']]
    assert result['formats']['clash']['node_count'] == len(clash['proxies'])
    assert token not in json.dumps(result) and fixture['links']['reality'] not in json.dumps(result)
    assert {suffix: client.call('/s/' + token + suffix) for suffix in original} == original
    client.json('/api/users/' + '0' * 32 + '/subscription-diagnostics', expected=404)
    client.json('/api/users/' + uid, 'PUT', {'name': '旧用户 / A+空 格', 'enabled': False})
    inactive = client.json(endpoint)
    assert inactive['user_status'] == 'disabled'
    assert all(item['status'] == 'inactive' for item in inactive['formats'].values())


@pytest.mark.parametrize('fixture', [POLICY], indirect=True)
def test_diagnostics_shows_published_template_and_shadowrocket_groups(fixture):
    c = fixture['client']; c.login(); uid = fixture['uid']; token = fixture['token']
    c.json('/api/users/' + uid + '/rule-template', 'POST', {'template_id': 'independent'})
    result = c.json('/api/users/' + uid + '/subscription-diagnostics')
    assert result['template']['name'] == '独立服务分组'
    assert result['template']['revision'] >= 1
    assert '独立 · Google' in result['formats']['clash']['groups']
    mobile = result['formats']['shadowrocket']
    assert mobile['status'] == 'ready'
    assert 'XCLI-独立 · Google' in mobile['groups']
    assert token not in json.dumps(result)
    response = c.call('/s/' + token + '/shadowrocket.conf')[2]
    assert mobile['sha256'] == hashlib.sha256(response).hexdigest()
