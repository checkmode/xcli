"""Clash export endpoints through the authenticated HTTP server."""

import yaml
from test_http import Client, fixture


def test_clash_export_and_revocation(fixture):
    c = fixture['client']
    c.login()
    links = c.json('/api/users/' + fixture['uid'] + '/shadowrocket')
    path = '/s/' + fixture['token'] + '/clash.yaml'
    assert links['clash'].endswith(path)
    assert links['clash_install'].startswith('clash://install-config?url=')
    status, headers, content = Client(c.port).call(path)
    assert status == 200 and 'yaml' in headers['content-type']
    assert headers['subscription-userinfo'] == 'upload=123; download=456; total=0; expire=0'
    (fixture['tmp'] / 'clash.yaml').write_bytes(content)
    value = yaml.safe_load(content)
    assert len(value['proxies']) == 2
    assert value['proxy-groups'][0]['type'] == 'select'
    assert value['rules'][-1] == 'MATCH,PROXY'
    assert value['proxies'][1]['ws-opts'] == {'path': '/connect/test', 'headers': {'Host': 'testserver'}}
    assert value['proxies'][1]['skip-cert-verify'] is False
    assert value['dns']['nameserver'][0].endswith('#PROXY')
    c.json('/api/users/' + fixture['uid'], 'PUT', {'name': 'disabled', 'enabled': False})
    assert c.call(path)[0] == 403
    c.json('/api/users/' + fixture['uid'] + '/rotate', 'POST', {})
    assert c.call(path)[0] == 404

