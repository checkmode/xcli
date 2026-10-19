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
    assert value['proxies'][0]['reality-opts']['support-x25519mlkem768'] is True
    assert value['proxy-groups'][0]['type'] == 'select'
    assert value['proxy-groups'][0]['proxies'][0] == 'HTTPS'
    assert value['rules'][-1] == 'MATCH,PROXY'
    assert value['rules'][0] == 'DOMAIN,testserver,DIRECT'
    assert value['rules'][-6:] == ['GEOSITE,private,DIRECT','GEOSITE,cn,DIRECT',
        'GEOSITE,geolocation-!cn,PROXY','GEOIP,private,DIRECT,no-resolve','GEOIP,CN,DIRECT','MATCH,PROXY']
    domestic = ['https://223.5.5.5/dns-query#DIRECT','https://1.12.12.12/dns-query#DIRECT']
    assert value['dns']['nameserver-policy']['geosite:cn,private'] == domestic
    assert value['dns']['direct-nameserver'] == domestic
    assert value['dns']['proxy-server-nameserver'] == domestic
    assert value['proxies'][1]['ws-opts'] == {'path': '/connect/test', 'headers': {'Host': 'testserver'}}
    assert value['proxies'][1]['skip-cert-verify'] is False
    assert value['dns']['nameserver'][0].endswith('#PROXY')
    c.json('/api/users/' + fixture['uid'], 'PUT', {'name': 'disabled', 'enabled': False})
    assert c.call(path)[0] == 403
    c.json('/api/users/' + fixture['uid'] + '/rotate', 'POST', {})
    assert c.call(path)[0] == 404



import json
import subprocess
import pytest
from test_http import BINARY

SERVICE_SETTINGS = {
    'hysteria2_port': 443,
    'residential_exits': [{'tag': 'residential-28', 'label': 'IPRoyal ISP 28', 'exit_ip': '8.8.4.4',
        'country': 'SG', 'ws_path': '/connect/test/residential-28', 'port': 12028, 'hysteria2': True}],
    'clash_service_routes': {'__USER_ID__': [
        {'name': 'CLAUDE', 'outbound': 'residential-28', 'domains': ['claude.ai', 'anthropic.com'], 'udp': 'reject'},
        {'name': 'GITHUB', 'outbound': 'hysteria2', 'domains': ['github.com', 'githubusercontent.com'], 'udp': 'proxy'}]}}


def subscription(fixture, token=None):
    status, _, content = fixture['client'].call('/s/' + (token or fixture['token']) + '/clash.yaml')
    assert status == 200
    return yaml.safe_load(content)


@pytest.mark.parametrize('fixture', [SERVICE_SETTINGS], indirect=True)
def test_service_routes_are_user_scoped_and_follow_identity_rotation(fixture):
    value = subscription(fixture)
    groups = {g['name']: g for g in value['proxy-groups']}
    assert groups['CLAUDE'] == {'name': 'CLAUDE', 'type': 'select', 'proxies': ['IPRoyal ISP 28 · 8.8.4.4']}
    assert groups['GITHUB']['proxies'] == ['Hysteria 2']
    assert 'CLAUDE' not in groups['PROXY']['proxies']
    rule = 'AND,((RULE-SET,service-CLAUDE),(NETWORK,UDP)),REJECT'
    assert value['rules'].index(rule) < value['rules'].index('RULE-SET,service-CLAUDE,CLAUDE')
    assert value['rules'].index('RULE-SET,service-GITHUB,GITHUB') < value['rules'].index('GEOSITE,cn,DIRECT')
    assert value['rule-providers']['service-CLAUDE'] == {
        'type': 'inline', 'behavior': 'domain', 'payload': ['+.claude.ai', '+.anthropic.com']}
    assert value['dns']['nameserver-policy']['+.claude.ai'][0].endswith('#CLAUDE')
    assert value['dns']['nameserver-policy']['+.github.com'][0].endswith('#GITHUB')
    c = fixture['client']; c.login()
    other_id = c.json('/api/users', 'POST', {'name': 'unaffected-user'})['id']
    with fixture['legacy'].db() as db:
        other_token = db.execute('SELECT token FROM users WHERE id=?', (other_id,)).fetchone()[0]
    other = subscription(fixture, other_token)
    assert 'rule-providers' not in other
    assert not any(g['name'] in ('CLAUDE', 'GITHUB') for g in other['proxy-groups'])
    assert len(other['rules']) == 11
    assert list(other['dns']['nameserver-policy']) == ['geosite:cn,private']
    # Rotate credentials, preserving the same user's routing policy.
    c.json('/api/users/' + fixture['uid'] + '/rotate', 'POST', {})
    with fixture['legacy'].db() as db:
        token = db.execute('SELECT token FROM users WHERE id=?', (fixture['uid'],)).fetchone()[0]
    assert subscription(fixture, token)['rules'] == value['rules']


@pytest.mark.parametrize('fixture', [{**SERVICE_SETTINGS, 'residential_exits': [], 'hysteria2_port': 0}], indirect=True)
def test_missing_exit_rejects_instead_of_falling_back(fixture):
    value = subscription(fixture)
    for group in value['proxy-groups']:
        if group['name'] in ('CLAUDE', 'GITHUB'):
            assert group['proxies'] == ['REJECT']
    assert 'RULE-SET,service-CLAUDE,CLAUDE' in value['rules']
    assert 'AND,((RULE-SET,service-CLAUDE),(NETWORK,UDP)),REJECT' in value['rules']


@pytest.mark.parametrize('fixture', [SERVICE_SETTINGS], indirect=True)
def test_fixed_exit_protocol_choices_keep_names_identity_and_revocation(fixture):
    import base64
    from urllib.parse import urlsplit, parse_qs, unquote
    c=fixture['client'];c.login()
    path='/api/users/'+fixture['uid']
    value=subscription(fixture)
    proxies={p['name']:p for p in value['proxies']}
    groups={g['name']:g for g in value['proxy-groups']}
    name='IPRoyal ISP 28 · 8.8.4.4'
    assert groups[name]['proxies']==[name+' · Hysteria2',name+' · HTTPS']
    assert name in groups['PROXY']['proxies'] and name in groups['住宅分组 · 新加坡']['proxies']
    assert name+' · HTTPS' not in groups['PROXY']['proxies']
    all_names=list(proxies)+list(groups)
    assert len(all_names)==len(set(all_names))
    assert all(target in all_names+['DIRECT','REJECT'] for group in groups.values() for target in group['proxies'])
    https=proxies[name+' · HTTPS'];hy2=proxies[name+' · Hysteria2']
    assert https['type']=='vless' and https['network']=='ws' and hy2['type']=='hysteria2'
    assert hy2['password']==https['uuid']+'.residential-28-hy2'
    assert https['udp'] is False and hy2['udp'] is False
    links=c.json(path+'/links')
    ws=urlsplit(links['residential-28']);hy=urlsplit(links['residential-28-hy2'])
    assert ws.scheme=='vless' and hy.scheme=='hysteria2'
    assert parse_qs(ws.query)['path']==['/connect/test/residential-28']
    assert unquote(hy.username)==ws.username+'.residential-28-hy2'
    assert unquote(ws.fragment)==unquote(hy.fragment)+' · HTTPS'
    subpath='/s/'+fixture['token']
    status,_,body=c.call(subpath)
    assert status==200 and set(base64.b64decode(body).decode().splitlines())=={
        links[k] for k in ('reality','websocket','hysteria2','residential-28','residential-28-hy2')}
    c.json(path+'/rotate','POST',{})
    assert c.call(subpath)[0]==404
    rotated=c.json(path+'/links')
    assert all(rotated[k]!=links[k] for k in ('residential-28','residential-28-hy2'))
    newpath=urlsplit(rotated['subscription']).path
    c.json(path,'PUT',{'name':'disabled','enabled':False})
    assert c.call(newpath)[0]==403 and c.call(newpath+'/clash.yaml')[0]==403


def test_invalid_service_routing_is_rejected_before_startup(fixture):
    original = json.loads((fixture['tmp'] / 'settings.json').read_text())
    service = {'name': 'CLAUDE', 'outbound': 'residential-28', 'domains': ['claude.ai'], 'udp': 'reject'}
    bad_values = [
        {**service, 'udp': 'proxy'},
        {**service, 'domains': ['claude.ai,PROXY']},
        {**service, 'name': 'PROXY'},
        {**service, 'domains': ['claude.ai', 'api.claude.ai']},
        {**service, 'outbound': 'arbitrary-display-name'},
    ]
    for index, bad in enumerate(bad_values):
        settings = fixture['tmp'] / ('invalid-' + str(index) + '.json')
        settings.write_text(json.dumps({**original, 'clash_service_routes': {fixture['uid']: [bad]}}))
        result = subprocess.run([str(BINARY), '--state', str(fixture['tmp'] / ('invalid-state-' + str(index))),
            '--settings', str(settings), '--offline', '--preflight'], capture_output=True, timeout=10)
        assert result.returncode != 0
        assert b'Clash service' in result.stderr or b'Residential service' in result.stderr
