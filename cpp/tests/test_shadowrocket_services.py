"""Per-user profiles inherit, rather than replace, a Shadowrocket base config."""
import json
import subprocess

import pytest
from test_http import Client, fixture, BINARY
from test_clash import SERVICE_SETTINGS

SETTINGS = {**SERVICE_SETTINGS, 'shadowrocket_service_users': ['__USER_ID__']}


def module(fixture, token=None):
    return Client(fixture['client'].port).call('/s/' + (token or fixture['token']) + '/shadowrocket.conf')


@pytest.mark.parametrize('fixture', [SETTINGS], indirect=True)
def test_private_module_preserves_base_and_binds_exact_credentials(fixture):
    c = fixture['client']; c.login()
    status, headers, body = module(fixture)
    text = body.decode()
    assert status == 200 and headers['cache-control'] == 'no-store'
    assert headers['content-type'] == 'text/plain; charset=utf-8'
    setup = c.json('/s/' + fixture['token'] + '/shadowrocket.json')
    assert setup == {'service_routing': True, 'resource': '/s/' + fixture['token'] + '/shadowrocket.conf'}
    assert text.count('[General]') == text.count('[Proxy]') == text.count('[Proxy Group]') == text.count('[Rule]') == 1
    assert '[Host]' not in text and 'dns-server' not in text and 'FINAL,' not in text
    assert 'include = default.conf\n' in text
    assert 'update-url = https://testserver/s/' + fixture['token'] + '/shadowrocket.conf\n' in text
    assert c.json('/api/users/' + fixture['uid'] + '/shadowrocket')['shadowrocket'] == 'shadowrocket://config/add/https://testserver/s/' + fixture['token'] + '/shadowrocket.conf'
    assert 'udp-policy-not-supported-behaviour = REJECT' in text
    with fixture['legacy'].db() as db:
        uuid = db.execute('SELECT uuid FROM users WHERE id=?', (fixture['uid'],)).fetchone()[0]
    for name, auth, udp in [('CLAUDE', uuid + '.residential-28-hy2', '0'), ('GITHUB', uuid, '1')]:
        node = 'XCLI-' + name + '-' + fixture['uid'][:8]
        assert node + ' = hysteria2,203.0.113.2,443,auth=' + auth + ',peer=testserver,udp=' + udp in text
        assert 'XCLI-' + name + ' = select,' + node + '\n' in text
    for host in ('claude.ai', 'anthropic.com'):
        assert text.index('AND,((DOMAIN-SUFFIX,' + host + '),(PROTOCOL,UDP)),REJECT') < text.index('DOMAIN-SUFFIX,' + host + ',XCLI-CLAUDE')
    assert 'DOMAIN-SUFFIX,github.com,XCLI-GITHUB' in text
    assert 'fallback' not in text and ',PROXY' not in text and ',DIRECT' not in text
    other = c.json('/api/users', 'POST', {'name': 'other'})['id']
    with fixture['legacy'].db() as db:
        other_token = db.execute('SELECT token FROM users WHERE id=?', (other,)).fetchone()[0]
    assert module(fixture, other_token)[0] == 404
    assert c.json('/s/' + other_token + '/shadowrocket.json') == {'service_routing': False, 'resource': '/shadowrocket-dns.sgmodule'}
    c.json('/api/users/' + fixture['uid'] + '/rotate', 'POST', {})
    assert module(fixture)[0] == 404
    with fixture['legacy'].db() as db:
        token = db.execute('SELECT token FROM users WHERE id=?', (fixture['uid'],)).fetchone()[0]
    assert module(fixture, token)[0] == 200
    assert uuid.encode() not in module(fixture, token)[2]
    c.json('/api/users/' + fixture['uid'], 'PUT', {'name': 'disabled', 'enabled': False})
    assert module(fixture, token)[0] == 403
    assert c.call('/s/' + token + '/shadowrocket.json')[0] == 403


@pytest.mark.parametrize('fixture', [{**SETTINGS, 'hysteria2_port': 0, 'residential_exits': []}], indirect=True)
def test_missing_nodes_reject_instead_of_using_home_selection(fixture):
    status, _, body = module(fixture)
    text = body.decode()
    assert status == 200
    assert 'XCLI-CLAUDE = select,REJECT' in text
    assert 'XCLI-GITHUB = select,REJECT' in text
    assert ' = hysteria2,' not in text
    assert 'DOMAIN-SUFFIX,claude.ai,XCLI-CLAUDE' in text


def test_disabled_by_default_and_invalid_opt_in_rejected(fixture):
    assert module(fixture)[0] == 404
    original = json.loads((fixture['tmp'] / 'settings.json').read_text())
    for index, enabled in enumerate([['f' * 32], ['bad'], {}, 'all']):
        settings = fixture['tmp'] / ('bad-shadow-' + str(index) + '.json')
        settings.write_text(json.dumps({**original, 'shadowrocket_service_users': enabled}))
        result = subprocess.run([str(BINARY), '--state', str(fixture['tmp'] / ('bad-state-' + str(index))),
            '--settings', str(settings), '--offline', '--preflight'], capture_output=True, timeout=10)
        assert result.returncode != 0
