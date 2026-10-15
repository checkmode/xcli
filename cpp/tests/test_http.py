"""Run the real C++ HTTP server against disposable copies of the legacy schema."""
import base64
import concurrent.futures
import contextlib
import hashlib
import http.client
import importlib.util
import json
import os
import pathlib
import re
import shutil
import socket
import sqlite3
import subprocess
import time
import uuid
from urllib.parse import parse_qs, urlsplit

import pytest

BINARY = pathlib.Path(os.environ['XG_TEST_BINARY']).resolve()
LEGACY = pathlib.Path(os.environ.get('XG_LEGACY_APP', '/opt/xray-gateway/app.py')).resolve()
PASSWORD = 'compatibility-test-password'
ORIGIN = 'https://testserver'


def available_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Client:
    def __init__(self, port):
        self.port = port
        self.cookie = ''
        self.csrf = ''

    def call(self, path, method='GET', data=None, headers=None, raw=None):
        values = {'Host': 'testserver', 'Origin': ORIGIN}
        if self.cookie:
            values['Cookie'] = 'xg_session=' + self.cookie
        if self.csrf:
            values['X-CSRF-Token'] = self.csrf
        payload = raw
        if data is not None:
            payload = json.dumps(data, ensure_ascii=False).encode()
            values['Content-Type'] = 'application/json'
        values.update(headers or {})
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=20)
        try:
            conn.request(method, path, body=payload, headers=values)
            response = conn.getresponse()
            content = response.read()
            return response.status, dict((k.lower(), v) for k, v in response.getheaders()), content
        finally:
            conn.close()

    def json(self, path, method='GET', data=None, expected=200, headers=None):
        status, _, content = self.call(path, method, data, headers)
        assert status == expected, (path, status, content[:100])
        return json.loads(content)

    def login(self, password=PASSWORD):
        status, headers, content = self.call('/api/login', 'POST', {'username': 'admin', 'password': password})
        assert status == 200
        self.cookie = headers['set-cookie'].split(';')[0].split('=', 1)[1]
        self.csrf = json.loads(content)['csrf']
        return headers


@pytest.fixture
def fixture(tmp_path, monkeypatch, request):
    spec = importlib.util.spec_from_file_location('legacy_xg_test', LEGACY)
    legacy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(legacy)
    state = tmp_path / 'state'
    settings = tmp_path / 'settings.json'
    settings.write_text(json.dumps({'origin': ORIGIN, 'domain': 'testserver', 'public_ip': '203.0.113.2',
        'reality_sni': 'example.com', 'reality_public': 'p' * 43, 'short_id': 'aabbccdd', 'ws_path': '/connect/test'}))
    settings.chmod(0o600)
    monkeypatch.setattr(legacy, 'STATE', state)
    monkeypatch.setattr(legacy, 'SETTINGS', settings)
    legacy.init_db()
    uid = uuid.uuid4().hex
    token = 't' * 43
    old_cookie = 'c' * 43
    old_csrf = 'f' * 43
    with legacy.db() as db:
        db.execute('INSERT INTO admin VALUES(1,?)', (legacy.password_hash(PASSWORD),))
        db.execute('INSERT INTO users(id,name,uuid,token,upload,download,created) VALUES(?,?,?,?,?,?,?)',
            (uid, '旧用户 / A+空 格', str(uuid.uuid4()), token, 123, 456, int(time.time())))
        db.execute('INSERT INTO sessions VALUES(?,?,?)', (hashlib.sha256(old_cookie.encode()).hexdigest(), old_csrf, int(time.time()) + 1000))
        old_user = legacy.get_user(db, uid)
        original_links = legacy.links(old_user)
    settings_override = getattr(request, 'param', None)
    if settings_override:
        override = json.loads(json.dumps(settings_override).replace('__USER_ID__', uid))
        current_settings = json.loads(settings.read_text())
        current_settings.update(override)
        settings.write_text(json.dumps(current_settings))
    port = available_port()
    log = (tmp_path / 'server.log').open('wb')
    process = subprocess.Popen([str(BINARY), '--state', str(state), '--settings', str(settings),
        '--static', str(LEGACY.parent / 'static'), '--port', str(port), '--offline', '--monitor-report', str(tmp_path / 'report.json')], stdout=log, stderr=log)
    client = Client(port)
    try:
        for _ in range(100):
            assert process.poll() is None, (tmp_path / 'server.log').read_text()
            try:
                if client.call('/healthz')[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(.05)
        else:
            raise RuntimeError('C++ server did not become ready')
        yield dict(client=client, state=state, uid=uid, token=token, legacy=legacy, old_cookie=old_cookie,
                   old_csrf=old_csrf, links=original_links, process=process, tmp=tmp_path)
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        log.close()
        assert process.returncode == 0, (tmp_path / 'server.log').read_text()[-4000:]


def test_old_password_cookie_and_subscription_are_compatible(fixture):
    c = fixture['client']
    c.cookie, c.csrf = fixture['old_cookie'], fixture['old_csrf']
    assert c.json('/api/session')['csrf'] == fixture['old_csrf']
    assert c.json('/api/users/' + fixture['uid'] + '/links') == fixture['links']
    status, headers, content = c.call('/s/' + fixture['token'])
    expected = fixture['links']['reality'] + '\n' + fixture['links']['websocket'] + '\n'
    assert status == 200 and base64.b64decode(content).decode() == expected
    assert headers['subscription-userinfo'] == 'upload=123; download=456; total=0; expire=0'
    assert headers['profile-update-interval'] == '6'
    overview = c.json('/api/overview')
    assert overview['users'][0]['name'] == '旧用户 / A+空 格'
    assert overview['totals'] == {'upload': 123, 'download': 456}
    assert not {'uuid', 'token'} & overview['users'][0].keys()
    c.json('/api/users/' + fixture['uid'], 'PUT', {'name': '改名', 'quota': 1000})
    with sqlite3.connect(fixture['state'] / 'gateway.sqlite') as db:
        user = db.execute('SELECT token,upload,download FROM users WHERE id=?', (fixture['uid'],)).fetchone()
        assert user == (fixture['token'], 123, 456)
    headers = c.login()
    assert all(part in headers['set-cookie'] for part in ('HttpOnly', 'Secure', 'SameSite=Strict', 'Max-Age=28800', 'Path=/'))


def test_authentication_origin_csrf_and_input_validation(fixture):
    c = fixture['client']
    c.json('/api/overview', expected=401)
    c.login()
    c.json('/api/users', 'POST', {'name': 'x'}, expected=403, headers={'Origin': 'https://evil.test'})
    c.json('/api/users', 'POST', {'name': 'x'}, expected=403, headers={'X-CSRF-Token': 'wrong'})
    for data in ({'name': ''}, {'name': ' 　'}, {'name': 'x\nq'}, {'name': 'x', 'quota': -1},
                 {'name': 'x', 'quota': 10**17}, {'name': 'x', 'expires': 4102444801},
                 {'name': 'x', 'enabled': []}, {'name': 'x', 'command': 'invalid'}, {'name': '名' * 61}):
        c.json('/api/users', 'POST', data, expected=422)
    assert c.call('/api/users', 'POST', raw=b'{')[0] == 422
    assert c.call('/api/users', 'POST', raw=b'x' * 17000)[0] == 413
    uid = c.json('/api/users', 'POST', {'name': '　中文用户名　'})['id']
    assert next(u for u in c.json('/api/overview')['users'] if u['id'] == uid)['name'] == '中文用户名'


def test_user_update_rotate_delete_and_quota(fixture):
    c = fixture['client']
    c.login()
    uid = c.json('/api/users', 'POST', {'name': 'test'})['id']
    path = '/api/users/' + uid
    original = c.json(path + '/links')
    subscription_path = original['subscription'].replace(ORIGIN, '')
    assert c.call(subscription_path)[0] == 200
    c.json(path, 'PUT', {'name': 'renamed', 'quota': 1000})
    assert c.json(path + '/links')['subscription'] == original['subscription']
    c.json(path, 'PUT', {'name': 'expired', 'expires': int(time.time()) - 1})
    c.json(subscription_path, expected=403)
    c.json(path, 'PUT', {'name': 'disabled', 'enabled': False})
    c.json(subscription_path, expected=403)
    c.json(path, 'PUT', {'name': 'active'})
    c.json(path + '/rotate', 'POST', {})
    c.json(subscription_path, expected=404)
    new = c.json(path + '/links')
    assert new['subscription'] != original['subscription'] and new['reality'] != original['reality']
    c.json(path, 'DELETE')
    c.json(path + '/links', expected=404)
    assert c.call(new['subscription'].replace(ORIGIN, ''))[0] == 404


def test_password_change_invalidates_all_sessions(fixture):
    c = fixture['client']
    c.login()
    second = Client(c.port)
    second.login()
    c.json('/api/password', 'POST', {'current_password': 'wrong', 'new_password': 'changed-safe-password'}, expected=403)
    c.json('/api/password', 'POST', {'current_password': PASSWORD, 'new_password': 'changed-safe-password'})
    c.json('/api/session', expected=401)
    second.json('/api/session', expected=401)
    c.login('changed-safe-password')
    # The hash remains readable by the old Python backend for rollback.
    with fixture['legacy'].db() as db:
        value = db.execute('SELECT password FROM admin WHERE id=1').fetchone()[0]
    assert fixture['legacy'].password_check('changed-safe-password', value)


def test_logout_and_expired_session(fixture):
    c = fixture['client']
    c.login()
    c.json('/api/logout', 'POST', {})
    c.json('/api/session', expected=401)
    c.cookie = fixture['old_cookie']
    with sqlite3.connect(fixture['state'] / 'gateway.sqlite') as db:
        db.execute('UPDATE sessions SET expires=0')
    c.json('/api/session', expected=401)


def test_login_rate_limit_and_proxy_address(fixture):
    c = fixture['client']
    for _ in range(8):
        c.json('/api/login', 'POST', {'username': 'admin', 'password': 'wrong'}, expected=401, headers={'X-Forwarded-For': '192.0.2.3'})
    c.json('/api/login', 'POST', {'username': 'admin', 'password': PASSWORD}, expected=429, headers={'X-Forwarded-For': '192.0.2.3'})
    c.login()


def test_static_and_error_security_headers(fixture):
    c = fixture['client']
    for path in ('/', '/static/app.js', '/static/runtime.js', '/static/style.css', '/client/shadowrocket',
                 '/static/shadowrocket.js', '/static/shadowrocket.css', '/shadowrocket-dns.sgmodule',
                 '/healthz', '/docs', '/api/overview', '/static/../app.py'):
        status, headers, body = c.call(path)
        assert headers['x-frame-options'] == 'DENY'
        assert headers['x-content-type-options'] == 'nosniff'
        assert headers['cache-control'] == 'no-store'
        assert "script-src 'self'" in headers['content-security-policy']
    assert c.call('/docs')[0] == 404
    assert c.call('/static/../app.py')[0] == 404
    assert c.call('/')[2] == (LEGACY.parent / 'static/index.html').read_bytes()
    assert c.call('/static/app.js')[2] == (LEGACY.parent / 'static/app.js').read_bytes()


def test_qr_png_decodes_to_existing_links(fixture):
    c = fixture['client']
    c.login()
    decoder = shutil.which('zbarimg')
    assert decoder, 'Install zbar-tools for QR interoperability verification'
    for kind, link in fixture['links'].items():
        status, headers, png = c.call('/api/users/' + fixture['uid'] + '/qr/' + kind)
        assert status == 200 and headers['content-type'] == 'image/png' and png[:8] == b'\x89PNG\r\n\x1a\n'
        path = fixture['tmp'] / (kind + '.png')
        path.write_bytes(png)
        decoded = subprocess.check_output([decoder, '--quiet', '--raw', str(path)], stderr=subprocess.DEVNULL)
        assert decoded.decode().rstrip('\n') == link


def test_shadowrocket_import_qr_preserves_subscription_and_hides_token_from_page_request(fixture):
    c = fixture['client']
    path = '/api/users/' + fixture['uid']
    c.json(path + '/shadowrocket', expected=401)
    c.json(path + '/qr/shadowrocket', expected=401)
    c.json(path + '/qr/dns', expected=401)
    c.login()
    links = c.json(path + '/shadowrocket')
    page = urlsplit(links['shadowrocket'])
    assert page.scheme == 'https' and page.netloc == 'testserver'
    assert page.path == '/client/shadowrocket' and page.query == ''
    assert page.fragment == fixture['token']
    assert links['dns'] == ORIGIN + '/shadowrocket-dns.sgmodule'
    assert parse_qs(urlsplit(links['dns_install']).query)['module'] == [links['dns']]
    assert c.json(path + '/links') == fixture['links']
    decoder = shutil.which('zbarimg')
    assert decoder, 'Install zbar-tools for QR interoperability verification'
    for kind, expected in (('shadowrocket', links['shadowrocket']), ('dns', links['dns_install'])):
        status, headers, png = c.call(path + '/qr/' + kind)
        assert status == 200 and headers['content-type'] == 'image/png'
        image = fixture['tmp'] / (kind + '.png')
        image.write_bytes(png)
        decoded = subprocess.check_output([decoder, '--quiet', '--raw', str(image)], stderr=subprocess.DEVNULL)
        assert decoded.decode().rstrip('\n') == expected
    c.json(path + '/rotate', 'POST', {})
    c.json('/s/' + page.fragment, expected=404)
    assert c.json(path + '/shadowrocket')['shadowrocket'] != links['shadowrocket']


def test_public_shadowrocket_module_only_overrides_dns_and_this_server_host(fixture):
    c = fixture['client']
    status, _, page = c.call('/client/shadowrocket')
    assert status == 200 and '安装 DNS 模块' in page.decode()
    assert fixture['token'].encode() not in page
    status, headers, content = c.call('/shadowrocket-dns.sgmodule')
    assert status == 200 and headers['content-type'] == 'text/plain; charset=utf-8'
    assert fixture['token'].encode() not in content
    assert fixture['uid'].encode() not in content
    sections = {}
    for line in content.decode().splitlines():
        if line.startswith('['):
            section = line[1:-1]
            assert section not in sections
            sections[section] = {}
        elif line and not line.startswith('#'):
            key, value = line.split('=', 1)
            assert key.strip() not in sections[section]
            sections[section][key.strip()] = value.strip()
    assert set(sections) == {'General', 'Host'}
    assert sections['General'] == {
        'dns-server': 'https://1.1.1.1/dns-query#proxy',
        'fallback-dns-server': 'https://1.0.0.1/dns-query#proxy',
        'dns-direct-system': 'false', 'hijack-dns': ':53',
        'udp-policy-not-supported-behaviour': 'REJECT'}
    assert sections['Host'] == {'testserver': '203.0.113.2'}


def test_no_descriptor_growth_after_2000_http_queries(fixture):
    c = fixture['client']
    c.login()
    proc = pathlib.Path('/proc') / str(fixture['process'].pid) / 'fd'
    initial = len(list(proc.iterdir()))
    def query(_):
        assert c.call('/api/overview')[0] == 200
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(query, range(2000)))
    time.sleep(.2)
    assert len(list(proc.iterdir())) <= initial + 2
    assert fixture['process'].poll() is None


def test_second_instance_cannot_share_http_port(fixture):
    c = fixture['client']
    result = subprocess.run([str(BINARY), '--state', str(fixture['state']), '--settings', str(fixture['tmp'] / 'settings.json'),
        '--static', str(LEGACY.parent / 'static'), '--port', str(c.port), '--offline'], capture_output=True, timeout=10)
    assert result.returncode != 0
    assert b'Cannot bind management port' in result.stderr
    assert c.call('/healthz')[0] == 200
