"""Security and recovery acceptance against a real isolated HTTP process."""
import base64
import hashlib
import hmac
import json
import pathlib
import sqlite3
import struct
import subprocess
import time

from test_http import BINARY, PASSWORD, Client, fixture


def otp(secret, offset=0):
    step = int(time.time()) // 30 + offset
    digest = hmac.new(base64.b32decode(secret), struct.pack('!Q', step), hashlib.sha1).digest()
    pos = digest[-1] & 15
    return str((struct.unpack('!I', digest[pos:pos + 4])[0] & 0x7fffffff) % 1000000).zfill(6)


def login_code(c, code, expected=200):
    status, headers, content = c.call('/api/login', 'POST', {'username': 'admin', 'password': PASSWORD, 'code': code})
    assert status == expected
    if expected == 200:
        c.cookie = headers['set-cookie'].split(';')[0].split('=', 1)[1]
        c.csrf = json.loads(content)['csrf']


def enroll(c):
    setup = c.json('/api/security/setup', 'POST', {'current_password': PASSWORD})
    result = c.json('/api/security/enable', 'POST', {'current_password': PASSWORD, 'code': otp(setup['secret'])})
    return setup['secret'], result['recovery_codes']


def test_mfa_enrollment_login_replay_recovery_and_disable(fixture):
    c = fixture['client']; c.login()
    other = Client(c.port); other.login()
    assert c.json('/api/security')['enabled'] is False
    c.json('/api/security/setup', 'POST', {'current_password': 'wrong'}, expected=403)
    setup = c.json('/api/security/setup', 'POST', {'current_password': PASSWORD})
    assert setup['qr'].startswith('data:image/png;base64,')
    other.json('/api/security/enable', 'POST', {'current_password': PASSWORD, 'code': otp(setup['secret'])}, expected=409)
    c.json('/api/security/enable', 'POST', {'current_password': PASSWORD, 'code': 'invalid'}, expected=403)
    result = c.json('/api/security/enable', 'POST', {'current_password': PASSWORD, 'code': otp(setup['secret'])})
    codes = result['recovery_codes']
    assert len(codes) == len(set(codes)) == 10
    other.json('/api/session', expected=401)
    assert c.json('/api/security') == {'enabled': True, 'recovery_remaining': 10}
    with sqlite3.connect(fixture['state'] / 'gateway.sqlite') as db:
        row = db.execute('SELECT secret,pending FROM mfa').fetchone()
        assert setup['secret'] not in row[0] and row[1] == ''
        assert db.execute('SELECT hash FROM recovery_codes').fetchone()[0] not in codes
    login_code(other, '', 401)
    login_code(other, otp(setup['secret']), 401)
    login_code(other, otp(setup['secret'], 1))
    login_code(other, codes[0])
    login_code(Client(c.port), codes[0], 401)
    assert c.json('/api/security')['recovery_remaining'] == 9
    regen = c.json('/api/security/recovery', 'POST', {'current_password': PASSWORD, 'code': codes[1]})['recovery_codes']
    login_code(Client(c.port), codes[2], 401)
    c.json('/api/security/disable', 'POST', {'current_password': PASSWORD, 'code': regen[0]})
    c.json('/api/session', expected=401)
    c.login()
    assert c.json('/api/security')['enabled'] is False


def test_mfa_enrollment_expiry_and_attempt_limit(fixture):
    c = fixture['client']; c.login()
    setup = c.json('/api/security/setup', 'POST', {'current_password': PASSWORD})
    with sqlite3.connect(fixture['state'] / 'gateway.sqlite') as db:
        db.execute('UPDATE mfa SET pending_expires=0')
    c.json('/api/security/enable', 'POST', {'current_password': PASSWORD, 'code': otp(setup['secret'])}, expected=409)
    c.json('/api/security/setup', 'POST', {'current_password': PASSWORD})
    for _ in range(7):
        c.json('/api/security/enable', 'POST', {'current_password': PASSWORD, 'code': 'invalid'}, expected=403)
    c.json('/api/security/enable', 'POST', {'current_password': PASSWORD, 'code': 'invalid'}, expected=429)


def test_encrypted_backup_restore_preserves_auth_usage_and_addresses(fixture):
    c = fixture['client']; c.login()
    original_links = c.json('/api/users/' + fixture['uid'] + '/links')
    backup = c.json('/api/backups', 'POST', {})
    path = fixture['state'] / 'backups' / backup['id']
    assert path.stat().st_mode & 0o777 == 0o600
    raw = path.read_bytes()
    assert raw.startswith(b'XGB1') and b'SQLite format' not in raw and fixture['token'].encode() not in raw
    assert c.call('/api/backups/' + backup['id'] + '/download')[2] == raw
    assert c.json('/api/backups/' + backup['id'] + '/inspect')['same_server']
    new_id = c.json('/api/users', 'POST', {'name': 'after-backup'})['id']
    c.json('/api/users/' + fixture['uid'], 'PUT', {'name': 'changed-name'})
    _, codes = enroll(c)
    with sqlite3.connect(fixture['state'] / 'gateway.sqlite') as db:
        db.execute('UPDATE users SET upload=8000,download=9000 WHERE id=?', (fixture['uid'],))
        current_mfa = db.execute('SELECT secret FROM mfa').fetchone()[0]
    body = {'id': backup['id'], 'confirm': backup['id'], 'current_password': PASSWORD, 'code': codes[0]}
    c.json('/api/backups/restore', 'POST', dict(body, confirm='wrong'), expected=422)
    c.json('/api/backups/restore', 'POST', dict(body, current_password='wrong'), expected=403)
    c.json('/api/backups/restore', 'POST', body)
    c.json('/api/session', expected=401)
    login_code(c, codes[1])
    assert c.json('/api/users/' + fixture['uid'] + '/links') == original_links
    c.json('/api/users/' + new_id + '/links', expected=404)
    overview = c.json('/api/overview')
    assert len(overview['users']) == 1 and overview['users'][0]['upload'] == 8000 and overview['users'][0]['download'] == 9000
    with sqlite3.connect(fixture['state'] / 'gateway.sqlite') as db:
        assert db.execute('SELECT secret FROM mfa').fetchone()[0] == current_mfa
    assert any(b['reason'] == 'before-restore' for b in c.json('/api/backups')['backups'])
    login_code(Client(c.port), codes[0], 401)


def test_backup_auth_tamper_and_offline_extraction(fixture):
    c = fixture['client']; c.login()
    backup = c.json('/api/backups', 'POST', {})
    path = fixture['state'] / 'backups' / backup['id']
    anonymous = Client(c.port)
    anonymous.json('/api/backups', expected=401)
    assert anonymous.call('/api/backups/' + backup['id'] + '/download')[0] == 401
    c.json('/api/backups', 'POST', {}, headers={'X-CSRF-Token': 'wrong'}, expected=403)
    destination = fixture['tmp'] / 'extracted'
    result = subprocess.run([str(BINARY), '--extract-backup', str(path), '--secret-key', str(fixture['state'] / 'security.key'), '--destination', str(destination)], capture_output=True)
    assert result.returncode == 0, result.stderr
    with sqlite3.connect(destination / 'gateway.sqlite') as db:
        assert db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
        assert db.execute('SELECT token FROM users').fetchone()[0] == fixture['token']
        assert db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0] == 0
    assert (destination / 'security.key').read_bytes() == (fixture['state'] / 'security.key').read_bytes()
    assert destination.stat().st_mode & 0o777 == 0o700
    bad = bytearray(path.read_bytes()); bad[-1] ^= 1; path.write_bytes(bad)
    c.json('/api/backups/' + backup['id'] + '/inspect', expected=503)
    c.json('/api/backups/restore', 'POST', {'id': backup['id'], 'confirm': backup['id'], 'current_password': PASSWORD}, expected=503)
    assert c.json('/api/overview')['users'][0]['id'] == fixture['uid']
    assert any(not b['valid'] for b in c.json('/api/backups')['backups'])


def test_automatic_backup_initial_run_and_schedule(fixture):
    c = fixture['client']; c.login()
    for _ in range(30):
        state = c.json('/api/backups')
        if state['backups']:
            break
        time.sleep(.1)
    assert state['automatic'] and state['interval'] == 21600 and state['retention'] == 28
    assert state['backups'][0]['reason'] == 'automatic'
    assert state['next_backup'] - state['last_backup'] == 21600


def test_monitor_fresh_stale_corrupt_and_no_credentials(fixture):
    c = fixture['client']; c.login()
    report = fixture['tmp'] / 'report.json'
    assert c.json('/api/overview')['monitor']['status'] == 'unknown'
    payload = {'schema': 1, 'scope': 'server', 'updated': int(time.time()), 'status': 'healthy', 'secret': 'do-not-expose',
               'checks': [{'transport': kind, 'status': 'healthy', 'https_ms': 100, 'udp_ms': 50, 'uuid': 'do-not-expose'}
                          for kind in ('reality', 'websocket')]}
    report.write_text(json.dumps(payload))
    value = c.json('/api/overview')['monitor']
    assert value['status'] == 'healthy' and 'do-not-expose' not in json.dumps(value)
    payload['updated'] -= 181; report.write_text(json.dumps(payload))
    assert c.json('/api/overview')['monitor']['status'] == 'stale'
    report.write_text('{bad')
    assert c.json('/api/overview')['monitor']['status'] == 'unknown'
