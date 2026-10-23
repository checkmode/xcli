import base64,json,sqlite3,time,uuid
import pytest
from fastapi.testclient import TestClient
import app

@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setattr(app,'STATE',tmp_path)
    settings=tmp_path/'settings.json';settings.write_text(json.dumps({'origin':'https://testserver','domain':'testserver','public_ip':'203.0.113.2','reality_sni':'example.com','reality_public':'p'*43,'short_id':'aabbccdd','ws_path':'/connect/test'}));monkeypatch.setattr(app,'SETTINGS',settings)
    app.init_db();app.RATE.clear()
    with app.db() as c:c.execute('INSERT INTO admin VALUES(1,?)',(app.password_hash('correct-password-for-tests'),))
    return TestClient(app.app,base_url='https://testserver')

def login(c):
    r=c.post('/api/login',json={'username':'admin','password':'correct-password-for-tests'},headers={'Origin':'https://testserver'})
    assert r.status_code==200
    return {'Origin':'https://testserver','X-CSRF-Token':r.json()['csrf']}

def create(c,h,**extra):
    r=c.post('/api/users',json={'name':'test user',**extra},headers=h);assert r.status_code==200;return r.json()['id']

def test_auth_and_csrf(client):
    assert client.get('/api/overview').status_code==401
    h=login(client)
    assert 'HttpOnly' in client.cookies.jar._cookies['testserver.local']['/']['xg_session']._rest
    assert client.post('/api/users',json={'name':'x'},headers={'Origin':'https://evil.test'}).status_code==403
    assert client.post('/api/users',json={'name':'x'},headers={'Origin':'https://testserver'}).status_code==403
    uid=create(client,h)
    r=client.get('/api/overview');assert r.status_code==200
    assert 'uuid' not in r.json()['users'][0] and 'token' not in r.json()['users'][0]

def test_admin_origin_compatibility(client):
    headers=login(client);uid=create(client,headers)
    before=client.get(f'/api/users/{uid}/links').json()
    settings=app.config();settings['admin_origin']='https://admin.testserver'
    app.SETTINGS.write_text(json.dumps(settings))
    assert client.get('/api/session').status_code==200
    assert client.post('/api/users',json={'name':'old-origin'},headers=headers).status_code==403
    headers['Origin']='https://admin.testserver'
    assert client.post('/api/users',json={'name':'new-origin'},headers=headers).status_code==200
    assert client.get(f'/api/users/{uid}/links').json()==before
    assert client.get(before['subscription']).status_code==200

@pytest.mark.parametrize('origin',['http://admin.testserver','https://admin.testserver/','https://user:pass@admin.testserver','https://admin.testserver:0','https://admin.testserver:65536','https://bad..example',None])
def test_admin_origin_rejects_non_origin_values(client,origin):
    settings=app.config();settings['admin_origin']=origin
    app.SETTINGS.write_text(json.dumps(settings))
    with pytest.raises(ValueError):app.config()

def test_admin_origin_normalizes_default_port(client):
    settings=app.config();settings['admin_origin']='https://admin.testserver:0443'
    app.SETTINGS.write_text(json.dumps(settings))
    assert app.config()['admin_origin']=='https://admin.testserver'

def test_subscription_rotation_disable_and_delete(client):
    h=login(client);uid=create(client,h)
    old=client.get(f'/api/users/{uid}/links').json();r=client.get(old['subscription']);assert r.status_code==200
    raw=base64.b64decode(r.content).decode();assert raw.count('vless://')==2 and 'security=reality' in raw and 'type=ws' in raw
    assert 'subscription-userinfo' in r.headers
    assert client.get(f'/api/users/{uid}/qr/reality').content[:8]==b'\x89PNG\r\n\x1a\n'
    assert client.post(f'/api/users/{uid}/rotate',json={},headers=h).status_code==200
    assert client.get(old['subscription']).status_code==404
    new=client.get(f'/api/users/{uid}/links').json();assert new['reality']!=old['reality']
    assert client.put(f'/api/users/{uid}',json={'name':'disabled','enabled':False},headers=h).status_code==200
    assert client.get(new['subscription']).status_code==403
    assert client.delete(f'/api/users/{uid}',headers=h).status_code==200
    assert client.get(f'/api/users/{uid}/links').status_code==404
    assert client.get('/api/overview').json()['users']==[]

def test_password_rotation_invalidates_all_sessions(client):
    h=login(client)
    assert client.post('/api/password',json={'current_password':'wrong','new_password':'new-secure-password'},headers=h).status_code==403
    assert client.post('/api/password',json={'current_password':'correct-password-for-tests','new_password':'new-secure-password'},headers=h).status_code==200
    assert client.get('/api/session').status_code==401

def test_rate_limit_and_schema(client):
    for _ in range(8): assert client.post('/api/login',json={'username':'admin','password':'wrong'},headers={'Origin':'https://testserver'}).status_code==401
    assert client.post('/api/login',json={'username':'admin','password':'wrong'},headers={'Origin':'https://testserver'}).status_code==429
    app.RATE.clear();h=login(client)
    assert client.post('/api/users',json={'name':'x','quota':-1},headers=h).status_code==422
    assert client.post('/api/users',json={'name':'x','command':'evil'},headers=h).status_code==422
    assert client.post('/api/users',json={'name':'   '},headers=h).status_code==422

def test_expiry_and_quota(client):
    h=login(client);uid=create(client,h,expires=int(time.time())-1)
    link=client.get(f'/api/users/{uid}/links').json()['subscription'];assert client.get(link).status_code==403
    with app.db() as c:c.execute('UPDATE users SET expires=0,quota=100,upload=100 WHERE id=?',(uid,))
    assert client.get(link).status_code==403

def test_counter_persistence_and_restart(client,monkeypatch):
    h=login(client);uid=create(client,h)
    with app.db() as c:u=app.get_user(c,uid)
    name=f"user>>>{uid}.{u['uuid'][:8]}@reality>>>traffic>>>uplink"
    value=100
    monkeypatch.setattr(app,'xapi',lambda *args:json.dumps({'stat':[{'name':name,'value':value}]}))
    with app.db() as c:app.sample_stats(c,'gen1')
    with app.db() as c:app.sample_stats(c,'gen1')
    value=180
    with app.db() as c:app.sample_stats(c,'gen1')
    value=250
    with app.db() as c:app.sample_stats(c,'gen2')
    with app.db() as c:assert app.get_user(c,uid)['upload']==430

def test_revoke_restarts_existing_connections(client,monkeypatch):
    calls=[]
    monkeypatch.setattr(app,'live_users',lambda tag:{'stale-user':{}} if tag=='reality' else {})
    monkeypatch.setattr(app,'restart_core',lambda:calls.append('restart'))
    with app.db() as c:assert app.reconcile(c) is False
    assert calls==['restart']

def test_security_headers(client):
    r=client.get('/');assert r.headers['x-frame-options']=='DENY'
    assert "script-src 'self'" in r.headers['content-security-policy']
    assert r.headers['cache-control']=='no-store'
    assert client.get('/docs').status_code==404

def test_database_transaction_and_connection_lifetime(tmp_path,monkeypatch):
    monkeypatch.setattr(app,'STATE',tmp_path)
    app.init_db()
    with app.db() as committed:
        committed.execute("INSERT INTO metadata VALUES('committed','yes')")
    with pytest.raises(sqlite3.ProgrammingError,match='closed'):
        committed.execute('SELECT 1')
    with pytest.raises(RuntimeError,match='abort'):
        with app.db() as rolled_back:
            rolled_back.execute("INSERT INTO metadata VALUES('rolled-back','no')")
            raise RuntimeError('abort')
    with pytest.raises(sqlite3.ProgrammingError,match='closed'):
        rolled_back.execute('SELECT 1')
    with app.db() as c:
        assert [tuple(r) for r in c.execute('SELECT * FROM metadata')]==[('committed','yes')]

def test_database_descriptors_do_not_accumulate(tmp_path,monkeypatch):
    import gc
    import os
    from pathlib import Path
    fd_dir=Path('/proc/self/fd')
    if not fd_dir.is_dir(): pytest.skip('Linux descriptor regression test')
    monkeypatch.setattr(app,'STATE',tmp_path)
    app.init_db();gc.collect()
    initial=len(os.listdir(fd_dir));was_enabled=gc.isenabled();gc.disable()
    retained=[]
    try:
        for _ in range(2000):
            with app.db() as c:
                assert c.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0
            retained.append(c)  # Do not let garbage collection hide a leak.
        assert len(os.listdir(fd_dir))<=initial+2
    finally:
        for c in retained:c.close()
        if was_enabled:gc.enable()
