"""Authenticated operations APIs against the real, disposable C++ server."""
import json
import sqlite3
import time

from test_http import PASSWORD, Client, fixture


def test_notification_configuration_auth_redaction_and_validation(fixture):
    c=fixture['client'];c.login()
    anonymous=Client(c.port)
    anonymous.json('/api/notifications',expected=401)
    anonymous.json('/api/history',expected=401)
    state=c.json('/api/notifications')
    assert not state['enabled'] and not state['configured']
    c.json('/api/notifications/test','POST',{},expected=409)
    payload={'url':'https://receiver.example.net/hook?key=private-url-key','bearer':'private-header-token',
             'signing_secret':'private-signing-secret','enabled':False,'current_password':PASSWORD}
    c.json('/api/notifications','PUT',payload,headers={'X-CSRF-Token':'wrong'},expected=403)
    c.json('/api/notifications','PUT',dict(payload,current_password='wrong'),expected=403)
    for url in ['http://receiver.example.net','https://127.0.0.1/','https://[::ffff:127.0.0.1]/',
                'https://169.254.169.254/latest/meta-data','https://user:pass@example.net/',
                'https://example.net/#credential','https://localhost/','file:///etc/passwd']:
        c.json('/api/notifications','PUT',dict(payload,url=url),expected=422)
    c.json('/api/notifications','PUT',dict(payload,bearer='bad\r\nX-Test: bad'),expected=422)
    c.json('/api/notifications','PUT',dict(payload,failures=0),expected=422)
    c.json('/api/notifications','PUT',dict(payload,enabled='true'),expected=422)
    c.json('/api/notifications','PUT',payload)
    state=c.json('/api/notifications')
    assert state['configured'] and not state['enabled']
    assert state['destination']=='receiver.example.net' and state['has_bearer'] and state['has_signing_secret']
    assert 'private-' not in json.dumps(state)
    with sqlite3.connect(fixture['state']/'gateway.sqlite') as db:
        stored=db.execute('SELECT url,bearer,signing FROM notification_config').fetchone()
        assert all('private-' not in value for value in stored)
    c.json('/api/notifications','PUT',{'enabled':False,'current_password':PASSWORD,'clear_url':True})
    state=c.json('/api/notifications')
    assert not state['configured'] and not state['has_bearer'] and not state['has_signing_secret']


def test_history_aggregation_empty_gaps_and_range_validation(fixture):
    c=fixture['client'];c.login()
    c.json('/api/history?range=unbounded',expected=422)
    assert c.json('/api/history?range=1h')['traffic']==[]
    minute=int(time.time())//60*60
    with sqlite3.connect(fixture['state']/'gateway.sqlite') as db:
        for ts,up,down in [(minute-180,10,100),(minute-60,20,200)]:
            db.execute('INSERT INTO traffic_history VALUES(?,?,?)',(ts,up,down))
        db.executemany('INSERT INTO probe_history VALUES(?,?,?,?,?)',[
            (minute-180,'reality','healthy',100,50),
            (minute-120,'reality','failed',None,None),
            (minute-60,'reality','unknown',None,None)])
    hist=c.json('/api/history?range=1h')
    assert hist['bucket_seconds']==60 and hist['retention_days']==30
    assert sum(row['upload'] for row in hist['traffic'])==30
    assert sum(row['download'] for row in hist['traffic'])==300
    assert minute-120 not in {row['ts'] for row in hist['traffic']}
    reality=next(row for row in hist['summary'] if row['transport']=='reality')
    assert reality['healthy']==1 and reality['failed']==1 and reality['unknown']>=1
    assert reality['success_percent']==50 and reality['https_ms']==100
    for value,bucket in [('24h',300),('7d',1800),('30d',7200)]:
        result=c.json('/api/history?range='+value)
        assert result['bucket_seconds']==bucket and sum(row['upload'] for row in result['traffic'])==30


def test_new_frontend_assets_and_existing_subscription_survive(fixture):
    c=fixture['client'];c.login()
    before=c.call('/s/'+fixture['token'])[2]
    c.json('/api/notifications','PUT',{'enabled':False,'current_password':PASSWORD})
    assert c.call('/s/'+fixture['token'])[2]==before
    assert c.call('/static/operations.js')[0]==200
    assert b'loadHistory' in c.call('/static/operations.js')[2]
    html=c.call('/')[2].decode()
    assert 'page-history' in html and 'page-notifications' in html
    assert 'private-header-token' not in html
