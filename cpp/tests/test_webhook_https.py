"""Real TLS receiver tests, only inside a disposable network AND mount namespace.

Run through run-webhook-tests.sh. No production trust store or host routes change.
"""
import hashlib
import hmac
import http.server
import json
import os
import pathlib
import sqlite3
import ssl
import subprocess
import threading
import time

import pytest
from test_http import PASSWORD, fixture

pytestmark=pytest.mark.skipif(os.environ.get('XG_ISOLATED_NETWORK')!='1',reason='isolated network/mount namespace required')


@pytest.fixture
def receiver(tmp_path):
    if pathlib.Path('/proc/self/ns/net').readlink()==pathlib.Path('/proc/1/ns/net').readlink():
        raise RuntimeError('Refusing to alter host network/trust environment')
    cert=tmp_path/'receiver.pem';key=tmp_path/'receiver.key'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(key),'-out',str(cert),
        '-subj','/CN=webhook-test','-addext','subjectAltName=IP:8.8.8.8,DNS:rebind.test'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['mount','--bind',str(cert),'/etc/ssl/certs/ca-certificates.crt'],check=True)
    hosts=tmp_path/'hosts';hosts.write_text('127.0.0.1 localhost rebind.test\n::1 localhost\n')
    subprocess.run(['mount','--bind',str(hosts),'/etc/hosts'],check=True)
    records=[];mode={'status':204}
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            body=self.rfile.read(int(self.headers.get('Content-Length','0')))
            records.append({'body':body,'headers':dict(self.headers),'path':self.path})
            self.send_response(mode['status'])
            if mode['status']==302:self.send_header('Location','https://127.0.0.1/should-not-follow')
            self.end_headers()
        def log_message(self,*args):pass
    server=http.server.ThreadingHTTPServer(('0.0.0.0',0),Handler)
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,key);server.socket=tls.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield {'port':server.server_port,'records':records,'mode':mode}
    finally:
        server.shutdown();server.server_close();thread.join()
        subprocess.run(['umount','/etc/hosts'],check=True)
        subprocess.run(['umount','/etc/ssl/certs/ca-certificates.crt'],check=True)


def wait_delivery(c,event_id,status,timeout=15):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        row=next((d for d in c.json('/api/notifications')['deliveries'] if d['id']==event_id),None)
        if row and row['status']==status and row['attempts']>0:return row
        time.sleep(.1)
    raise AssertionError(f'Expected delivery {status}: {row}')


def setup(c,receiver,host='8.8.8.8'):
    c.login()
    c.json('/api/notifications','PUT',{'enabled':False,'url':f'https://{host}:{receiver["port"]}/hook?secret=test-only',
        'bearer':'isolated-bearer','signing_secret':'isolated-signing-secret','current_password':PASSWORD})


def test_real_https_signature_success_and_retry(fixture,receiver):
    c=fixture['client'];setup(c,receiver)
    receiver['mode']['status']=503
    event=c.json('/api/notifications/test','POST',{})['id']
    row=wait_delivery(c,event,'pending')
    assert row['attempts']==1 and row['http_status']==503
    receiver['mode']['status']=204
    with sqlite3.connect(fixture['state']/'gateway.sqlite') as db:
        db.execute('UPDATE notifications SET next_attempt=0 WHERE id=?',(event,))
    row=wait_delivery(c,event,'delivered')
    assert row['attempts']==2 and row['http_status']==204
    assert len(receiver['records'])==2
    for record in receiver['records']:
        headers={k.lower():v for k,v in record['headers'].items()}
        assert headers['authorization']=='Bearer isolated-bearer'
        assert headers['x-xcli-event-id']==event
        signature=hmac.new(b'isolated-signing-secret',headers['x-xcli-timestamp'].encode()+b'.'+record['body'],hashlib.sha256).hexdigest()
        assert headers['x-xcli-signature']=='sha256='+signature
        payload=json.loads(record['body']);assert payload['event']=='test' and payload['id']==event
        assert b'isolated-bearer' not in record['body'] and b'test-only' not in record['body']
    assert receiver['records'][0]['body']==receiver['records'][1]['body']


def test_redirects_are_not_followed(fixture,receiver):
    c=fixture['client'];setup(c,receiver);receiver['mode']['status']=302
    event=c.json('/api/notifications/test','POST',{})['id'];row=wait_delivery(c,event,'pending')
    assert row['http_status']==302 and len(receiver['records'])==1
    assert receiver['records'][0]['path'].startswith('/hook')


def test_hostname_resolving_to_loopback_is_rejected(fixture,receiver):
    c=fixture['client'];setup(c,receiver,'rebind.test')
    event=c.json('/api/notifications/test','POST',{})['id'];row=wait_delivery(c,event,'pending')
    assert row['http_status']==0 and len(receiver['records'])==0
    assert 'secret=test-only' not in json.dumps(row)


def test_certificate_hostname_is_verified(fixture,receiver):
    c=fixture['client']
    # Map a mismatching hostname to the exact trusted, namespace-local test address.
    hosts=fixture['tmp']/'mismatch-hosts';hosts.write_text('127.0.0.1 localhost\n8.8.8.8 mismatch.test\n')
    subprocess.run(['mount','--bind',str(hosts),'/etc/hosts'],check=True)
    try:
        setup(c,receiver,'mismatch.test')
        event=c.json('/api/notifications/test','POST',{})['id'];row=wait_delivery(c,event,'pending')
        assert row['http_status']==0 and len(receiver['records'])==0
    finally:subprocess.run(['umount','/etc/hosts'],check=True)
