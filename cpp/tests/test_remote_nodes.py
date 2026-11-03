"""Exercise independent-node enrollment through the real HTTP server."""
import base64
import json

from test_http import Client, fixture


def test_node_registration_permissions_accounting_and_revocation(fixture):
    client = fixture['client']; client.login()
    uid = fixture['uid']
    node_id, key = 'a'*32, 'B'*43
    registration = {'version': 1, 'id': node_id, 'key': key, 'public_ip': '8.8.8.8',
                    'domain': 'node.example.com', 'public_port': 443, 'reality_sni': 'www.example.com',
                    'reality_public': 'P'*43, 'short_id': '0011223344556677',
                    'ws_path': '/connect/0123456789abcdef01234567', 'hysteria2_port': 443}
    packed = base64.b64encode(bytes.fromhex(uid)).decode()
    payload = {'name': '测试节点', 'registration': registration, 'users': packed}
    assert client.call('/api/remote-nodes', 'POST', payload, headers={'X-CSRF-Token': 'wrong'})[0] == 403
    created = client.json('/api/remote-nodes', 'POST', payload, expected=201)
    assert key not in json.dumps(created)
    assert key not in json.dumps(client.json('/api/remote-nodes'))
    anonymous = Client(client.port)
    sync = {'revision': '', 'counters': []}
    assert anonymous.call('/api/nodes/sync', 'POST', sync, headers={'Origin': '', 'Authorization': 'Xcli-Node '+node_id+'.'+'X'*43})[0] == 401
    headers = {'Origin': '', 'Authorization': 'Xcli-Node '+node_id+'.'+key}
    grant = anonymous.json('/api/nodes/sync', 'POST', sync, headers=headers)
    assert [u['id'] for u in grant['users']] == [uid]
    assert not any(k.startswith('remote-') for k in client.json('/api/users/'+uid+'/links'))
    grant = anonymous.json('/api/nodes/sync', 'POST', {'revision': grant['revision'], 'counters': []}, headers=headers)
    links = client.json('/api/users/'+uid+'/links')
    assert len([k for k in links if k.startswith('remote-')]) == 3
    # A temporary outage must not remove an already applied node from subscriptions.
    with fixture['legacy'].db() as database:
        registry = json.loads(database.execute("SELECT value FROM metadata WHERE key='remote_nodes_v1'").fetchone()[0])
        registry[0]['last_seen'] = 1
        database.execute("UPDATE metadata SET value=? WHERE key='remote_nodes_v1'", (json.dumps(registry),))
    assert len([k for k in client.json('/api/users/'+uid+'/links') if k.startswith('remote-')]) == 3
    client.json('/api/users/'+uid+'/rule-template', 'POST', {'template_id': 'independent'})
    import yaml
    status, _, contents = client.call('/s/'+fixture['token']+'/clash.yaml')
    assert status == 200
    clash = yaml.safe_load(contents)
    remote = [p['name'] for p in clash['proxies'] if p.get('server') == '8.8.8.8']
    assert len(remote) == 3
    assert all(name in clash['proxy-groups'][0]['proxies'] for name in remote)
    status, _, profile = client.call('/s/'+fixture['token']+'/shadowrocket.conf')
    assert status == 200 and '测试节点'.encode() in profile
    count = [{'id': uid, 'upload': 10, 'download': 20}]
    body = {'revision': grant['revision'], 'counters': count}
    anonymous.json('/api/nodes/sync', 'POST', body, headers=headers)
    anonymous.json('/api/nodes/sync', 'POST', body, headers=headers)
    user = next(u for u in client.json('/api/overview')['users'] if u['id'] == uid)
    assert (user['upload'], user['download']) == (133, 476)
    client.json('/api/remote-nodes/'+node_id, 'PUT', {'name': '测试节点', 'users': packed, 'enabled': False})
    assert anonymous.json('/api/nodes/sync', 'POST', body, headers=headers)['users'] == []
    assert not any(k.startswith('remote-') for k in client.json('/api/users/'+uid+'/links'))


def test_node_agent_synchronizes_with_real_panel_over_verified_tls(fixture, monkeypatch):
    import http.client
    import http.server
    import os
    from pathlib import Path
    import ssl
    import subprocess
    import sys
    import threading

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'scripts'))
    from node_agent import AgentError, NodeAgent
    from node_ledger import Ledger
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]/'tests'/'node'))
    from test_node_agent import FakeCore

    client = fixture['client']; client.login()
    uid = fixture['uid']; node_id = 'd'*32; key = 'E'*43
    registration = {'version': 1, 'id': node_id, 'key': key, 'public_ip': '8.8.8.8',
        'domain': 'node.example.com', 'public_port': 443, 'reality_sni': 'www.example.com',
        'reality_public': 'P'*43, 'short_id': '0011223344556677',
        'ws_path': '/connect/0123456789abcdef01234567', 'hysteria2_port': 443}
    client.json('/api/remote-nodes', 'POST', {'name': 'TLS test', 'registration': registration, 'users': [uid]}, expected=201)
    with fixture['legacy'].db() as database:
        credential = database.execute('SELECT uuid FROM users WHERE id=?', (uid,)).fetchone()[0]
    cert, private = fixture['tmp']/'tls.crt', fixture['tmp']/'tls.key'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
        '-addext','subjectAltName=DNS:localhost','-addext','basicConstraints=critical,CA:TRUE',
        '-keyout',str(private),'-out',str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    drop_response = {'once': False}
    class Forward(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            data = self.rfile.read(int(self.headers['Content-Length']))
            conn = http.client.HTTPConnection('127.0.0.1', client.port, timeout=5)
            try:
                conn.request('POST', self.path, body=data, headers={'Content-Type':'application/json',
                             'Authorization':self.headers.get('Authorization','')})
                response = conn.getresponse(); body = response.read()
                if drop_response['once'] and json.loads(data)['counters']:
                    drop_response['once'] = False
                    self.close_connection = True
                    return
                self.send_response(response.status); self.send_header('Content-Type', response.getheader('Content-Type'))
                self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
            finally: conn.close()
    proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Forward)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain(cert, private)
    proxy.socket = context.wrap_socket(proxy.socket, server_side=True)
    thread = threading.Thread(target=proxy.serve_forever, daemon=True); thread.start()
    core = FakeCore(); ledger = Ledger(fixture['tmp']/'node.sqlite')
    agent = NodeAgent(node_id, key, f'https://localhost:{proxy.server_port}', ledger, core)
    try:
        monkeypatch.setenv('SSL_CERT_FILE', str(fixture['tmp']/'missing-ca.pem'))
        try: agent.synchronize(); assert False, 'Untrusted TLS certificate accepted'
        except AgentError: pass
        assert not core.users
        monkeypatch.setenv('SSL_CERT_FILE', str(cert))
        agent.synchronize(); assert uid in core.users
        agent.synchronize()
        assert len([k for k in client.json('/api/users/'+uid+'/links') if k.startswith('remote-')]) == 3
        core.stats = [{'name': 'user>>>'+uid+'.'+credential[:8]+'@websocket>>>traffic>>>downlink', 'value': '80'}]
        # The panel commits, but the network loses its response. A retry must
        # acknowledge the same cumulative value without charging it twice.
        drop_response['once'] = True
        try: agent.synchronize(); assert False, 'A dropped response appeared successful'
        except AgentError: pass
        assert ledger.pending()[0]['download'] == 80
        agent.synchronize()
        user = next(u for u in client.json('/api/overview')['users'] if u['id'] == uid)
        assert user['download'] == 536
        assert ledger.pending() == []
        client.json('/api/users/'+uid, 'PUT', {'name':'disabled', 'enabled':False})
        agent.synchronize(); assert core.users == {}
        assert core.restarts == 1
    finally:
        agent.stop(); ledger.close(); proxy.shutdown(); proxy.server_close(); thread.join(timeout=5)
