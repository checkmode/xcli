"""Compare synthetic Clash configurations to the real legacy HTTP service."""
import http.client
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import shutil
import subprocess
import tempfile
import time
import unittest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import yaml
from test_panel_auth_compat import free_port
from test_panel_security_compat import decode_qr

PANEL=os.environ.get('XCLI_LEGACY_PANEL','')
DRIVER=os.environ.get('XCLI_CLASH_DRIVER','')
RUST_PANEL=os.environ.get('XCLI_PANEL_SERVICE','')
SHADOW_DRIVER=os.environ.get('XCLI_SHADOW_DRIVER','')


@unittest.skipUnless(PANEL and DRIVER and Path(PANEL).is_file() and Path(DRIVER).is_file(),
                     'set XCLI_LEGACY_PANEL and XCLI_CLASH_DRIVER')
class ClashCompatibility(unittest.TestCase):
    def test_generated_clash_configuration(self):
        with tempfile.TemporaryDirectory(prefix='xcli-clash-compat-') as folder:
            root=Path(folder);state=root/'state';state.mkdir();key=root/'key';key.write_bytes(bytes(range(32)));key.chmod(0o600)
            ws='/connect/test'
            settings={'origin':'https://testserver','domain':'testserver','public_ip':'203.0.113.2',
                'reality_sni':'www.bing.com','reality_public':'p'*43,'short_id':'0123456789abcdef','ws_path':ws,
                'hysteria2_port':443,'vmess_ws_path':ws+'/vmess','vmess_port':10081,
                'residential_exits':[{'tag':'residential-01','label':'住宅 HK','exit_ip':'8.8.8.8','country':'HK',
                    'ws_path':ws+'/residential-01','port':11001,'hysteria2':True},
                    {'tag':'residential-02','label':'住宅 US','exit_ip':'1.1.1.1','country':'US',
                    'ws_path':ws+'/residential-02','port':11002},
                    {'tag':'residential-11','label':'动态 US','exit_ip':'','country':'US',
                    'ws_path':ws+'/residential-11','port':10110,'dynamic':True}]}
            settings_path=root/'settings.json';settings_path.write_text(json.dumps(settings))
            db=sqlite3.connect(state/'gateway.sqlite');db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)')
            db.execute('INSERT INTO admin VALUES(1,?)',('000102030405060708090a0b0c0d0e0f:'
                'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf',));db.commit();db.close()
            listen=free_port();panel=None;driver=None;shadow_driver=None
            def launch():
                return subprocess.Popen([PANEL,'--state',str(state),'--settings',str(settings_path),'--static',str(root),
                    '--secret-key',str(key),'--port',str(listen),'--offline','--no-auto-backup'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            def stop(process):
                if process is None:return
                process.terminate()
                try:process.wait(timeout=15)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
            def request(path,method='GET',data=None,cookie='',csrf='',authorization=''):
                conn=http.client.HTTPConnection('127.0.0.1',listen,timeout=15);headers={'Origin':'https://testserver','Content-Type':'application/json'}
                if cookie:headers['Cookie']=cookie
                if csrf:headers['X-CSRF-Token']=csrf
                if authorization:headers['Authorization']=authorization
                try:
                    conn.request(method,path,body=json.dumps(data,ensure_ascii=False).encode() if data is not None else None,headers=headers)
                    response=conn.getresponse();return response.status,response.read()
                finally:conn.close()
            def ready(process):
                for _ in range(100):
                    if process.poll() is not None:self.fail('disposable legacy panel stopped')
                    try:
                        if request('/healthz')[0]==200:return
                    except OSError:time.sleep(.05)
                self.fail('disposable legacy panel did not become ready')
            def login():
                conn=http.client.HTTPConnection('127.0.0.1',listen,timeout=15)
                conn.request('POST','/api/login',json.dumps({'username':'admin','password':'fixture-password'}),
                    {'Origin':'https://testserver','Content-Type':'application/json'})
                response=conn.getresponse();cookie=response.getheader('Set-Cookie').split(';',1)[0];body=json.loads(response.read());conn.close()
                self.assertEqual(response.status,200);return cookie,body['csrf']
            def get_from(port,path,cookie=''):
                conn=http.client.HTTPConnection('127.0.0.1',port,timeout=15)
                try:
                    conn.request('GET',path,headers={'Cookie':cookie} if cookie else {});response=conn.getresponse()
                    return response.status,dict((k.lower(),v) for k,v in response.getheaders()),response.read()
                finally:conn.close()
            def rust(input):
                driver.stdin.write(json.dumps(input,ensure_ascii=False)+'\n');driver.stdin.flush()
                line=driver.stdout.readline();self.assertTrue(line,'Rust Clash driver stopped');return json.loads(line)
            try:
                panel=launch();ready(panel);cookie,csrf=login()
                status,body=request('/api/users','POST',{'name':'测试 / A','quota':1000000},cookie,csrf)
                self.assertEqual(status,200);user_id=json.loads(body)['id']
                with closing(sqlite3.connect(state/'gateway.sqlite')) as db:
                    uuid,token=db.execute('SELECT uuid,token FROM users WHERE id=?',(user_id,)).fetchone()
                node_id='a'*32;node_key='B'*43
                registration={'version':1,'id':node_id,'key':node_key,'public_ip':'8.8.4.4','domain':'node.example.com',
                    'public_port':8443,'reality_sni':'www.bing.com','reality_public':'Y'*43,'short_id':'fedcba9876543210',
                    'ws_path':'/connect/'+'b'*24,'hysteria2_port':8443}
                self.assertEqual(request('/api/remote-nodes','POST',{'name':'远程节点','registration':registration,'users':[user_id]},cookie,csrf)[0],201)
                authorization=f'Xcli-Node {node_id}.{node_key}'
                status,body=request('/api/nodes/sync','POST',{'revision':'','counters':[]},authorization=authorization)
                self.assertEqual(status,200);revision=json.loads(body)['revision']
                self.assertEqual(request('/api/nodes/sync','POST',{'revision':revision,'counters':[]},authorization=authorization)[0],200)
                status,body=request('/api/remote-nodes',cookie=cookie);self.assertEqual(status,200);nodes=json.loads(body)['nodes']
                driver=subprocess.Popen([DRIVER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
                if SHADOW_DRIVER:
                    self.assertTrue(Path(SHADOW_DRIVER).is_file())
                    shadow_driver=subprocess.Popen([SHADOW_DRIVER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
                payload={'settings':settings,'user':{'id':user_id,'uuid':uuid,'name':'测试 / A','token':token},'remote_nodes':nodes,'dynamic_enabled':False,
                    'policy':{'base':'standard','ai_outbound':'proxy','rules':'','managed':False}}
                checked_qr=False
                def compare():
                    nonlocal checked_qr
                    subpath='/s/'+token+'/clash.yaml'
                    status,old_headers,body=get_from(listen,subpath);self.assertEqual(status,200)
                    expected=yaml.safe_load(body);result=rust(payload);self.assertTrue(result['ok'])
                    actual=result['value']
                    self.assertEqual(actual.keys(),expected.keys())
                    aliases={'住宅 HK · 8.8.8.8':'香港01','住宅 US · 1.1.1.1':'美国01'}
                    def normalized_proxy(item):
                        item=dict(item)
                        for old_name,new_name in aliases.items():
                            if item['name']==old_name or item['name'].startswith(old_name+' · '):
                                item['name']=new_name+item['name'][len(old_name):];break
                        return item
                    self.assertEqual(actual['proxies'],[normalized_proxy(item) for item in expected['proxies']])
                    for field in expected:
                        if field not in ('proxies','proxy-groups'):
                            self.assertEqual(json.dumps(actual[field],ensure_ascii=False),json.dumps(expected[field],ensure_ascii=False),field)
                    groups={item['name']:item for item in actual['proxy-groups']}
                    old_groups={item['name']:item for item in expected['proxy-groups']}
                    for name in ('STUN','独立 · STUN','直连','故障转移','自动选择','GITHUB','MISSING'):
                        if name in old_groups:self.assertEqual(groups[name],old_groups[name],name)
                    self.assertEqual(groups['香港01']['type'],'fallback')
                    self.assertEqual(groups['香港01']['proxies'],['香港01 · Hysteria2','香港01 · HTTPS'])
                    self.assertTrue(groups['香港01']['hidden'])
                    self.assertTrue({'香港01','美国01'}.issubset(groups['PROXY']['proxies']))
                    if '独立 · AI' in groups:
                        for name in ('独立 · AI','独立 · Google'):
                            self.assertTrue({'香港01','美国01','DIRECT'}.issubset(groups[name]['proxies']))
                            self.assertFalse(any(node.startswith('住宅分组 · ') for node in groups[name]['proxies']))
                    self.assertEqual(yaml.safe_load(result['yaml']),actual)
                    setup_status,setup_body=request('/s/'+token+'/shadowrocket.json')
                    self.assertEqual(setup_status,200)
                    old_setup=json.loads(setup_body)
                    if shadow_driver is not None:
                        shadow_driver.stdin.write(json.dumps(payload,ensure_ascii=False)+'\n');shadow_driver.stdin.flush()
                        shadow=json.loads(shadow_driver.stdout.readline());self.assertTrue(shadow['ok'])
                        # Fixed exits with protocol failover require an
                        # integrated profile even on standard rules.
                        self.assertTrue(shadow['setup']['service_routing'])
                        self.assertEqual(shadow['setup']['dns_routing'],'integrated')
                        if old_setup['service_routing']:
                            self.assertEqual(shadow['setup']['resource'],old_setup['resource'])
                        profile_status,profile_body=request('/s/'+token+'/shadowrocket.conf')
                        if old_setup['service_routing']:self.assertEqual(shadow['status'],profile_status)
                        self.assertEqual(shadow['status'],200)
                        if shadow['status']==200:
                            self.assertIn('XCLI-香港01 = fallback,测试 / A · 香港01,测试 / A · 香港01 · HTTPS,',shadow['profile'])
                    if RUST_PANEL:
                        self.assertTrue(Path(RUST_PANEL).is_file())
                        with tempfile.TemporaryDirectory(dir=root,prefix='rust-state-') as folder:
                            rust_state=Path(folder)
                            with closing(sqlite3.connect(state/'gateway.sqlite')) as source,closing(sqlite3.connect(rust_state/'gateway.sqlite')) as target:
                                source.backup(target)
                            if (state/'webshare/config.xgb').exists():
                                (rust_state/'webshare').mkdir();shutil.copyfile(state/'webshare/config.xgb',rust_state/'webshare/config.xgb')
                            rust_port=free_port();rust_panel=subprocess.Popen([RUST_PANEL,'--experimental','--db',str(rust_state/'gateway.sqlite'),
                                '--settings',str(settings_path),'--secret-key',str(key),'--origin','https://testserver','--port',str(rust_port)],
                                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                            try:
                                for _ in range(100):
                                    if rust_panel.poll() is not None:self.fail('disposable Rust panel stopped')
                                    try:
                                        if get_from(rust_port,'/healthz')[0]==200:break
                                    except OSError:time.sleep(.05)
                                else:self.fail('disposable Rust panel did not become ready')
                                new_status,new_headers,new_body=get_from(rust_port,subpath)
                                self.assertEqual(new_status,status);self.assertEqual(new_body,result['yaml'].encode())
                                for header in ('subscription-userinfo','profile-update-interval','content-type','content-disposition'):
                                    self.assertEqual(new_headers[header],old_headers[header])
                                for suffix in ('shadowrocket.json','shadowrocket.conf'):
                                    shadow_path='/s/'+token+'/'+suffix
                                    old_status,old_headers,old_body=get_from(listen,shadow_path)
                                    new_status,new_headers,new_body=get_from(rust_port,shadow_path)
                                    if shadow_driver is not None:
                                        self.assertEqual(new_status,200 if suffix.endswith('.json') else shadow['status'])
                                        if suffix.endswith('.json'):self.assertEqual(json.loads(new_body),shadow['setup'])
                                        else:self.assertEqual(new_body,shadow['profile'].encode())
                                    else:
                                        self.assertEqual(new_status,200)
                                        if suffix.endswith('.json'):self.assertTrue(json.loads(new_body)['service_routing'])
                                        else:self.assertIn(b'fallback,',new_body)
                                    if new_status==old_status:self.assertEqual(new_headers['content-type'],old_headers['content-type'])
                                old_status,_,old_module=get_from(listen,'/shadowrocket-dns.sgmodule')
                                new_status,_,new_module=get_from(rust_port,'/shadowrocket-dns.sgmodule')
                                self.assertEqual((new_status,new_module),(old_status,old_module))
                                client_path='/api/users/'+user_id+'/shadowrocket'
                                self.assertEqual(get_from(rust_port,client_path)[0],401)
                                old_status,_,old_clients=get_from(listen,client_path,cookie)
                                new_status,_,new_clients=get_from(rust_port,client_path,cookie)
                                self.assertEqual(new_status,old_status)
                                previous_clients,client=json.loads(old_clients),json.loads(new_clients)
                                for entry_name in client:
                                    if entry_name!='shadowrocket' or old_setup['service_routing']:
                                        self.assertEqual(client[entry_name],previous_clients[entry_name])
                                self.assertTrue(client['shadowrocket'].startswith('shadowrocket://config/add/'))
                                if not checked_qr:
                                    for kind,expected in [('shadowrocket',client['shadowrocket']),('dns',client['dns_install']),('clash',client['clash'])]:
                                        qr_path='/api/users/'+user_id+'/qr/'+kind
                                        self.assertEqual(get_from(rust_port,qr_path)[0],401)
                                        old_status,old_headers,old_qr=get_from(listen,qr_path,cookie)
                                        new_status,new_headers,new_qr=get_from(rust_port,qr_path,cookie)
                                        self.assertEqual(new_status,old_status);self.assertEqual(new_headers['content-type'],old_headers['content-type'])
                                        for side,data in [('old',old_qr),('new',new_qr)]:
                                            self.assertTrue(data.startswith(b'\x89PNG\r\n\x1a\n'))
                                            png=root/('synthetic-'+side+'-'+kind+'.png');png.write_bytes(data);decoded=decode_qr(png)
                                            if os.environ.get('XCLI_REQUIRE_QR_DECODER'):self.assertIsNotNone(decoded,'QR decoder required')
                                            if decoded is not None:
                                                old_expected=previous_clients['shadowrocket'] if kind=='shadowrocket' else expected
                                                self.assertEqual(decoded,old_expected if side=='old' else expected)
                                    self.assertEqual(get_from(rust_port,'/api/users/'+user_id+'/qr/missing',cookie)[0],404)
                                    checked_qr=True
                            finally:stop(rust_panel)
                compare()
                nonce=bytes(range(12));ciphertext=AESGCM(bytes(range(32))).encrypt(nonce,b'{"enabled":true}',b'xcli:webshare:config:v1')
                (state/'webshare').mkdir();(state/'webshare/config.xgb').write_bytes(b'XGB1'+nonce+ciphertext[-16:]+ciphertext[:-16])
                payload['dynamic_enabled']=True;compare()
                self.assertEqual(request('/api/users/'+user_id+'/rule-template','POST',{'template_id':'standard'},cookie,csrf)[0],200)
                payload['policy']['managed']=True;compare()
                self.assertEqual(request('/api/users/'+user_id+'/rule-template','POST',{'template_id':'independent'},cookie,csrf)[0],200)
                status,body=request('/api/rule-templates',cookie=cookie);self.assertEqual(status,200)
                spec=next(item['published_spec'] for item in json.loads(body)['templates'] if item['id']=='independent')
                payload['policy']=dict(spec,managed=True);compare()
                custom=dict(spec,rules='DOMAIN,gemini.google.com,独立 · AI\nDOMAIN-KEYWORD,google,独立 · Google\nDOMAIN,example.com,办公',
                    groups=[{'name':'办公','default':'故障转移'}])
                status,body=request('/api/rule-templates','POST',{'name':'custom','spec':custom},cookie,csrf);self.assertEqual(status,200)
                template_id=json.loads(body)['id']
                self.assertEqual(request('/api/rule-templates/'+template_id+'/publish','POST',{'expected_revision':1},cookie,csrf)[0],200)
                self.assertEqual(request('/api/users/'+user_id+'/rule-template','POST',{'template_id':template_id},cookie,csrf)[0],200)
                payload['policy']=dict(custom,managed=True);compare()
                stop(panel);panel=None
                settings['clash_service_routes']={user_id:[{'name':'GITHUB','outbound':'hysteria2','domains':['github.com'],'udp':'proxy'},
                    {'name':'MISSING','outbound':'residential-99','domains':['missing.example'],'udp':'reject'}]}
                settings_path.write_text(json.dumps(settings));panel=launch();ready(panel);compare()
                self.assertEqual(request('/api/users/'+user_id+'/rule-template','POST',{'template_id':'legacy'},cookie,csrf)[0],200)
                stop(panel);panel=None
                settings['client_policies']={user_id:{'ai_outbound':'residential-01'}}
                settings['shadowrocket_base_profiles']={user_id:'[General]\r\ninclude = default.conf\r\nupdate-url = https://old.example/config\r\ndns-server = 8.8.8.8\r\n[Proxy Group]\r\nOld = select,PROXY\r\n[Rule]\r\nDOMAIN-KEYWORD,google,PROXY\r\nDOMAIN,gemini.google.com,PROXY\r\nFINAL,PROXY\r\n[Host]\r\nother.example = 8.8.8.8\r\n'}
                settings_path.write_text(json.dumps(settings));panel=launch();ready(panel)
                payload['policy']={'base':'independent','ai_outbound':'residential-01','rules':'','managed':False};compare()
                stop(panel);panel=None
                settings.pop('client_policies');settings.pop('shadowrocket_base_profiles')
                settings['shadowrocket_service_users']=[user_id];settings_path.write_text(json.dumps(settings));panel=launch();ready(panel)
                payload['policy']={'base':'standard','ai_outbound':'proxy','rules':'','managed':False};compare()
                stop(panel);panel=None
                settings['shadowrocket_base_profiles']={user_id:'[General]\r\ninclude = default.conf\r\n[Rule]\r\nFINAL,PROXY\r\n'}
                settings_path.write_text(json.dumps(settings));panel=launch();ready(panel);compare()
            finally:
                if driver is not None:driver.stdin.close();driver.wait(timeout=10);driver.stdout.close()
                if shadow_driver is not None:shadow_driver.stdin.close();shadow_driver.wait(timeout=10);shadow_driver.stdout.close()
                stop(panel)
