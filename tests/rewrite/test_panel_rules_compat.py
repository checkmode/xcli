"""Compare rule validation against the live legacy C++ HTTP endpoint.

The databases, credentials and domains in these fixtures are synthetic.
"""
import http.client
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest

from test_panel_auth_compat import free_port

PANEL = os.environ.get('XCLI_LEGACY_PANEL', '')
DRIVER = os.environ.get('XCLI_RULES_DRIVER', '')
RUST_PANEL = os.environ.get('XCLI_PANEL_SERVICE', '')


@unittest.skipUnless(PANEL and DRIVER and Path(PANEL).is_file() and Path(DRIVER).is_file(),
                     'set XCLI_LEGACY_PANEL and XCLI_RULES_DRIVER')
class RulesCompatibility(unittest.TestCase):
    def test_validation_matches_legacy(self):
        with tempfile.TemporaryDirectory(prefix='xcli-rules-compat-') as folder:
            root=Path(folder);state=root/'state';state.mkdir();key=root/'key'
            key.write_bytes(bytes(range(32)));key.chmod(0o600)
            settings=root/'settings.json'
            settings.write_text(json.dumps({'origin':'https://testserver','domain':'testserver','public_ip':'203.0.113.2',
                'reality_sni':'example.com','reality_public':'p'*43,'short_id':'aabbccdd','ws_path':'/connect/test'}))
            db=sqlite3.connect(state/'gateway.sqlite');db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)')
            db.execute('INSERT INTO admin VALUES(1,?)',('000102030405060708090a0b0c0d0e0f:'
                'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf',));db.commit();db.close()
            port=free_port();panel=subprocess.Popen([PANEL,'--state',str(state),'--settings',str(settings),
                '--static',str(root),'--secret-key',str(key),'--port',str(port),'--offline','--no-auto-backup'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            driver=None;rust_panel=None
            def request(path,method='GET',body=None,cookie='',csrf='',target_port=None):
                conn=http.client.HTTPConnection('127.0.0.1',target_port or port,timeout=15)
                headers={'Origin':'https://testserver','Content-Type':'application/json'}
                if cookie:headers['Cookie']=cookie
                if csrf:headers['X-CSRF-Token']=csrf
                try:
                    conn.request(method,path,body=json.dumps(body,ensure_ascii=False).encode() if body is not None else None,headers=headers)
                    response=conn.getresponse()
                    return response.status,dict((k.lower(),v) for k,v in response.getheaders()),json.loads(response.read())
                finally:conn.close()
            try:
                for _ in range(100):
                    if panel.poll() is not None:self.fail('disposable legacy panel stopped')
                    try:
                        if request('/healthz')[0]==200:break
                    except OSError:time.sleep(.05)
                else:self.fail('disposable legacy panel did not become ready')
                status,headers,body=request('/api/login','POST',{'username':'admin','password':'fixture-password'})
                self.assertEqual(status,200);cookie=headers['set-cookie'].split(';',1)[0];csrf=body['csrf']
                status,_,catalog=request('/api/rule-templates',cookie=cookie);self.assertEqual(status,200)
                initial_standard=next(t['spec'] for t in catalog['templates'] if t['id']=='standard')
                status,_,created=request('/api/users','POST',{'name':'fixture user'},cookie,csrf);self.assertEqual(status,200)
                user_id=created['id']
                with closing(sqlite3.connect(state/'gateway.sqlite')) as db:
                    token=db.execute('SELECT token FROM users WHERE id=?',(user_id,)).fetchone()[0]
                status,_,created=request('/api/rule-templates','POST',{'name':'published','spec':initial_standard},cookie,csrf)
                self.assertEqual(status,200);template_id=created['id']
                self.assertEqual(request('/api/rule-templates/'+template_id+'/publish','POST',{'expected_revision':1},cookie,csrf)[0],200)
                self.assertEqual(request('/api/users/'+user_id+'/rule-template','POST',{'template_id':template_id},cookie,csrf)[0],200)
                self.assertEqual(request('/api/rule-templates','POST',{'name':'draft','spec':initial_standard},cookie,csrf)[0],200)
                edited=dict(initial_standard,ai_outbound='reality')
                self.assertEqual(request('/api/rule-templates/standard','PUT',{'name':'标准定制','spec':edited,'expected_revision':1},cookie,csrf)[0],200)
                self.assertEqual(request('/api/rule-templates/standard/publish','POST',{'expected_revision':2},cookie,csrf)[0],200)
                status,_,catalog=request('/api/rule-templates',cookie=cookie);self.assertEqual(status,200)
                if RUST_PANEL:
                    self.assertTrue(Path(RUST_PANEL).is_file())
                    rust_state=root/'rust-state';rust_state.mkdir()
                    with closing(sqlite3.connect(state/'gateway.sqlite')) as source,closing(sqlite3.connect(rust_state/'gateway.sqlite')) as target:
                        source.backup(target)
                    rust_port=free_port();rust_panel=subprocess.Popen([RUST_PANEL,'--experimental','--db',str(rust_state/'gateway.sqlite'),
                        '--secret-key',str(key),'--settings',str(settings),'--origin','https://testserver','--port',str(rust_port)],
                        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    for _ in range(100):
                        if rust_panel.poll() is not None:self.fail('disposable Rust panel stopped')
                        try:
                            if request('/healthz',target_port=rust_port)[0]==200:break
                        except OSError:time.sleep(.05)
                    else:self.fail('disposable Rust panel did not become ready')
                    self.assertEqual(request('/api/rule-templates',target_port=rust_port)[0],401)
                    rust_status,_,rust_catalog=request('/api/rule-templates',cookie=cookie,target_port=rust_port)
                    self.assertEqual((rust_status,rust_catalog),(200,catalog))
                standard=next(t['spec'] for t in catalog['templates'] if t['id']=='standard')
                independent=next(t['spec'] for t in catalog['templates'] if t['id']=='independent')
                fixture_rules=[
                    '', '# comment\r\n  DOMAIN,google.com,PROXY  \r\n',
                    'DOMAIN-SUFFIX,google.com,独立 · Google', 'DOMAIN-KEYWORD,google,独立 · Google',
                    'DOMAIN,GOOGLE.COM,PROXY', 'DOMAIN,a-.com,PROXY', 'DOMAIN,a..com,PROXY',
                    'DOMAIN,abc,PROXY','DOMAIN,-a.com,PROXY','DOMAIN,a.b,PROXY','DOMAIN,é.test,PROXY',
                    'DOMAIN-KEYWORD,-.abc-123,PROXY','DOMAIN-KEYWORD,ABC,PROXY','DOMAIN-KEYWORD,,PROXY',
                    'IP-CIDR,192.0.2.0/24,PROXY','IP-CIDR,192.0.2.1/032,DIRECT,resolve',
                    'IP-CIDR,192.0.02.1/24,DIRECT','IP-CIDR,192.0.2.1/33,DIRECT',
                    'IP-CIDR,192.0.2.1/-1,DIRECT','IP-CIDR,192.0.2.1/24/4,DIRECT',
                    'IP-CIDR6,2001:db8::/128,DIRECT,no-resolve','IP-CIDR6,::ffff:192.0.2.1/128,PROXY',
                    'IP-CIDR6,2001:db8::/129,DIRECT','GEOIP,CN,DIRECT','GEOIP,cn,DIRECT',
                    'GEOIP,US,PROXY,resolve','DST-PORT,443,PROXY','DST-PORT,00001,DIRECT',
                    'DST-PORT,0,DIRECT','DST-PORT,65536,DIRECT','DST-PORT,53,DIRECT,no-resolve',
                    'UNKNOWN,x,DIRECT','DOMAIN,a.b','DOMAIN,a.b,DIRECT,resolve,extra',
                    'DOMAIN,a.b,DIRECT,no-resolve','IP-CIDR,1.1.1.1/32,DIRECT,unknown',
                    'DOMAIN,a.b,UNKNOWN','DOMAIN,a.b,STUN','\n# comment\nDOMAIN,a.b,独立 · AI',
                    'DOMAIN,a.b,DIRECT\n'*500,'DOMAIN,a.b,DIRECT\n'*501,' '*14000,' '*14001,
                ]
                fixtures=[standard,independent]
                for base in ('standard','independent'):
                    for rule in fixture_rules:fixtures.append({'base':base,'ai_outbound':'proxy','rules':rule})
                fixtures.extend([
                    {'base':'standard','ai_outbound':'proxy','rules':'','groups':[]},
                    {'base':'standard','ai_outbound':'proxy','rules':'DOMAIN,x.y,工作','groups':[{'name':'工作','default':'DIRECT'}]},
                    {'base':'independent','ai_outbound':'residential-01','rules':'DOMAIN,x.y,工作','groups':[{'name':'工作','default':'故障转移'}]},
                    {'base':'standard','ai_outbound':'proxy','rules':'','groups':[{'name':'工作','default':'故障转移'}]},
                    {'base':'independent','ai_outbound':'proxy','rules':'','groups':[{'name':'独立 · Google','default':'DIRECT'}]},
                    {'base':'standard','ai_outbound':'proxy','rules':'','groups':[{'name':' a','default':'DIRECT'}]},
                    {'base':'standard','ai_outbound':'proxy','rules':'','groups':[{'name':'a#b','default':'DIRECT'}]},
                    {'base':'standard','ai_outbound':'proxy','rules':'','groups':[{'name':'a'*64,'default':'PROXY'}]},
                    {'base':'standard','ai_outbound':'proxy','rules':'','groups':[{'name':'a'*65,'default':'PROXY'}]},
                    {'base':'standard','ai_outbound':'proxy','rules':'','groups':[{'name':str(i),'default':'PROXY'} for i in range(16)]},
                    {'base':'standard','ai_outbound':'proxy','rules':'','groups':[{'name':str(i),'default':'PROXY'} for i in range(17)]},
                    {'base':'standard','ai_outbound':'proxy','rules':'','groups':[{'name':'x','default':'DIRECT'}]*2},
                    {'base':'standard','ai_outbound':'proxy','rules':'','groups':[{'name':'x','default':'DIRECT','extra':1}]},
                    {'base':'standard','ai_outbound':'proxy','rules':'','groups':None},
                    {'base':'standard','ai_outbound':'residential-1','rules':''},
                    {'base':'standard','ai_outbound':'proxy','rules':'','extra':True},
                    {'base':'standard','ai_outbound':'proxy'},None,
                ])
                driver=subprocess.Popen([DRIVER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
                for index,fixture in enumerate(fixtures):
                    with self.subTest(case=index):
                        driver.stdin.write(json.dumps(fixture,ensure_ascii=False)+'\n');driver.stdin.flush()
                        result=json.loads(driver.stdout.readline())
                        status,_,response=request('/api/rule-templates/validate','POST',{'name':'fixture','spec':fixture},cookie,csrf)
                        if rust_panel is not None:
                            rust_status,_,rust_response=request('/api/rule-templates/validate','POST',
                                {'name':'fixture','spec':fixture},cookie,csrf,target_port=rust_port)
                            self.assertEqual((rust_status,rust_response),(status,response))
                        self.assertEqual(status==200,result['ok'])
                        if result['ok']:self.assertEqual(response['spec'],result['value'])
                        else:
                            self.assertEqual(status,422);self.assertEqual(response['detail'],result['detail'])
                if rust_panel is not None:
                    bodies=[{}, {'name':'fixture'}, {'name':'fixture','spec':standard,'extra':0},
                        {'name':None,'spec':standard}, {'name':'','spec':standard}, {'name':'a'*61,'spec':standard},
                        {'name':'   ','spec':standard}, {'name':'bad\nname','spec':standard},
                        {'name':'\u2003 fixture \u3000','spec':standard}]
                    for body in bodies:
                        old_status,_,old_body=request('/api/rule-templates/validate','POST',body,cookie,csrf)
                        new_status,_,new_body=request('/api/rule-templates/validate','POST',body,cookie,csrf,target_port=rust_port)
                        self.assertEqual((new_status,new_body),(old_status,old_body))
                    changed={'name':'edited draft','spec':dict(initial_standard,rules='DOMAIN,example.com,DIRECT'),'expected_revision':1}
                    cases=[('/api/rule-templates/'+template_id,'PUT',changed),
                        ('/api/rule-templates/'+template_id,'PUT',changed),
                        ('/api/rule-templates/standard','PUT',{'name':'builtin draft','spec':initial_standard,'expected_revision':2}),
                        ('/api/rule-templates/'+'f'*32,'PUT',changed),
                        ('/api/rule-templates/'+template_id,'PUT',dict(changed,expected_revision=0)),
                        ('/api/rule-templates','POST',{'name':'bad','spec':dict(initial_standard,rules='DOMAIN,BAD,DIRECT')}),
                        ('/api/rule-templates','POST',{'name':'   ','spec':initial_standard})]
                    for path,method,body in cases:
                        old_status,_,old_body=request(path,method,body,cookie,csrf)
                        new_status,_,new_body=request(path,method,body,cookie,csrf,target_port=rust_port)
                        self.assertEqual((new_status,new_body),(old_status,old_body))
                    body={'name':'  new draft  ','spec':initial_standard}
                    old_status,_,old_created=request('/api/rule-templates','POST',body,cookie,csrf)
                    new_status,_,new_created=request('/api/rule-templates','POST',body,cookie,csrf,target_port=rust_port)
                    self.assertEqual((old_status,new_status),(200,200));self.assertEqual((old_created['revision'],new_created['revision']),(1,1))
                    old_catalog=request('/api/rule-templates',cookie=cookie)[2]
                    new_catalog=request('/api/rule-templates',cookie=cookie,target_port=rust_port)[2]
                    for item in new_catalog['templates']:
                        if item['id']==new_created['id']:item['id']=old_created['id']
                    self.assertEqual(new_catalog,old_catalog)
                    def both(path,body):
                        old_status,_,old_body=request(path,'POST',body,cookie,csrf)
                        new_status,_,new_body=request(path,'POST',body,cookie,csrf,target_port=rust_port)
                        self.assertEqual((new_status,new_body),(old_status,old_body));return old_status,old_body
                    self.assertEqual(both('/api/rule-templates/'+template_id+'/publish',{'expected_revision':2}),
                        (200,{'published_revision':2,'affected_users':1}))
                    bad_spec=dict(independent,ai_outbound='residential-99')
                    bad_draft={'name':'unavailable AI','spec':bad_spec,'expected_revision':2}
                    old_status,_,old_body=request('/api/rule-templates/'+template_id,'PUT',bad_draft,cookie,csrf)
                    new_status,_,new_body=request('/api/rule-templates/'+template_id,'PUT',bad_draft,cookie,csrf,target_port=rust_port)
                    self.assertEqual((new_status,new_body),(old_status,old_body));self.assertEqual(old_status,200)
                    self.assertEqual(both('/api/rule-templates/'+template_id+'/publish',{'expected_revision':3})[0],422)
                    self.assertEqual(both('/api/rule-templates/standard/reset',{'expected_revision':3})[0],200)
                    self.assertEqual(both('/api/rule-templates/standard/undo-reset',{'expected_revision':4})[0],200)
                    draft_id=next(item['id'] for item in old_catalog['templates'] if item['name']=='draft')
                    self.assertEqual(both('/api/users/'+user_id+'/rule-template',{'template_id':draft_id})[0],409)
                    self.assertEqual(both('/api/users/'+user_id+'/rule-template',{'template_id':'standard'})[0],200)
                    def raw(port,path):
                        conn=http.client.HTTPConnection('127.0.0.1',port,timeout=15)
                        try:
                            conn.request('GET',path);response=conn.getresponse();return response.status,response.read()
                        finally:conn.close()
                    self.assertEqual(raw(port,'/s/'+token+'/clash.yaml'),raw(rust_port,'/s/'+token+'/clash.yaml'))
                    self.assertEqual(both('/api/rule-templates/standard/reset',{'expected_revision':5})[1]['affected_users'],1)
                    self.assertTrue(both('/api/rule-templates/standard/reset',{'expected_revision':6})[1]['unchanged'])
                    self.assertEqual(raw(port,'/s/'+token+'/clash.yaml'),raw(rust_port,'/s/'+token+'/clash.yaml'))
                    self.assertEqual(both('/api/rule-templates/standard/undo-reset',{'expected_revision':6})[1]['affected_users'],1)
                    self.assertEqual(raw(port,'/s/'+token+'/clash.yaml'),raw(rust_port,'/s/'+token+'/clash.yaml'))
                    self.assertEqual(both('/api/users/'+user_id+'/rule-template',{'template_id':'legacy'})[0],200)
                    def events(database):
                        with closing(sqlite3.connect(database)) as db:
                            return db.execute("SELECT action,detail FROM events WHERE action LIKE 'rule_template_%' ORDER BY id").fetchall()
                    self.assertEqual(events(state/'gateway.sqlite'),events(rust_state/'gateway.sqlite'))
            finally:
                if driver is not None:driver.stdin.close();driver.wait(timeout=10);driver.stdout.close()
                if rust_panel is not None:
                    rust_panel.terminate()
                    try:rust_panel.wait(timeout=15)
                    except subprocess.TimeoutExpired:rust_panel.kill();rust_panel.wait(timeout=5)
                panel.terminate()
                try:panel.wait(timeout=15)
                except subprocess.TimeoutExpired:panel.kill();panel.wait(timeout=5)
