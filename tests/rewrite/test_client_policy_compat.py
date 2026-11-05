"""Compare independent AI/Google selectors and DNS ordering with legacy C++."""
import copy
import json
import os
from pathlib import Path
import subprocess
import unittest

LEGACY=os.environ.get('XCLI_LEGACY_RULES_APPLY_DRIVER','')
RUST=os.environ.get('XCLI_POLICY_DRIVER','')


@unittest.skipUnless(LEGACY and RUST and Path(LEGACY).is_file() and Path(RUST).is_file(),
                     'set legacy and Rust policy comparison drivers')
class ClientPolicyCompatibility(unittest.TestCase):
    def test_independent_policy_and_google_match(self):
        old=subprocess.Popen([LEGACY],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1)
        new=subprocess.Popen([RUST],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1)
        def ask(process,value):
            process.stdin.write(json.dumps(value,ensure_ascii=False)+'\n');process.stdin.flush()
            line=process.stdout.readline();self.assertTrue(line,'disposable driver stopped');return json.loads(line)
        def compare(payload):
            expected=ask(old,payload);actual=ask(new,payload)
            self.assertEqual(actual['ok'],expected['ok'])
            if expected['ok']:
                self.assertEqual(json.dumps(actual['value'],ensure_ascii=False),json.dumps(expected['value'],ensure_ascii=False))
            else:self.assertEqual(actual,expected)
            return expected
        try:
            config={'proxies':[{'name':'REALITY'},{'name':'HTTPS'},{'name':'Hysteria 2'},
                {'name':'住宅 HK · Hysteria2'},{'name':'住宅 HK · HTTPS'}],
                'proxy-groups':[{'name':'PROXY','type':'select','proxies':['HTTPS','REALITY','Hysteria 2','住宅 HK','住宅分组 · 香港']},
                    {'name':'住宅 HK','type':'select','proxies':['住宅 HK · Hysteria2','住宅 HK · HTTPS']},
                    {'name':'住宅分组 · 香港','type':'select','proxies':['住宅 HK']},
                    {'name':'STUN','type':'select','proxies':['Hysteria 2','HTTPS','REALITY']},
                    {'name':'业务服务','type':'select','proxies':['REALITY']}],
                'rules':['DOMAIN,testserver,DIRECT','RULE-SET,service-业务服务,业务服务',
                    'RULE-SET,stun-endpoints,STUN','RULE-SET,stun-endpoints,REJECT','GEOSITE,private,DIRECT','MATCH,PROXY'],
                'dns':{'nameserver-policy':{'testserver':['bootstrap'],'+.todesk.com':['direct'],
                    'stun.l.google.com':['https://1.1.1.1/dns-query#STUN'],
                    '+.google.com':['existing-override'],'geosite:cn,private':['domestic']}},
                'rule-providers':{'service-业务服务':{'type':'inline','behavior':'domain','payload':['+.example.com']},
                    'stun-endpoints':{'type':'inline','behavior':'classical','payload':['DOMAIN,stun.l.google.com']}}}
            outbound={'reality':'REALITY','websocket':'HTTPS','hysteria2':'Hysteria 2','residential-01':'住宅 HK'}
            for choice in ('proxy','reality','residential-01','residential-99'):
                with self.subTest(ai_outbound=choice):
                    result=compare({'action':'client-policy','config':config,'ai_outbound':choice,'outbound':outbound})
                    self.assertTrue(result['ok'])
                    compare({'action':'google-policy','config':result['value']})
            remote=copy.deepcopy(config)
            remote['proxies'].extend([{'name':'节点 B · REALITY'},{'name':'节点 A · HTTPS'}])
            remote_outbound=dict(outbound,**{'remote-b-reality':'节点 B · REALITY','remote-a-websocket':'节点 A · HTTPS'})
            compare({'action':'client-policy','config':remote,'ai_outbound':'proxy','outbound':remote_outbound})
            no_residential=copy.deepcopy(config)
            no_residential['proxy-groups']=[g for g in no_residential['proxy-groups'] if not g['name'].startswith('住宅')]
            compare({'action':'client-policy','config':no_residential,'ai_outbound':'proxy','outbound':outbound})
            conflict=copy.deepcopy(config);conflict['proxies'].append({'name':'独立 · Google'})
            compare({'action':'client-policy','config':conflict,'ai_outbound':'proxy','outbound':outbound})
            conflict=copy.deepcopy(config);conflict['rule-providers']['category-Google']={}
            compare({'action':'google-policy','config':conflict})
        finally:
            for process in (old,new):process.stdin.close();process.wait(timeout=10);process.stdout.close()
