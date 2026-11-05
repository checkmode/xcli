"""Compare generated rule precedence and DNS ordering with legacy C++."""
import copy
import json
import os
from pathlib import Path
import subprocess
import unittest

LEGACY=os.environ.get('XCLI_LEGACY_RULES_APPLY_DRIVER','')
RUST=os.environ.get('XCLI_RULES_APPLY_DRIVER','')


@unittest.skipUnless(LEGACY and RUST and Path(LEGACY).is_file() and Path(RUST).is_file(),
                     'set both rule application drivers')
class RuleApplicationCompatibility(unittest.TestCase):
    def test_rule_and_dns_order(self):
        old=subprocess.Popen([LEGACY],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1)
        new=subprocess.Popen([RUST],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1)
        def ask(process,value):
            process.stdin.write(json.dumps(value,ensure_ascii=False)+'\n');process.stdin.flush()
            line=process.stdout.readline();self.assertTrue(line,'disposable driver stopped');return json.loads(line)
        try:
            factory=ask(old,{'action':'factory'})['factory']
            config={'proxies':[{'name':'REALITY'},{'name':'HTTPS'}],
                'proxy-groups':[{'name':'PROXY','type':'select','proxies':['HTTPS','REALITY','直连']},
                    {'name':'STUN','type':'select','proxies':['HTTPS']},
                    {'name':'故障转移','type':'fallback','proxies':['REALITY']},
                    {'name':'自动选择','type':'url-test','proxies':['HTTPS']},
                    {'name':'直连','type':'select','proxies':['DIRECT']},
                    {'name':'独立 · AI','type':'select','proxies':['故障转移']},
                    {'name':'独立 · Google','type':'select','proxies':['PROXY']},
                    {'name':'其他流量','type':'select','proxies':['PROXY']}],
                'rules':['DOMAIN,testserver,DIRECT','RULE-SET,category-AI,独立 · AI',
                    'RULE-SET,category-Apple,DIRECT','GEOSITE,private,DIRECT','MATCH,PROXY'],
                'dns':{'nameserver-policy':{'testserver':['bootstrap'],'+.google.com':['old-google'],
                    'gemini.google.com':['old-gemini'],'+.openai.com':['old-ai'],
                    'rule-set:other':['other'],'geosite:cn':['cn']}},
                'rule-providers':{'category-AI':{'payload':['old-ai']},'category-Apple':{'payload':['old-apple']},
                    'other':{'payload':['keep']}}}
            baseline={'testserver':['bootstrap'],'+.openai.com':['baseline-ai'],'rule-set:other':['other']}
            def spec(base,rules,groups=None):
                value={'base':base,'ai_outbound':'proxy','rules':rules}
                if groups is not None:value['groups']=groups
                return value
            fixtures=[
                (config,spec('standard','')),
                (config,spec('standard','DOMAIN-SUFFIX,google.com,PROXY\nDOMAIN,gemini.google.com,DIRECT')),
                (config,spec('standard','DOMAIN,gemini.google.com,DIRECT\nDOMAIN-SUFFIX,google.com,PROXY')),
                (config,spec('standard','DOMAIN-KEYWORD,google,PROXY\nDOMAIN,gemini.google.com,DIRECT\nDOMAIN,abc.com,DIRECT')),
                (config,spec('standard','DOMAIN,abc.com,工作\nIP-CIDR,192.0.2.0/24,工作',
                    [{'name':'工作','default':'DIRECT'}])),
                (config,spec('independent','DOMAIN-SUFFIX,google.com,独立 · Google\nDOMAIN,gemini.google.com,独立 · AI')),
                (config,spec('independent','DOMAIN-SUFFIX,google.com,独立 · Google\nDOMAIN-KEYWORD,google,独立 · Google\nDOMAIN,gemini.google.com,独立 · AI')),
                (config,spec('independent','IP-CIDR,192.0.2.1/32,独立 · AI\nIP-CIDR6,2001:db8::/32,独立 · AI,no-resolve')),
                (config,spec('independent',factory,[{'name':'工作','default':'故障转移'}])),
                (config,spec('standard','',[{'name':'HTTPS','default':'DIRECT'}])),
                (config,spec('independent','',[{'name':'工作','default':'自动选择'}])),
                (config,spec('standard','DOMAIN,x.y,STUN')),
            ]
            no_proxy=copy.deepcopy(config);no_proxy['proxy-groups']=[]
            fixtures.append((no_proxy,spec('standard','')))
            no_stun=copy.deepcopy(config);no_stun['proxy-groups']=[g for g in no_stun['proxy-groups'] if g['name']!='STUN']
            fixtures.append((no_stun,spec('standard','DOMAIN,x.y,STUN')))
            no_fallback=copy.deepcopy(config);no_fallback['proxy-groups']=[g for g in no_fallback['proxy-groups'] if g['name']!='故障转移']
            fixtures.append((no_fallback,spec('independent','',[{'name':'工作','default':'故障转移'}])))
            for index,(configuration,policy) in enumerate(fixtures):
                with self.subTest(case=index):
                    request={'config':configuration,'spec':policy,'baseline_dns':baseline,'factory':factory}
                    expected=ask(old,request);actual=ask(new,request)
                    self.assertEqual(actual['ok'],expected['ok'])
                    if expected['ok']:
                        # Object order matters to the generated DNS policy, unlike normal dict equality.
                        self.assertEqual(json.dumps(actual['value'],ensure_ascii=False),json.dumps(expected['value'],ensure_ascii=False))
                    else:self.assertEqual(actual,expected)
        finally:
            for process in (old,new):
                process.stdin.close();process.wait(timeout=10);process.stdout.close()
