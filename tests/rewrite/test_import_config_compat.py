"""Compare isolated fixed-proxy configuration candidates with legacy Python."""
import copy
import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
DRIVER=os.environ.get('XCLI_IMPORT_CONFIG_DRIVER','')


@unittest.skipUnless(DRIVER and Path(DRIVER).is_file(), 'set import candidate driver')
class ImportConfigCompatibility(unittest.TestCase):
    def test_fixed_candidate_preserves_routes_and_rejects_conflicts(self):
        sys.path.insert(0,str(ROOT/'scripts'))
        spec=importlib.util.spec_from_file_location('legacy_import_fixture',ROOT/'scripts/proxy_import.py')
        legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
        base={'settings':{'public_ip':'8.8.8.8','ws_path':'/connect/fixture','residential_exits':[]},
              'core':{'inbounds':[{'tag':'reality','port':10080,'protocol':'vless'}],
                  'outbounds':[{'tag':'direct','protocol':'freedom'},{'tag':'blocked','protocol':'blackhole'}],
                  'routing':{'rules':[{'type':'field','ip':['8.8.8.8/32'],'outboundTag':'blocked'},
                      {'type':'field','inboundTag':['reality'],'outboundTag':'direct'}]}},
              'monitor':{'residential_exits':[]},'nginx':'server {\n        location = /connect/fixture {\n        }\n}',
              'locations':None,'pool':None}
        first={'address':'1.1.1.1','port':12345,'username':'fixture-user','password':'synthetic-password',
               'protocol':'socks','exit_ip':'1.1.1.1','country':'US'}
        second={'address':'8.8.4.4','port':23456,'username':'fixture-other','password':'synthetic-other',
                'protocol':'socks','exit_ip':'8.8.4.4','country':'JP'}
        def legacy_candidate(files, inputs):
            old={key:json.dumps(files[key]).encode() for key in ('settings','core','monitor')}
            old['nginx']=files['nginx'].encode()
            if files['locations'] is not None:old['locations']=files['locations'].encode()
            if files['pool'] is not None:old['pool']=json.dumps(files['pool']).encode()
            if inputs[0]['protocol']=='vmess':
                proxies=[legacy.proxy_vmess.parse_links(item['link'])[0] for item in inputs]
                rows=[{'status':'verified','exit_ip':item['exit_ip'],'country':item['country'],'server_ip':item['server_ip']} for item in inputs]
            else:
                proxies=[{key:item[key] for key in ('address','port','username','password')} for item in inputs]
                rows=[{'status':'verified','exit_ip':item['exit_ip'],'country':item['country']} for item in inputs]
            try:
                new,entries=legacy.configure(old,proxies,inputs[0]['protocol'],'fixture',rows)
                return {'ok':True,'settings':json.loads(new['settings']),'core':json.loads(new['core']),
                    'monitor':json.loads(new['monitor']),'pool':json.loads(new['pool']),
                    'nginx':new['nginx'].decode(),'locations':new['locations'].decode(),'entries':entries}
            except legacy.ImportErrorSafe:return {'ok':False}
        driver=subprocess.Popen([DRIVER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
        def compare(files,inputs):
            driver.stdin.write(json.dumps({'files':files,'inputs':inputs,'label':'fixture'})+'\n');driver.stdin.flush()
            actual=json.loads(driver.stdout.readline());expected=legacy_candidate(files,inputs)
            self.assertEqual(actual,expected)
            if actual['ok']:
                public=json.dumps([actual['settings'],actual['monitor'],actual['nginx'],actual['locations']])
                self.assertNotIn('synthetic-password',public)
            return actual
        def manage(files, operation, tag='residential-27', verified=None, changes=None):
            old={key:json.dumps(files[key]).encode() for key in ('settings','core','monitor','pool')}
            old.update(nginx=files['nginx'].encode(),locations=files['locations'].encode())
            request={'operation':operation,'tag':tag}
            if changes is not None:request['changes']=changes
            driver.stdin.write(json.dumps({'files':files,**request,'now':1700000000,'verified':verified})+'\n');driver.stdin.flush()
            actual=json.loads(driver.stdout.readline())
            legacy.stamp=lambda:1700000000
            try:
                new,entries,_target=legacy.manage_config(old,request,verified)
                expected={'ok':True,'settings':json.loads(new['settings']),'core':json.loads(new['core']),
                    'monitor':json.loads(new['monitor']),'pool':json.loads(new['pool']),
                    'nginx':new['nginx'].decode(),'locations':new['locations'].decode(),'entries':entries}
            except legacy.ImportErrorSafe:expected={'ok':False}
            self.assertEqual(actual,expected)
            if actual['ok']:
                public=json.dumps([actual['settings'],actual['monitor'],actual['nginx'],actual['locations']])
                self.assertNotIn('synthetic-password',public)
            return actual
        def as_files(result):
            return {key:result[key] for key in ('settings','core','monitor','pool','nginx','locations')}
        def enable_vmess(files):
            old={key:json.dumps(files[key]).encode() for key in ('settings','core','monitor')}
            old['nginx']=files['nginx'].encode()
            if files['locations'] is not None:old['locations']=files['locations'].encode()
            if files['pool'] is not None:old['pool']=json.dumps(files['pool']).encode()
            driver.stdin.write(json.dumps({'files':files,'operation':'enable-vmess'})+'\n');driver.stdin.flush()
            actual=json.loads(driver.stdout.readline())
            try:
                new,entries=legacy.vmess_entry_config(old)
                expected={'ok':True,'settings':json.loads(new['settings']),'core':json.loads(new['core']),
                    'monitor':json.loads(new['monitor']),'pool':json.loads(new['pool']),
                    'nginx':new['nginx'].decode(),'locations':new['locations'].decode(),'entries':entries}
            except legacy.ImportErrorSafe:expected={'ok':False}
            self.assertEqual(actual,expected)
            return actual
        def enable_hysteria(files, tag=None):
            old={key:json.dumps(files[key]).encode() for key in ('settings','core','monitor','pool')}
            old.update(nginx=files['nginx'].encode(),locations=files['locations'].encode())
            request={'operation':'enable-hysteria','tag':tag} if tag else {'operation':'enable-all-hysteria'}
            driver.stdin.write(json.dumps({'files':files,**request})+'\n');driver.stdin.flush()
            actual=json.loads(driver.stdout.readline())
            try:
                new,entries=legacy.enable_residential_hysteria(old,tag) if tag else legacy.enable_all_residential_hysteria(old)
                expected={'ok':True,'settings':json.loads(new['settings']),'core':json.loads(new['core']),
                    'monitor':json.loads(new['monitor']),'pool':json.loads(new['pool']),
                    'nginx':new['nginx'].decode(),'locations':new['locations'].decode(),'entries':entries}
            except legacy.ImportErrorSafe:expected={'ok':False}
            self.assertEqual(actual,expected)
            return actual
        try:
            vmess_entry=enable_vmess(base);self.assertTrue(vmess_entry['ok'])
            self.assertFalse(enable_vmess(as_files(vmess_entry))['ok'])
            occupied_vmess=copy.deepcopy(base);occupied_vmess['core']['inbounds'].append({'tag':'other','port':10081})
            self.assertFalse(enable_vmess(occupied_vmess)['ok'])
            invalid_vmess=copy.deepcopy(base);invalid_vmess['settings']['ws_path']='/connect/invalid/path'
            self.assertFalse(enable_vmess(invalid_vmess)['ok'])
            duplicate_vmess=copy.deepcopy(base);duplicate_vmess['nginx']+='\nlocation = /connect/fixture {}'
            self.assertFalse(enable_vmess(duplicate_vmess)['ok'])
            built=compare(base,[first]);self.assertTrue(built['ok'])
            self.assertTrue(enable_vmess(as_files(built))['ok'])
            built_two=compare(base,[first,second]);self.assertTrue(built_two['ok'])
            verification={'status':'verified','exit_ip':'8.8.8.8','country':'JP'}
            original=as_files(built_two)
            self.assertFalse(enable_hysteria(original,'residential-27')['ok'])
            with_hysteria=copy.deepcopy(original);with_hysteria['settings']['hysteria2_port']=443
            with_hysteria['core']['inbounds'].append({'tag':'hysteria2','port':443,'protocol':'hysteria'})
            enabled_hysteria=enable_hysteria(with_hysteria,'residential-27');self.assertTrue(enabled_hysteria['ok'])
            self.assertFalse(enable_hysteria(as_files(enabled_hysteria),'residential-27')['ok'])
            enabled_all=enable_hysteria(as_files(enabled_hysteria));self.assertTrue(enabled_all['ok'])
            self.assertTrue(all(p['entry']['hysteria2'] for p in enabled_all['pool']['proxies']))
            self.assertEqual(as_files(enabled_all),as_files(enable_hysteria(as_files(enabled_all))))
            disabled=manage(original,'disable');self.assertTrue(disabled['ok'])
            self.assertEqual([p['tag'] for p in disabled['settings']['residential_exits']],['residential-28'])
            self.assertTrue(any(r.get('inboundTag')==['residential-28'] and r.get('outboundTag')=='blocked'
                for r in disabled['core']['routing']['rules']))
            enabled=manage(as_files(disabled),'enable',verified=verification);self.assertTrue(enabled['ok'])
            deleted=manage(as_files(enabled),'delete');self.assertTrue(deleted['ok'])
            self.assertEqual(deleted['pool']['proxies'][0]['deleted_at'],1700000000)
            restored=manage(as_files(deleted),'restore');self.assertTrue(restored['ok'])
            self.assertFalse(restored['pool']['proxies'][0]['enabled'])
            self.assertTrue(manage(as_files(restored),'enable',verified=verification)['ok'])
            edited=manage(original,'edit',verified=verification,changes={'label':'新的住宅','protocol':'http',
                'password':'synthetic-new-password','username':''})
            self.assertTrue(edited['ok'])
            self.assertEqual(edited['pool']['proxies'][0]['username'],'fixture-user')
            self.assertEqual([p['tag'] for p in edited['settings']['residential_exits']],['residential-27','residential-28'])
            self.assertTrue(manage(as_files(disabled),'edit',verified=verification,changes={'label':'停用仍可编辑'})['ok'])
            self.assertFalse(manage(original,'edit',verified=verification,changes={'label':'\u007f'})['ok'])
            self.assertFalse(manage(original,'edit',verified=verification,changes={'protocol':'vmess'})['ok'])
            self.assertFalse(manage(original,'edit',verified=verification,changes={'unknown':True})['ok'])
            self.assertFalse(manage(as_files(deleted),'disable')['ok'])
            self.assertFalse(manage(original,'restore')['ok'])
            conflicting=copy.deepcopy(original)
            conflicting['core']['routing']['rules'].append({'type':'field','inboundTag':['other'],'outboundTag':'residential-27-exit'})
            self.assertFalse(manage(conflicting,'disable')['ok'])
            duplicate=copy.deepcopy(original)
            duplicate['pool']['proxies'][1]['address']=duplicate['pool']['proxies'][0]['address']
            duplicate['pool']['proxies'][1]['port']=duplicate['pool']['proxies'][0]['port']
            self.assertFalse(manage(duplicate,'disable')['ok'])
            invalid=copy.deepcopy(verification);invalid['exit_ip']='127.0.0.1'
            self.assertFalse(manage(as_files(disabled),'enable',verified=invalid)['ok'])
            http=copy.deepcopy(first);http['protocol']='http';compare(base,[http])
            extended=copy.deepcopy(base);extended['settings']['hysteria2_port']=443
            extended['settings']['residential_exits']=[{'tag':'residential-11','dynamic':True,'country':'US'}]
            extended['monitor']['residential_exits']=copy.deepcopy(extended['settings']['residential_exits'])
            extended['core']['inbounds'].append({'tag':'hysteria2','port':443,'protocol':'hysteria'})
            compare(extended,[first])
            subsequent={key:built[key] for key in ('settings','core','monitor','pool','nginx','locations')}
            compare(subsequent,[second]);compare(subsequent,[first])
            older=copy.deepcopy(subsequent);older['pool']['proxies'][0].pop('entry')
            older['pool']['proxies'][0].pop('enabled');older['pool']['proxies'][0].pop('deleted_at')
            compare(older,[second])
            occupied=copy.deepcopy(base)
            occupied['core']['inbounds'].append({'tag':'other','port':10450,'protocol':'vless'})
            occupied['core']['outbounds'].append({'tag':'residential-27-exit','protocol':'freedom'})
            candidate=compare(occupied,[first]);self.assertEqual(candidate['entries'][0]['tag'],'residential-28')
            self.assertEqual(candidate['entries'][0]['port'],10451)
            altered=copy.deepcopy(base);altered['core']['routing']['rules'].append({'type':'field','network':'tcp','outboundTag':'direct'})
            compare(altered,[first])
            exception={'type':'field','ruleTag':'subscription-https-all','user':['regexp:^[0-9a-f]{32}\\.[0-9a-f]{8}@'],
                'ip':['8.8.8.8/32'],'port':'443','network':'tcp','outboundTag':'direct'}
            valid=copy.deepcopy(base);valid['core']['routing']['rules'].insert(0,exception);compare(valid,[first])
            invalid=copy.deepcopy(valid);invalid['core']['routing']['rules'][0]['port']='1-65535';compare(invalid,[first])
            mismatch=copy.deepcopy(base);mismatch['locations']='existing';compare(mismatch,[first])
            repeated=copy.deepcopy(base);repeated['nginx']+='\nlocation = /connect/fixture {}';compare(repeated,[first])
            large=copy.deepcopy(base);large['monitor']['extra']='x'*17000;compare(large,[first])
            link={'v':'2','add':'proxy.example.com','port':'443','id':'11111111-2222-3333-4444-555555555555',
                'net':'ws','tls':'tls','path':'/vmess','sni':'edge.example.com'}
            encoded='vmess://'+base64.b64encode(json.dumps(link).encode()).decode()
            vmess={'protocol':'vmess','link':encoded,'server_ip':'8.8.4.4','exit_ip':'1.1.1.1','country':'US'}
            built_vmess=compare(base,[vmess]);self.assertTrue(built_vmess['ok'])
            next_vmess={key:built_vmess[key] for key in ('settings','core','monitor','pool','nginx','locations')}
            compare(next_vmess,[vmess])
            disabled_vmess=manage(next_vmess,'disable');self.assertTrue(disabled_vmess['ok'])
            verified_vmess={**verification,'server_ip':'8.8.4.4'}
            self.assertTrue(manage(as_files(disabled_vmess),'enable',verified=verified_vmess)['ok'])
            self.assertTrue(manage(next_vmess,'edit',verified=verified_vmess,changes={'path':'/changed','uuid':''})['ok'])
            self.assertFalse(manage(next_vmess,'edit',verified=verified_vmess,changes={'protocol':'socks'})['ok'])
            bad_vmess=copy.deepcopy(vmess);bad_vmess['server_ip']='127.0.0.1';compare(base,[bad_vmess])
            full=copy.deepcopy(base);full['settings']['residential_exits']=[{'tag':f'residential-{i:02}'} for i in range(1,41)]
            compare(full,[first])
        finally:
            driver.stdin.close();driver.wait(timeout=10);driver.stdout.close()
