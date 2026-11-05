"""Compare bounded provider parsing against the existing Python worker."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'scripts/webshare.py'
DRIVER=os.environ.get('XCLI_WEBSHARE_PROVIDER_DRIVER','')


@unittest.skipUnless(SOURCE.is_file() and DRIVER and Path(DRIVER).is_file(),'set XCLI_WEBSHARE_PROVIDER_DRIVER')
class WebshareProviderCompatibility(unittest.TestCase):
    def test_provider_response_and_session_names(self):
        spec=importlib.util.spec_from_file_location('legacy_webshare_fixture',SOURCE);legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
        driver=subprocess.Popen([DRIVER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
        def rust(op,value):
            driver.stdin.write(json.dumps({'op':op,'input':value})+'\n');driver.stdin.flush()
            line=driver.stdout.readline();self.assertTrue(line,'disposable provider driver stopped');return json.loads(line)
        try:
            cases=[{'results':[]},{'results':[{'id':17,'status':'active','pool_filter':'residential','bandwidth_limit':10},
                {'id':18,'status':'active','proxy_subtype':'isp'},{'id':19,'status':'cancelled','pool_filter':'residential'},
                {'id':'bad','status':'active'},{'id':22,'status':None,'pool_filter':None}]}]
            for value in cases:self.assertEqual(rust('plans',value)['value'],legacy.plans_from_response(value))
            for value in ({},{'results':None},{'results':{}}):self.assertFalse(rust('plans',value)['ok'])
            for username in ('fixture','fixture_123-1234','fixture-abc_def--4'):
                value={'results':[{'username':username,'password':'synthetic-password'}]}
                self.assertEqual(rust('credentials',value)['value'],legacy.credentials(value))
            for username in ('-bad','bad-','space bad','bad!'):
                value={'results':[{'username':username,'password':'synthetic-password'}]}
                self.assertFalse(rust('credentials',value)['ok'])
                with self.assertRaises(legacy.ProviderError):legacy.credentials(value)
            for country in legacy.REGIONS:
                value={'base':'fixture_user','country':country,'id':'123456'}
                self.assertEqual(rust('username',value)['value'],legacy.session_username(value['base'],country,value['id']))
            data={'bandwidth_total':1234,'requests_total':10,'requests_successful':9,'requests_failed':-1,'secret':'not-for-output'}
            expected={k:data[k] for k in ('bandwidth_total','requests_total','requests_successful','requests_failed') if type(data.get(k)) is int and data[k]>=0}
            self.assertEqual(rust('usage',data)['value'],expected)
        finally:
            driver.stdin.close();driver.wait(timeout=10);driver.stdout.close()
