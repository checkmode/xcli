"""Exercise the experimental probe subprocess with synthetic invalid inputs."""
import json
import os
from pathlib import Path
import subprocess
import unittest

HELPER=os.environ.get('XCLI_IMPORT_PROBE','')


@unittest.skipUnless(HELPER and Path(HELPER).is_file() and os.geteuid()!=0,
                     'set import probe and run as an unprivileged user')
class ImportProbeHelper(unittest.TestCase):
    def test_invalid_requests_are_bounded_and_never_echo_credentials(self):
        fixed={'kind':'fixed','protocol':'socks','fields':{'address':'127.0.0.1','port':1080,
            'username':'fixture-user','password':'synthetic-only-password'}}
        vmess={'kind':'vmess','protocol':'vmess','fields':{'address':'127.0.0.1','port':443,
            'uuid':'11111111-2222-3333-4444-555555555555','security':'auto','network':'ws','tls':False,
            'server_name':'','host':'','path':'/','alpn':'','fingerprint':''}}
        for request in (fixed,vmess,{**fixed,'unexpected':True},
                        {**fixed,'fields':{**fixed['fields'],'address':'1.1.1.1','username':'a:b'}}):
            result=subprocess.run([HELPER],input=json.dumps(request),capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0)
            self.assertEqual(json.loads(result.stdout),{'ok':False})
            self.assertNotIn('synthetic-only-password',result.stdout+result.stderr)
        result=subprocess.run([HELPER],input='x'*20001,capture_output=True,text=True,timeout=5)
        self.assertEqual(json.loads(result.stdout),{'ok':False})
        result=subprocess.run([HELPER,'unexpected'],input='',capture_output=True,text=True,timeout=5)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.stdout,'')
