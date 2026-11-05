"""Compare VMess parsing with the legacy Python importer using synthetic links."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest

DRIVER = os.environ.get('XCLI_VMESS_DRIVER', '')
SOURCE = Path(__file__).resolve().parents[2] / 'scripts/proxy_vmess.py'


def link(value):
    return 'vmess://' + base64.urlsafe_b64encode(json.dumps(value,ensure_ascii=False).encode()).decode().rstrip('=')


@unittest.skipUnless(DRIVER and Path(DRIVER).is_file() and SOURCE.is_file(), 'set VMess driver path')
class VmessInputCompatibility(unittest.TestCase):
    def test_parsing_and_pinned_outbound(self):
        spec=importlib.util.spec_from_file_location('legacy_vmess_fixture',SOURCE)
        old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
        base={'v':'2','add':'Example.COM','port':'443','id':'11111111-2222-3333-4444-555555555555','aid':'0'}
        variants=[{}, {'net':'raw'}, {'net':'ws','path':'','tls':'tls','host':'cdn.example.com','sni':'edge.example.com','fp':'chrome','alpn':'h2,http/1.1'},
            {'net':'grpc','path':'service','tls':'tls'}, {'net':'grpc','serviceName':'rpc','tls':'tls','type':'gun'},
            {'net':'ws','path':None}, {'scy':False}, {'allowInsecure':0.0}, {'add':'bücher.de'}, {'add':'faß.de'},
            {'add':'127.0.0.1'}, {'add':'thing.local'}, {'port':0}, {'port':65536}, {'aid':1}, {'v':1},
            {'allowInsecure':True}, {'unknown':'x'}, {'tls':'reality'}, {'net':'quic'}, {'sni':'edge.example.com'},
            {'path':'/wrong'}, {'net':'ws','path':'missing-slash'}, {'net':'grpc','path':'bad/name'}, {'scy':'unsupported'},
            {'add':'8.8.8.8'}, {'id':'invalid'}]
        cases=[]
        for variant in variants:
            value=copy.deepcopy(base);value.update(variant);cases.append(link(value))
        fields=('v','add','port','id','aid','scy','net','type','host','path','tls','sni','alpn','fp','allowInsecure','serviceName','mode')
        values=(None,False,True,0,0.0,1,'','0','false','tcp','ws','grpc','tls','none','h2','/','example.com',[],{},['x'])
        for field in fields:
            for value in values:
                item=copy.deepcopy(base);item[field]=value;cases.append(link(item))
        cases.extend(['', 'vmess://%%%', link(base)+'\n'+link(base), ' '+link(base)+'\r\n'])
        driver=subprocess.Popen([DRIVER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
        try:
            for index, text in enumerate(cases):
                with self.subTest(case=index):
                    driver.stdin.write(json.dumps({'text':text})+'\n');driver.stdin.flush()
                    result=json.loads(driver.stdout.readline())
                    try:
                        parsed=old.parse_links(text)
                        expected={'ok':True,'items':[{'address':item['address'],'port':item['port'],'outbound':old.outbound(item,'8.8.8.8')} for item in parsed]}
                    except old.InvalidProxy:
                        expected={'ok':False}
                    self.assertEqual(result,expected)
        finally:
            driver.stdin.close();driver.wait(timeout=10);driver.stdout.close()
