"""Compare isolated Rust monitor clients against the legacy Python generator."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
DRIVER=os.environ.get('XCLI_MONITOR_DRIVER','')
XRAY=os.environ.get('XCLI_TEST_XRAY','')


@unittest.skipUnless(DRIVER and Path(DRIVER).is_file(),'set monitor comparison driver')
class MonitorConfigCompatibility(unittest.TestCase):
    def test_generated_clients_match_python_for_each_transport(self):
        spec=importlib.util.spec_from_file_location('legacy_probe_fixture',ROOT/'scripts/probe.py')
        legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
        public='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        if XRAY and Path(XRAY).is_file():
            output=subprocess.check_output([XRAY,'x25519'],text=True)
            fields=dict(line.split(':',1) for line in output.splitlines() if ':' in line)
            public=next(fields[key].strip() for key in ('Password (PublicKey)','Password','PublicKey') if key in fields)
        base={'domain':'panel.example.com','public_ip':'8.8.8.8','reality_sni':'example.com','reality_public':public,
              'short_id':'0123456789abcdef','uuid':'11111111-2222-3333-4444-555555555555',
              'ws_path':'/connect/fixture','hysteria2_port':443,'vmess_ws_path':'/connect/fixture/vmess',
              'residential_exits':[{'tag':'residential-27','exit_ip':'1.1.1.1','ws_path':'/connect/fixture/residential-27'},
                  {'tag':'residential-28','exit_ip':'8.8.4.4','ws_path':'/connect/fixture/residential-28','hysteria2':True}]}
        driver=subprocess.Popen([DRIVER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
        try:
            with tempfile.TemporaryDirectory(prefix='xcli-monitor-compat-') as folder:
                for address_ip in (False,True):
                    config=copy.deepcopy(base);config['node_address_ip']=address_ip;config['public_port']=8443
                    kinds=['reality','websocket','hysteria2','vmess','residential-27','residential-28']
                    for kind in kinds:
                        request={'config':config,'kind':kind,'port':1080}
                        driver.stdin.write(json.dumps(request)+'\n');driver.stdin.flush()
                        result=json.loads(driver.stdout.readline())
                        self.assertTrue(result['ok'])
                        self.assertEqual(result['kinds'],kinds)
                        self.assertEqual(result['residential'],kind.startswith('residential-'))
                        self.assertEqual(result['client'],legacy.client_config(config,kind,1080))
                        if XRAY and Path(XRAY).is_file():
                            path=Path(folder)/'client.json';path.write_text(json.dumps(result['client']))
                            checked=subprocess.run([XRAY,'run','-test','-config',str(path)],capture_output=True,timeout=15)
                            self.assertEqual(checked.returncode,0,'synthetic monitor client rejected: '+checked.stderr.decode(errors='replace'))
                accounts=[]
                for _ in range(2):
                    driver.stdin.write(json.dumps({'config':base,'kind':'reality','port':1080,'secure':True})+'\n');driver.stdin.flush()
                    result=json.loads(driver.stdout.readline());self.assertTrue(result['ok'])
                    settings=result['client']['inbounds'][0]['settings']
                    self.assertEqual(settings['auth'],'password');accounts.append(settings['accounts'][0])
                    if XRAY and Path(XRAY).is_file():
                        path=Path(folder)/'secured-client.json';path.write_text(json.dumps(result['client']))
                        checked=subprocess.run([XRAY,'run','-test','-config',str(path)],capture_output=True,timeout=15)
                        self.assertEqual(checked.returncode,0,'authenticated synthetic monitor client rejected')
                self.assertNotEqual(accounts[0],accounts[1])
                basic=copy.deepcopy(base);basic['hysteria2_port']=0;basic.pop('vmess_ws_path');basic['residential_exits']=[]
                driver.stdin.write(json.dumps({'config':basic,'kind':'websocket','port':1080})+'\n');driver.stdin.flush()
                self.assertEqual(json.loads(driver.stdout.readline())['kinds'],['reality','websocket'])
                for change in ({'kind':'unknown'},{'port':0}):
                    driver.stdin.write(json.dumps({**{'config':basic,'kind':'reality','port':1080},**change})+'\n');driver.stdin.flush()
                    self.assertFalse(json.loads(driver.stdout.readline())['ok'])
        finally:
            driver.stdin.close();driver.wait(timeout=10);driver.stdout.close()
