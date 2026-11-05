"""Validate disposable Rust candidates with real Xray and Nginx parsers."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
DRIVER=os.environ.get('XCLI_IMPORT_CONFIG_DRIVER','')
XRAY=os.environ.get('XCLI_TEST_XRAY','')
NGINX=os.environ.get('XCLI_TEST_NGINX','')


@unittest.skipUnless(DRIVER and XRAY and NGINX and all(Path(path).is_file() for path in (DRIVER,XRAY,NGINX)),
                     'set candidate driver, Xray and Nginx paths')
class ImportCandidateValidation(unittest.TestCase):
    def test_real_parsers_accept_synthetic_fixed_and_vmess_candidates(self):
        sys.path.insert(0,str(ROOT/'deploy'))
        import provision
        key_output=subprocess.check_output([XRAY,'x25519'],text=True)
        settings=provision.settings_for('panel.example.com','8.8.8.8','example.com',key_output)
        settings['hysteria2_port']=0
        core=provision.core_config(settings);monitor=provision.monitor_config(settings)
        core['inbounds'][1]['settings']['clients']=[{'id':'11111111-2222-3333-4444-555555555555'}]
        nginx=('events {}\nhttp {\naccess_log off;\nmap $http_upgrade $connection_upgrade { default upgrade; "" close; }\n'
            'server { listen 127.0.0.1:18090;\nlocation = '+settings['ws_path']+' { return 204; }\n}\n}\n')
        files={'settings':settings,'core':core,'monitor':monitor,'nginx':nginx,'locations':None,'pool':None}
        fixed={'address':'1.1.1.1','port':12345,'username':'fixture-user','password':'synthetic-password',
            'protocol':'socks','exit_ip':'1.1.1.1','country':'US'}
        data={'v':'2','add':'proxy.example.com','port':'443','id':'11111111-2222-3333-4444-555555555555',
            'net':'ws','tls':'tls','path':'/fixture','sni':'edge.example.com'}
        vmess={'protocol':'vmess','link':'vmess://'+base64.b64encode(json.dumps(data).encode()).decode(),
            'server_ip':'8.8.4.4','exit_ip':'1.1.1.1','country':'US'}
        with tempfile.TemporaryDirectory(prefix='xcli-import-validate-') as folder:
            tmp=Path(folder);driver=subprocess.Popen([DRIVER],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
            try:
                def ask(request):
                    driver.stdin.write(json.dumps(request)+'\n');driver.stdin.flush()
                    result=json.loads(driver.stdout.readline());self.assertTrue(result['ok'])
                    return result
                def check(result):
                    core_path=tmp/'core.json';core_path.write_text(json.dumps(result['core']))
                    run=subprocess.run([XRAY,'run','-test','-config',str(core_path)],capture_output=True,timeout=15)
                    self.assertEqual(run.returncode,0,'synthetic Xray candidate failed validation: '+run.stderr.decode(errors='replace'))
                    locations=tmp/'locations.conf';locations.write_text(result['locations'])
                    config=tmp/'nginx.conf';config.write_text('error_log '+str(tmp/'error.log')+';\npid '+str(tmp/'nginx.pid')+';\n'+
                        result['nginx'].replace('/etc/nginx/xcli-import-locations.conf',str(locations)))
                    run=subprocess.run([NGINX,'-t','-c',str(config),'-p',str(tmp)],capture_output=True,timeout=15)
                    self.assertEqual(run.returncode,0,'synthetic Nginx candidate failed validation: '+run.stderr.decode(errors='replace'))
                def as_files(result):
                    return {key:result[key] for key in ('settings','core','monitor','pool','nginx','locations')}
                built_fixed=None
                for candidate in (fixed,vmess):
                    result=ask({'files':files,'inputs':[candidate],'label':'fixture'})
                    self.assertEqual(result['core']['inbounds'][:-1],core['inbounds'])
                    check(result)
                    if candidate is fixed:built_fixed=result
                check(ask({'files':files,'operation':'enable-vmess'}))
                # Two public TLS sites may expose the same managed entrances.
                # Both must receive new locations and validate against the
                # same staged include without changing the existing sites.
                marker='location = '+settings['ws_path']+' { return 204; }'
                include='include /etc/nginx/xcli-import-locations.conf;'
                sites=('events {}\nhttp { access_log off;\n'
                       'map $http_upgrade $connection_upgrade { default upgrade; "" close; }\n'
                       'server { listen 127.0.0.1:18090; '+marker+' }\n'
                       'server { listen 127.0.0.1:18091; '+marker+' }\n}\n')
                dual={**files,'nginx':sites}
                dual_fixed=ask({'files':dual,'inputs':[fixed],'label':'fixture'})
                self.assertEqual(dual_fixed['nginx'].count(include),2);check(dual_fixed)
                dual_vmess=ask({'files':dual,'operation':'enable-vmess'})
                self.assertEqual(dual_vmess['nginx'].count(include),2)
                self.assertEqual(dual_vmess['nginx'].count('location = '+settings['ws_path']+'/vmess {'),2)
                check(dual_vmess)
                existing={**dual,'nginx':sites.replace(marker,include+'\n'+marker),'locations':''}
                dual_existing=ask({'files':existing,'inputs':[fixed],'label':'fixture'})
                self.assertEqual(dual_existing['nginx'],existing['nginx']);check(dual_existing)
                disabled=ask({'files':as_files(built_fixed),'operation':'disable','tag':'residential-27'});check(disabled)
                enabled=ask({'files':as_files(disabled),'operation':'enable','tag':'residential-27',
                    'verified':{'exit_ip':'1.1.1.1','country':'US'}});check(enabled)
                cert=tmp/'cert.pem';key=tmp/'key.pem'
                subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                    '-subj','/CN=fixture.example.com','-keyout',str(key),'-out',str(cert)],
                    check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
                with_hysteria=as_files(built_fixed)
                with_hysteria['settings']['hysteria2_port']=1443
                with_hysteria['core']['inbounds'].append(provision.hysteria_inbound(1443,cert,key))
                check(ask({'files':with_hysteria,'operation':'enable-hysteria','tag':'residential-27'}))
            finally:
                driver.stdin.close();driver.wait(timeout=10);driver.stdout.close()
