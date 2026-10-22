#!/usr/bin/env python3
"""Exercise the actual authenticated HTTP preview/apply worker on disposable CI only."""
import base64
import http.cookiejar
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

SOURCE=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(SOURCE/'cpp/tests'))
from migration_state import snapshot


def main():
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.geteuid()!=0:raise SystemExit('Disposable CI only')
    settings_path=Path('/etc/xray-gateway/settings.json');before_settings=settings_path.read_bytes();settings=json.loads(before_settings)
    before=snapshot(Path('/var/lib/xray-gateway/gateway.sqlite'),settings_path)
    root=Path('/root/xcli-import-ci');root.mkdir(mode=0o700)
    state=Path('/var/lib/xray-gateway-import');state.mkdir(mode=0o750,exist_ok=True);shutil.chown(state,'root','xgateway')
    for source,target in [(SOURCE/'scripts/proxy_vmess.py',Path('/opt/xray-gateway/scripts/proxy_vmess.py')),(SOURCE/'scripts/proxy_import.py',Path('/opt/xray-gateway/scripts/proxy_import.py')),
                          (SOURCE/'deploy/xray-gateway-import.service',Path('/etc/systemd/system/xray-gateway-import.service'))]:
        shutil.copyfile(source,target);target.chmod(0o644)
    subprocess.run(['systemctl','daemon-reload'],check=True);subprocess.run(['systemctl','enable','--now','xray-gateway-import'],check=True)
    socks=[];ports=[]
    for _ in range(2):
        s=socket.socket();s.bind((settings['public_ip'],0));ports.append(s.getsockname()[1]);socks.append(s)
    upstream={'log':{'loglevel':'none'},'inbounds':[
        {'listen':settings['public_ip'],'port':port,'protocol':protocol,'settings':{'auth':'password','accounts':[{'user':'fixture-user','pass':'fixture-password'}]}}
        for port,protocol in zip(ports,['socks','http'])],
        'outbounds':[{'protocol':'freedom','streamSettings':{'sockopt':{'domainStrategy':'UseIPv4'}}}]}
    f=root/'upstream.json';f.write_text(json.dumps(upstream));f.chmod(0o600)
    for s in socks:s.close()
    process=subprocess.Popen(['/usr/local/lib/xray-gateway/xray','run','-config',str(f)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    rules=[];base=settings['origin'];jar=http.cookiejar.CookieJar();client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(jar))
    def api(path,data=None,csrf=None):
        headers={'Origin':base,'Content-Type':'application/json'}
        if csrf:headers['X-CSRF-Token']=csrf
        r=urllib.request.Request(base+'/api/'+path,data=None if data is None else json.dumps(data).encode(),headers=headers)
        with client.open(r,timeout=10) as response:return json.load(response)
    def wait(job,expected,timeout=220):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            try:
                result=api('proxy-import')
                if result.get('id')==job and result['status'] not in ('idle','verifying','applying'):
                    assert result['status']==expected,(result.get('message'),result.get('rows'));return result
            except (OSError,urllib.error.URLError):pass
            time.sleep(1)
        raise RuntimeError('Import job timed out')
    fields=dict(line.split(': ',1) for line in Path('/root/xray-gateway-admin.txt').read_text().splitlines());auth=api('login',{'username':'admin','password':fields['Password']});csrf=auth['csrf']
    try:
        for port in ports:
            rule=['-d',settings['public_ip']+'/32','-p','tcp','--dport',str(port),'-m','comment','--comment','xcli-import-ci','-j','RETURN']
            subprocess.run(['iptables','-w','-I','XG_OUT','1',*rule],check=True);rules.append(rule)
        for _ in range(15):
            if api('proxy-import')['status']!='unavailable':break
            time.sleep(1)
        for index,protocol in enumerate(('socks','http')):
            payload={'action':'preview','protocol':protocol,'label':'Fixture '+protocol,'text':f'{settings["public_ip"]}:{ports[index]}:fixture-user:fixture-password'}
            try:api('proxy-import',payload,'wrong')
            except urllib.error.HTTPError as e:assert e.code==403
            else:raise AssertionError('CSRF accepted')
            job=api('proxy-import',payload,csrf)['id'];ready=wait(job,'ready')
            assert settings_path.read_bytes()==before_settings if index==0 else True
            assert ready['rows'][0]['exit_ip']==settings['public_ip']
            assert 'fixture-password' not in json.dumps(ready) and 'fixture-user' not in json.dumps(ready)
            job=api('proxy-import',{'action':'apply','preview_id':job},csrf)['id'];result=wait(job,'complete')
            assert result['added']==1
            if index==0:first_job=job
            else:second_job=job
        users=api('overview')['users'];uid=next(u['id'] for u in users if u['status']=='active');links=api('users/'+uid+'/links')
        with client.open(links['subscription'],timeout=10) as r:text=base64.b64decode(r.read()).decode()
        assert len(text.splitlines())==7 and 'fixture-password' not in text
        monitor=api('overview')['monitor'];assert len(monitor['checks'])==5 and monitor['status']=='healthy'
        now=snapshot(Path('/var/lib/xray-gateway/gateway.sqlite'),settings_path)
        for key in ('identity_digest','admin_digest','security'):assert now[key]==before[key],key
        for uid,values in before['traffic'].items():assert all(a>=b for a,b in zip(now['traffic'][uid],values))
        # Duplicate preview must not change the running configuration.
        current=settings_path.read_bytes();job=api('proxy-import',payload,csrf)['id'];wait(job,'failed');assert settings_path.read_bytes()==current
        # Exercise management through the same authenticated Web API and actual core.
        catalog=api('proxy-import')['items'];assert len(catalog)==2
        tag=catalog[0]['tag'];management_jobs=[]
        def change(operation,changes=None):
            payload={'action':'manage','operation':operation,'tag':tag}
            if changes is not None:payload['changes']=changes
            previous=settings_path.read_bytes()
            preview=api('proxy-import',payload,csrf)['id'];wait(preview,'ready')
            assert settings_path.read_bytes()==previous
            job=api('proxy-import',{'action':'apply','preview_id':preview},csrf)['id'];wait(job,'complete');management_jobs.append(job)
            result=api('proxy-import')
            assert 'fixture-password' not in json.dumps(result) and 'fixture-user' not in json.dumps(result)
            return next(p for p in result['items'] if p['tag']==tag)
        def count(nodes,checks):
            # Each fixed exit has two client protocols and one upstream probe.
            with client.open(links['subscription'],timeout=10) as r:assert len(base64.b64decode(r.read()).decode().splitlines())==nodes
            assert len(api('overview')['monitor']['checks'])==checks
        changed=change('edit',{'label':'Edited fixture','address':settings['public_ip'],'port':ports[0],'protocol':'socks','username':'','password':''})
        assert changed['label']=='Edited fixture';count(7,5)
        assert not change('disable')['enabled'];count(5,4)
        assert change('enable')['enabled'];count(7,5)
        assert change('delete')['deleted_at'];count(5,4)
        restored=change('restore');assert not restored['deleted_at'] and not restored['enabled'];count(5,4)
        assert change('enable')['enabled'];count(7,5)
        for job in reversed(management_jobs):subprocess.run(['python3','/opt/xray-gateway/scripts/proxy_import.py','rollback',job],check=True)
        now=snapshot(Path('/var/lib/xray-gateway/gateway.sqlite'),settings_path)
        for key in ('identity_digest','admin_digest','security'):assert now[key]==before[key],key
        for job in (second_job,first_job):subprocess.run(['python3','/opt/xray-gateway/scripts/proxy_import.py','rollback',job],check=True)
        assert settings_path.read_bytes()==before_settings
        assert not Path('/etc/nginx/xcli-import-locations.conf').exists()
        assert not Path('/etc/xray-gateway/imported-proxies.json').exists()
        assert api('session')['csrf']==csrf
        print('Authenticated SOCKS5 and HTTP import, redaction, duplicate rejection, existing users and both rollbacks passed.')
    finally:
        for rule in rules:subprocess.run(['iptables','-w','-D','XG_OUT',*rule],check=True)
        api('logout',{},csrf);process.terminate();process.wait(timeout=10)
        subprocess.run(['systemctl','disable','--now','xray-gateway-import'],check=True)


if __name__=='__main__':main()
