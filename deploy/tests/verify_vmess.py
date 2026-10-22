#!/usr/bin/env python3
"""Verify VMess ingress and imported TCP/WS/gRPC exits on a disposable CI host."""
import base64
import http.cookiejar
import json
import os
from pathlib import Path
import re
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
UUID='07a7ec9f-df87-4dfe-bb75-79e728517953'


def main():
    if os.environ.get('GITHUB_ACTIONS')!='true' or os.geteuid()!=0:raise SystemExit('Disposable CI only')
    settings_path=Path('/etc/xray-gateway/settings.json');before_settings=settings_path.read_bytes();settings=json.loads(before_settings)
    before=snapshot(Path('/var/lib/xray-gateway/gateway.sqlite'),settings_path)
    for name in ('proxy_import.py','proxy_vmess.py','probe.py'):
        target=Path('/opt/xray-gateway/scripts')/name;shutil.copyfile(SOURCE/'scripts'/name,target);target.chmod(0o644)
    subprocess.run(['systemctl','enable','--now','xray-gateway-import'],check=True)
    base=settings['origin'];client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def api(path,data=None,csrf=None):
        headers={'Origin':base,'Content-Type':'application/json'}
        if csrf:headers['X-CSRF-Token']=csrf
        request=urllib.request.Request(base+'/api/'+path,data=None if data is None else json.dumps(data).encode(),headers=headers)
        with client.open(request,timeout=10) as r:return json.load(r)
    fields=dict(line.split(': ',1) for line in Path('/root/xray-gateway-admin.txt').read_text().splitlines())
    auth=api('login',{'username':'admin','password':fields['Password']});csrf=auth['csrf']
    def wait(job,expected):
        end=time.monotonic()+220
        while time.monotonic()<end:
            try:
                result=api('proxy-import')
                if result.get('id')==job and result['status'] not in ('verifying','applying','idle'):
                    assert result['status']==expected,(result.get('message'),result.get('rows'));return result
            except (OSError,urllib.error.URLError):pass
            time.sleep(1)
        raise AssertionError('VMess worker timed out')
    jobs=[]
    def apply(payload):
        print('VMess check: '+payload.get('operation',payload['action']),flush=True)
        original=settings_path.read_bytes();preview=api('proxy-import',payload,csrf)['id'];wait(preview,'ready')
        assert settings_path.read_bytes()==original
        job=api('proxy-import',{'action':'apply','preview_id':preview},csrf)['id'];wait(job,'complete');jobs.append(job)
        state=api('proxy-import');assert UUID not in json.dumps(state)
        return state
    # Enable the real public WebSocket/TLS entry; its monitor verifies HTTPS and UDP.
    output=subprocess.check_output(['python3','/opt/xray-gateway/scripts/proxy_import.py','enable-vmess'],text=True)
    match=re.search(r'Rollback job: ([0-9a-f]{32})',output);assert match;jobs.append(match[1])
    assert api('session')['csrf']==csrf
    user=next(u for u in api('overview')['users'] if u['status']=='active');links=api('users/'+user['id']+'/links')
    vmess=json.loads(base64.b64decode(links['vmess'][8:]));assert vmess['net']=='ws' and vmess['tls']=='tls' and vmess['aid']=='0'
    def count(nodes,checks):
        with client.open(links['subscription'],timeout=10) as r:subscription=base64.b64decode(r.read()).decode()
        assert len(subscription.splitlines())==nodes and UUID not in subscription
        monitor=api('overview')['monitor'];assert monitor['status']=='healthy' and len(monitor['checks'])==checks,monitor
    count(4,4)
    vmess_check=next(c for c in api('overview')['monitor']['checks'] if c['transport']=='vmess')
    assert vmess_check['https_ms'] is not None and vmess_check['udp_ms'] is not None
    # Three independently authenticated upstream transports, with real TLS for WS/gRPC.
    sockets=[];ports=[]
    for _ in range(3):
        sock=socket.socket();sock.bind((settings['public_ip'],0));ports.append(sock.getsockname()[1]);sockets.append(sock)
    modes=('tcp','ws','grpc');inbounds=[]
    for mode,port in zip(modes,ports):
        stream={'network':mode,'security':'none' if mode=='tcp' else 'tls'}
        if mode!='tcp':stream['tlsSettings']={'alpn':['h2','http/1.1'],'certificates':[{'certificateFile':'/etc/xray-gateway/tls/fullchain.pem','keyFile':'/etc/xray-gateway/tls/privkey.pem'}]}
        if mode=='ws':stream['wsSettings']={'path':'/fixture-vmess'}
        if mode=='grpc':stream['grpcSettings']={'serviceName':'fixture-vmess'}
        inbounds.append({'listen':settings['public_ip'],'port':port,'protocol':'vmess','settings':{'clients':[{'id':UUID}]},'streamSettings':stream})
    root=Path('/root/xcli-vmess-ci');root.mkdir(mode=0o700)
    config=root/'upstream.json';config.write_text(json.dumps({'log':{'loglevel':'none'},'inbounds':inbounds,'outbounds':[{'protocol':'freedom','streamSettings':{'sockopt':{'domainStrategy':'UseIPv4'}}}]}));config.chmod(0o600)
    for sock in sockets:sock.close()
    process=subprocess.Popen(['/usr/local/lib/xray-gateway/xray','run','-config',str(config)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    rules=[]
    try:
        for port in ports:
            rule=['-d',settings['public_ip']+'/32','-p','tcp','--dport',str(port),'-m','comment','--comment','xcli-vmess-ci','-j','RETURN']
            subprocess.run(['iptables','-w','-I','XG_OUT','1',*rule],check=True);rules.append(rule)
        time.sleep(1);assert process.poll() is None
        for index,(mode,port) in enumerate(zip(modes,ports)):
            share={'v':'2','ps':'Fixture '+mode,'add':settings['public_ip'],'port':str(port),'id':UUID,'aid':'0','scy':'auto','net':mode,
                'type':'none','host':'' if mode=='tcp' else settings['domain'],'path':'' if mode=='tcp' else '/fixture-vmess' if mode=='ws' else 'fixture-vmess',
                'tls':'' if mode=='tcp' else 'tls','sni':'' if mode=='tcp' else settings['domain']}
            text='vmess://'+base64.b64encode(json.dumps(share).encode()).decode()
            state=apply({'action':'preview','protocol':'vmess','label':'Fixture '+mode,'text':text});count(6+2*index,5+index)
        item=next(p for p in state['items'] if p['network']=='ws');tag=item['tag']
        # Invalid changes cannot alter the serving configuration; blank UUID keeps it.
        original=settings_path.read_bytes()
        job=api('proxy-import',{'action':'manage','operation':'edit','tag':tag,'changes':{'label':'Invalid','address':item['address'],'port':item['port'],'protocol':'vmess','uuid':'bad'}},csrf)['id']
        wait(job,'failed');assert settings_path.read_bytes()==original
        apply({'action':'manage','operation':'edit','tag':tag,'changes':{'label':'Edited VMess','address':item['address'],'port':item['port'],'protocol':'vmess','uuid':''}});count(10,7)
        for operation,expected in [('disable',(8,6)),('delete',(8,6)),('restore',(8,6)),('enable',(10,7))]:
            state=apply({'action':'manage','operation':operation,'tag':tag});count(*expected)
            record=next(p for p in state['items'] if p['tag']==tag)
            if operation=='restore':assert not record['enabled'] and not record['deleted_at']
        for job in reversed(jobs):subprocess.run(['python3','/opt/xray-gateway/scripts/proxy_import.py','rollback',job],check=True)
        assert settings_path.read_bytes()==before_settings
        now=snapshot(Path('/var/lib/xray-gateway/gateway.sqlite'),settings_path)
        for key in ('identity_digest','admin_digest','security'):assert now[key]==before[key],key
        for uid,values in before['traffic'].items():assert all(a>=b for a,b in zip(now['traffic'][uid],values))
        print('VMess TLS ingress, TCP/WS/gRPC exits, authenticated edit/trash/restore, user continuity and every rollback passed.')
    finally:
        for rule in rules:subprocess.run(['iptables','-w','-D','XG_OUT',*rule],check=True)
        api('logout',{},csrf);process.terminate();process.wait(timeout=10)
        subprocess.run(['systemctl','disable','--now','xray-gateway-import'],check=True)


if __name__=='__main__':main()
