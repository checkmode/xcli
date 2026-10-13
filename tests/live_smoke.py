#!/usr/bin/env python3
"""Run on the deployed server; logs only assertions, never credentials."""
import json,subprocess,sys,tempfile,time,os,pathlib,urllib.parse
sys.path.insert(0,'/opt/xray-gateway')
import app
s=app.config();domain=s['domain'];work=tempfile.TemporaryDirectory(prefix='xg-acceptance-');w=pathlib.Path(work.name);os.chmod(w,0o700)
password=next(x.split(': ',1)[1] for x in pathlib.Path('/root/xray-gateway-admin.txt').read_text().splitlines() if x.startswith('Password: '))
csrf=''
def request(path,method='GET',body=None,expected=200):
    cmd=['curl','-sS','--fail-with-body','--resolve',domain+':443:127.0.0.1','-b',str(w/'cookies'),'-c',str(w/'cookies'),'-X',method,'-H','Origin: https://'+domain,'-H','X-CSRF-Token: '+csrf,'-H','Content-Type: application/json','https://'+domain+path]
    if body is not None:cmd+=['--data-binary','@-']
    p=subprocess.run(cmd,input=json.dumps(body) if body is not None else None,text=True,capture_output=True,timeout=15)
    if p.returncode:raise RuntimeError('HTTP request failed: '+path+' '+p.stderr[:180])
    return json.loads(p.stdout)
login=request('/api/login','POST',{'username':'admin','password':password});csrf=login['csrf']
print('PASS: valid HTTPS certificate, administrator login, CSRF session')
uid=request('/api/users','POST',{'name':'temporary-acceptance','quota':0,'expires':0})['id']
try:
    time.sleep(6)
    with app.db() as c:u=app.get_user(c,uid)
    for kind,port in [('reality',10808),('websocket',10809)]:
        stream=({'network':'tcp','security':'reality','realitySettings':{'serverName':s['reality_sni'],'fingerprint':'chrome','publicKey':s['reality_public'],'shortId':s['short_id']}} if kind=='reality' else {'network':'ws','security':'tls','tlsSettings':{'serverName':domain},'wsSettings':{'path':s['ws_path'],'headers':{'Host':domain}}})
        cfg={'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':port,'protocol':'socks','settings':{'auth':'noauth','udp':True}}],'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':443,'users':[{'id':u['uuid'],'encryption':'none',**({'flow':'xtls-rprx-vision'} if kind=='reality' else {})}]}]},'streamSettings':stream}]}
        p=w/(kind+'.json');p.write_text(json.dumps(cfg));p.chmod(0o600)
        log=(w/(kind+'.log')).open('w')
        process=subprocess.Popen([app.XRAY,'run','-config',str(p)],stdout=log,stderr=log)
        try:
            time.sleep(1)
            result=subprocess.run(['curl','-sS','--max-time','25','--proxy','socks5h://127.0.0.1:'+str(port),'https://api.ipify.org'],capture_output=True,text=True)
            if result.returncode or result.stdout.strip()!=s['public_ip']:
                print((w/(kind+'.log')).read_text()[-2500:]);raise RuntimeError(kind+' egress failed: '+result.stderr[:200])
            print('PASS:',kind,'authenticated egress IP',result.stdout.strip())
            # The proxy must reject private and metadata addresses.
            denied=subprocess.run(['curl','-sS','--max-time','5','--proxy','socks5h://127.0.0.1:'+str(port),'http://169.254.169.254/opc/v2/instance/'],capture_output=True,text=True)
            assert denied.returncode,'Metadata request unexpectedly succeeded'
            print('PASS:',kind,'metadata access denied')
            if kind=='websocket':
                request('/api/users/'+uid,'PUT',{'name':'temporary-acceptance','enabled':False})
                time.sleep(11)
                denied=subprocess.run(['curl','-sS','--max-time','7','--proxy','socks5h://127.0.0.1:'+str(port),'https://api.ipify.org'],capture_output=True,text=True)
                assert denied.returncode,'Disabled user unexpectedly connected'
                print('PASS: disabled user rejected by live core')
        finally:
            process.terminate();process.wait(timeout=5);log.close()
    users=request('/api/overview')['users'];test=next(x for x in users if x['id']==uid)
    assert test['upload']>0 and test['download']>0
    print('PASS: persisted per-user traffic',test['upload'],test['download'])
finally:
    request('/api/users/'+uid,'DELETE')
    request('/api/logout','POST',{})
    work.cleanup()
