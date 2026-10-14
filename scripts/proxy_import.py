#!/usr/bin/env python3
"""Fixed-proxy import worker. Root-owned code, bounded encrypted requests, fixed targets.

The panel never receives root privileges. A preview only probes public endpoints;
apply accepts a previously verified, short-lived root-owned snapshot. Configuration
updates retain existing routes and users, with a recoverable transaction journal.
"""
import base64
import concurrent.futures
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import threading
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path('/var/lib/xray-gateway-import')
INBOX = Path('/var/lib/xray-gateway/proxy-import/request.xgb')
KEY = Path('/etc/xray-gateway/security.key')
CONTEXT = b'xcli:proxy-import:request:v1'
FILES = {'settings': Path('/etc/xray-gateway/settings.json'),
         'core': Path('/etc/xray-gateway/core.json'),
         'monitor': Path('/etc/xcli-monitor/monitor.json'),
         'nginx': Path('/etc/nginx/nginx.conf'),
         'locations': Path('/etc/nginx/xcli-import-locations.conf'),
         'pool': Path('/etc/xray-gateway/imported-proxies.json')}
COUNTRIES = {'US':'美国','JP':'日本','SG':'新加坡','HK':'香港','TW':'台湾','KR':'韩国',
             'TH':'泰国','MY':'马来西亚','IN':'印度','CA':'加拿大','GB':'英国','DE':'德国',
             'FR':'法国','NL':'荷兰','AU':'澳大利亚'}
TTL = 900


class ImportErrorSafe(Exception):
    pass


def stamp():
    return int(time.time())


def read_regular(path, limit=1024*1024):
    # Reject symlinks/FIFOs before reading files in the unprivileged inbox.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ImportErrorSafe('文件类型或大小不符合要求')
        data = f.read(limit+1)
        if len(data)>limit:
            raise ImportErrorSafe('文件过大')
        return data


def atomic(path, data, mode=0o600, uid=0, gid=0):
    if isinstance(data, str): data=data.encode()
    temporary=path.with_name(path.name+'.'+secrets.token_hex(8))
    try:
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
        with os.fdopen(fd,'wb') as f:
            os.fchown(f.fileno(),uid,gid);os.fchmod(f.fileno(),mode)
            f.write(data);f.flush();os.fsync(f.fileno())
        os.replace(temporary,path)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:temporary.unlink(missing_ok=True)


def unseal(data,key):
    if len(data)<32 or data[:4]!=b'XGB1':raise ImportErrorSafe('导入请求校验失败')
    return json.loads(AESGCM(key).decrypt(data[4:16],data[32:]+data[16:32],CONTEXT))


def public_ip(value):
    try:ip=ipaddress.ip_address(value)
    except ValueError:raise ImportErrorSafe('仅支持公网 IPv4 地址') from None
    if ip.version!=4 or not ip.is_global or ip.is_multicast or str(ip)!=value:
        raise ImportErrorSafe('仅支持公网 IPv4 地址')
    return value


def validate(proxies, protocol, label):
    if protocol not in ('socks','http'):raise ImportErrorSafe('请选择 SOCKS5 或 HTTP 协议')
    if not isinstance(label,str) or not 1<=len(label)<=30 or any(ord(c)<32 for c in label):
        raise ImportErrorSafe('名称前缀需为 1～30 个可见字符')
    if not isinstance(proxies,list) or not 1<=len(proxies)<=20:raise ImportErrorSafe('每次可导入 1～20 个代理')
    seen=set()
    for p in proxies:
        if not isinstance(p,dict) or set(p)!= {'address','port','username','password'}:raise ImportErrorSafe('代理字段不正确')
        public_ip(p['address'])
        if type(p['port']) is not int or not 1<=p['port']<=65535:raise ImportErrorSafe('代理端口不正确')
        for k in ('username','password'):
            if not isinstance(p[k],str) or not 1<=len(p[k].encode())<=255 or any(ord(c)<32 or ord(c)==127 for c in p[k]):
                raise ImportErrorSafe('账号或密码格式不正确')
        if ':' in p['username']:raise ImportErrorSafe('账号不能包含冒号')
        peer=(p['address'],p['port'])
        if peer in seen:raise ImportErrorSafe('列表包含重复地址和端口')
        seen.add(peer)


def existing_peers(core):
    result=set()
    for outbound in core.get('outbounds',[]):
        if outbound.get('protocol') in ('socks','http'):
            for s in outbound.get('settings',{}).get('servers',[]):
                result.add((s.get('address'),s.get('port')))
    return result


def check_capacity(settings,core,proxies):
    if len(settings.get('residential_exits',[]))+len(proxies)>40:
        raise ImportErrorSafe('固定和动态入口合计最多 40 个，请减少本次导入数量')
    peers=existing_peers(core)
    if any((p['address'],p['port']) in peers for p in proxies):
        raise ImportErrorSafe('列表包含已接入的代理地址和端口，请移除重复项')
    if any(not r.get('inboundTag') and not (r.get('ip') and r.get('outboundTag')=='blocked') for r in core['routing']['rules']):
        raise ImportErrorSafe('现有自定义全局路由需要人工检查，未修改配置')


def probe(p,protocol):
    # curl reads credentials through stdin; neither command arguments nor reports contain them.
    def quote(s):return '"'+s.replace('\\','\\\\').replace('"','\\"')+'"'
    config='proxy = '+quote(('socks5h' if protocol=='socks' else 'http')+'://'+p['address']+':'+str(p['port']))+'\nproxy-user = '+quote(p['username']+':'+p['password'])+'\n'
    user=pwd.getpwnam('xgateway')
    def get(url,extra=()):
        return subprocess.run(['/usr/bin/curl','-q','--config','-','--noproxy','','-fsS','--connect-timeout','8',
            '--max-time','20','--max-filesize','8192',*extra,url],input=config.encode(),capture_output=True,timeout=24,
            user=user.pw_uid,group=user.pw_gid,extra_groups=[],env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'})
    row={'address':p['address'],'port':p['port'],'protocol':protocol,'status':'failed','error':'代理认证或 HTTPS 连接失败'}
    try:
        started=time.monotonic();r=get('https://www.cloudflare.com/cdn-cgi/trace')
        if r.returncode:return row
        fields=dict(line.split('=',1) for line in r.stdout.decode(errors='replace').splitlines() if '=' in line)
        actual=public_ip(fields.get('ip',''));country=fields.get('loc','')
        if not re.fullmatch('[A-Z]{2}',country):return row
        row.update(exit_ip=actual,country=country,https_ms=round((time.monotonic()-started)*1000))
        wire=struct.pack('!HHHHHH',1234,256,1,0,0,0)+b'\x07example\x03com\x00'+struct.pack('!HH',1,1)
        started=time.monotonic();r=get('https://1.1.1.1/dns-query?dns='+base64.urlsafe_b64encode(wire).decode().rstrip('='),('-H','accept: application/dns-message'))
        if r.returncode or len(r.stdout)<12 or struct.unpack('!H',r.stdout[:2])[0]!=1234 or not struct.unpack('!H',r.stdout[6:8])[0]:
            row['error']='加密 DNS 测试失败';return row
        row.update(status='verified',error='',doh_ms=round((time.monotonic()-started)*1000))
    except Exception:
        return row
    return row


def read_config():
    result={}
    for name,path in FILES.items():
        if path.exists() or path.is_symlink():result[name]=read_regular(path)
    for name in ('settings','core','monitor','nginx'):
        if name not in result:raise ImportErrorSafe('服务器配置不完整，未修改配置')
    return result


def digests(config):
    return {k:hashlib.sha256(v).hexdigest() for k,v in config.items()}


def configure(old,proxies,protocol,label,rows):
    validate(proxies,protocol,label)
    settings=json.loads(old['settings']);core=json.loads(old['core']);monitor=json.loads(old['monitor'])
    check_capacity(settings,core,proxies)
    if len(rows)!=len(proxies) or any(r.get('status')!='verified' for r in rows):raise ImportErrorSafe('请先通过全部代理检测')
    if not re.fullmatch(r'/connect/[A-Za-z0-9_-]+',settings['ws_path']):raise ImportErrorSafe('现有入口路径需要人工检查')
    tags={x['tag'] for x in core['inbounds']}|{x['tag'] for x in core['outbounds']}
    ports={x.get('port') for x in core['inbounds']};entries=[];locations=old.get('locations',b'').decode()
    pool=json.loads(old.get('pool',b'{"proxies":[]}'))
    for p,row in zip(proxies,rows):
        public_ip(row['exit_ip'])
        if not re.fullmatch('[A-Z]{2}',row['country']):raise ImportErrorSafe('出口地区无效')
        # Reserve 01..26 for original fixed pools and the supported dynamic registry.
        number=next((n for n in range(27,100) if f'residential-{n:02d}' not in tags and f'residential-{n:02d}-exit' not in tags),None)
        port=next((n for n in range(10450,10550) if n not in ports),None)
        if number is None or port is None:raise ImportErrorSafe('没有可用入口编号或端口')
        tag=f'residential-{number:02d}';tags.add(tag);ports.add(port);path=settings['ws_path']+'/'+tag
        entry={'tag':tag,'label':label+' '+str(number)+' · '+COUNTRIES.get(row['country'],row['country']),
            'exit_ip':row['exit_ip'],'country':row['country'],'ws_path':path,'port':port}
        entries.append(entry)
        settings.setdefault('residential_exits',[]).append(entry);monitor.setdefault('residential_exits',[]).append(entry)
        core['inbounds'].append({'tag':tag,'listen':'127.0.0.1','port':port,'protocol':'vless',
            'settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':'ws','wsSettings':{'path':path}}})
        core['outbounds'].append({'tag':tag+'-exit','protocol':protocol,'settings':{'servers':[{'address':p['address'],'port':p['port'],
            'users':[{'user':p['username'],'pass':p['password']}]}]}})
        pool['proxies'].append({**p,'tag':tag,'protocol':protocol,'country':row['country']})
        locations+=f'\nlocation = {path} {{\n    proxy_pass http://127.0.0.1:{port};\n    proxy_http_version 1.1;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection $connection_upgrade;\n    proxy_set_header Host $host;\n    proxy_read_timeout 600s;\n    proxy_send_timeout 600s;\n    proxy_buffering off;\n}}\n'
    rules=core['routing']['rules'];rules.append({'type':'field','inboundTag':[e['tag'] for e in entries],'network':'udp','outboundTag':'blocked'})
    rules.extend({'type':'field','inboundTag':[e['tag']],'network':'tcp','outboundTag':e['tag']+'-exit'} for e in entries)
    nginx=old['nginx'].decode();include='include '+str(FILES['locations'])+';';marker='location = '+settings['ws_path']+' {'
    if 'locations' in old:
        if nginx.count(include)!=1:raise ImportErrorSafe('既有导入入口与 Nginx 配置不一致')
    else:
        if include in nginx or nginx.count(marker)!=1:raise ImportErrorSafe('无法定位 Nginx 入口')
        nginx=nginx.replace(marker,include+'\n        '+marker,1)
    result={'settings':json.dumps(settings).encode(),'core':json.dumps(core).encode(),'monitor':json.dumps(monitor).encode(),
        'nginx':nginx.encode(),'locations':locations.encode(),'pool':json.dumps(pool).encode()}
    if len(result['monitor'])>16384:raise ImportErrorSafe('探测配置容量不足，未修改配置')
    return result,entries


def run(*args,timeout=90):
    r=subprocess.run(list(map(str,args)),capture_output=True,timeout=timeout)
    if r.returncode:raise ImportErrorSafe('服务或配置检查未通过')
    return r.stdout


def preflight():
    result=json.loads(run('/usr/local/lib/xray-gateway/panel-current','--secret-key',KEY,'--monitor-config',FILES['monitor'],'--preflight'))
    return result['database_integrity']=='ok' and result['pending_additions']==result['pending_revocations']==0


def wait_ready(since,expected):
    deadline=time.monotonic()+150
    while time.monotonic()<deadline:
        try:
            report=json.loads(read_regular(Path('/var/lib/xray-gateway-monitor/report.json')))
            if report['updated']>=since and {r['transport'] for r in report['checks']}==expected and report['status']=='healthy' and preflight():return
        except Exception:pass
        time.sleep(2)
    raise ImportErrorSafe('完整入口检查未通过')


def service_start():
    since=stamp();run('systemctl','restart','xray-gateway-core');run('systemctl','start','xray-gateway-panel')
    run('nginx','-t');run('systemctl','reload','nginx');time.sleep(6);run('systemctl','start','xray-gateway-monitor')
    return since


def monitor_tags(config):
    settings=json.loads(config['settings']);monitor=json.loads(config['monitor'])
    return {'reality','websocket'}|({'hysteria2'} if settings.get('hysteria2_port') else set())|{e['tag'] for e in monitor.get('residential_exits',[])}


def rollback(backup):
    manifest=json.loads(read_regular(backup/'manifest.json'))
    current=read_config()
    for name,value in current.items():
        if hashlib.sha256(value).hexdigest() not in manifest['allowed'][name]:
            raise ImportErrorSafe('配置已被其他操作修改，请人工检查回退快照')
    run('systemctl','stop','xray-gateway-monitor','xray-gateway-panel')
    for name,path in FILES.items():
        if name in manifest['metadata']:
            mode,uid,gid=manifest['metadata'][name];atomic(path,read_regular(backup/name),mode,uid,gid)
        else:path.unlink(missing_ok=True)
    since=service_start();wait_ready(since,monitor_tags(read_config()))
    manifest['phase']='rolled_back';atomic(backup/'manifest.json',json.dumps(manifest))


def apply_config(old,new,entries,job_id):
    backup=ROOT/'backups'/job_id;backup.mkdir(mode=0o700)
    metadata={}
    for name,data in old.items():
        info=FILES[name].stat();metadata[name]=[stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid];atomic(backup/name,data)
    manifest={'phase':'prepared','metadata':metadata,'allowed':{name:[hashlib.sha256(new[name]).hexdigest()]+([hashlib.sha256(old[name]).hexdigest()] if name in old else []) for name in FILES}}
    atomic(backup/'manifest.json',json.dumps(manifest))
    with sqlite3.connect('/var/lib/xray-gateway/gateway.sqlite') as db,sqlite3.connect(backup/'gateway.sqlite') as snapshot:db.backup(snapshot)
    (backup/'gateway.sqlite').chmod(0o600)
    atomic(backup/'core.candidate.json',new['core']);atomic(backup/'locations.candidate.conf',new['locations'])
    atomic(backup/'nginx.candidate.conf',new['nginx'].replace(str(FILES['locations']).encode(),str(backup/'locations.candidate.conf').encode()))
    run('/usr/local/lib/xray-gateway/xray','run','-test','-config',backup/'core.candidate.json')
    run('nginx','-t','-c',backup/'nginx.candidate.conf')
    for e in entries:
        with socket.socket() as s:s.bind(('127.0.0.1',e['port']))
    if not preflight():raise ImportErrorSafe('现有用户权限尚未同步完成，请稍后重试')
    manifest['phase']='applying';atomic(backup/'manifest.json',json.dumps(manifest))
    atomic(ROOT/'transaction.json',json.dumps({'id':job_id}))
    try:
        run('systemctl','stop','xray-gateway-monitor','xray-gateway-panel')
        for name,path in FILES.items():
            mode,uid,gid=metadata.get(name,(0o644 if name=='locations' else 0o600,0,0))
            atomic(path,new[name],mode,uid,gid)
        since=service_start();wait_ready(since,monitor_tags(new))
        manifest['phase']='committed';atomic(backup/'manifest.json',json.dumps(manifest))
    except Exception:
        try:rollback(backup)
        except Exception:raise ImportErrorSafe('导入未完成，自动回退需要人工检查；已保留恢复快照') from None
        raise ImportErrorSafe('导入检查未通过，已自动恢复原配置') from None
    finally:
        phase=json.loads(read_regular(backup/'manifest.json'))['phase']
        if phase in ('committed','rolled_back'):(ROOT/'transaction.json').unlink(missing_ok=True)


class Worker:
    def __init__(self):
        self.owner=pwd.getpwnam('xgateway');self.lock=threading.RLock();self.stop=threading.Event()
        self.key=read_regular(KEY,32)
        self.report={'id':'','status':'idle','message':'粘贴代理列表并检测后，即可确认导入','rows':[]}
        try:self.report=json.loads(read_regular(ROOT/'report.json'))
        except FileNotFoundError:pass
        if self.report.get('status') in ('verifying','applying'):
            self.report.update(status='failed',message='上次操作中断，请重新检测')
        self.processed=[]
        try:self.processed=json.loads(read_regular(ROOT/'processed.json'))
        except FileNotFoundError:pass

    def publish(self,**fields):
        with self.lock:
            self.report.update(fields,updated=stamp());atomic(ROOT/'report.json',json.dumps(self.report),0o640,0,self.owner.pw_gid)

    def heartbeat(self):
        while not self.stop.wait(5):
            try:self.publish()
            except Exception:pass

    def preview(self,request):
        (ROOT/'preview.json').unlink(missing_ok=True)
        proxies=request['proxies'];protocol=request['protocol'];label=request['label'];validate(proxies,protocol,label)
        old=read_config();check_capacity(json.loads(old['settings']),json.loads(old['core']),proxies)
        self.publish(status='verifying',message='正在检测认证、HTTPS 和加密 DNS',rows=[])
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:rows=list(pool.map(lambda p:probe(p,protocol),proxies))
        if any(r['status']!='verified' for r in rows):
            self.publish(status='failed',message='部分代理检测失败，未修改现有节点；请修正后重新检测',rows=rows);return
        new,entries=configure(old,proxies,protocol,label,rows)
        for row,entry in zip(rows,entries):row['label']=entry['label']
        atomic(ROOT/'preview.json',json.dumps({'id':request['id'],'expires':stamp()+TTL,'digests':digests(old),
            'proxies':proxies,'protocol':protocol,'label':label,'rows':rows}))
        self.publish(status='ready',message='全部检测通过，确认后加入节点和订阅',rows=rows,expires=stamp()+TTL)

    def apply(self,request):
        preview=json.loads(read_regular(ROOT/'preview.json'))
        if preview['id']!=request.get('preview_id') or preview['expires']<stamp():raise ImportErrorSafe('检测结果已过期，请重新检测')
        with open('/run/lock/xcli-update.lock','a') as lock:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ImportErrorSafe('服务器正在更新，请稍后重新检测') from None
            if (ROOT/'transaction.json').exists():raise ImportErrorSafe('存在未完成的恢复事务，请先检查服务')
            old=read_config()
            if digests(old)!=preview['digests']:raise ImportErrorSafe('服务器配置已变化，请重新检测')
            new,entries=configure(old,preview['proxies'],preview['protocol'],preview['label'],preview['rows'])
            self.publish(status='applying',message='正在保存恢复快照并应用节点，连接可能短暂重连',rows=preview['rows'])
            apply_config(old,new,entries,request['id'])
        self.publish(status='complete',message=f'已添加 {len(entries)} 个节点，请更新客户端订阅',added=len(entries),rows=preview['rows'])
        (ROOT/'preview.json').unlink(missing_ok=True)

    def process(self):
        if not INBOX.parent.exists():return
        # The directory is panel-writable, so pin it while opening the untrusted file.
        parent=os.open(INBOX.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            fd=os.open(INBOX.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
            with os.fdopen(fd,'rb') as f:
                info=os.fstat(f.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size>20000:raise ImportErrorSafe('请求文件不正确')
                data=f.read(20001)
        finally:os.close(parent)
        request=unseal(data,self.key)
        if not re.fullmatch('[0-9a-f]{32}',request.get('id','')):return
        if request['id'] in self.processed:return
        self.processed=(self.processed+[request['id']])[-64:];atomic(ROOT/'processed.json',json.dumps(self.processed))
        self.publish(id=request['id'],rows=[],expires=0,added=0)
        try:
            if type(request.get('requested_at')) is not int or not 0<=stamp()-request['requested_at']<=TTL:raise ImportErrorSafe('请求已过期，请重新检测')
            action=request.get('action')
            if action=='preview':self.preview(request)
            elif action=='apply':self.apply(request)
            else:raise ImportErrorSafe('不支持此操作')
        except ImportErrorSafe as e:self.publish(status='failed',message=str(e))
        except Exception:self.publish(status='failed',message='导入未完成，请检查服务状态后重新检测')

    def recover(self):
        transaction=ROOT/'transaction.json'
        if not transaction.exists():return
        job=json.loads(read_regular(transaction))['id']
        if not re.fullmatch('[0-9a-f]{32}',job):raise ImportErrorSafe('恢复事务无效')
        with open('/run/lock/xcli-update.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            backup=ROOT/'backups'/job;phase=json.loads(read_regular(backup/'manifest.json'))['phase']
            if phase not in ('committed','rolled_back'):rollback(backup)
            transaction.unlink()
            self.publish(status='failed' if phase!='committed' else 'complete',message='上次导入已恢复原配置，请重新检测' if phase!='committed' else '节点已添加，请更新客户端订阅')

    def loop(self):
        self.recover();self.publish();threading.Thread(target=self.heartbeat,daemon=True).start()
        while True:
            try:self.process()
            except Exception:pass  # Untrusted request failures never include credentials in logs.
            try:
                p=ROOT/'preview.json'
                if p.exists() and json.loads(read_regular(p))['expires']<stamp():
                    p.unlink()
                    if self.report.get('status')=='ready':self.publish(status='expired',message='检测结果已过期，请重新检测')
            except Exception:pass
            time.sleep(1)


def main():
    os.umask(0o077)
    if os.geteuid()!=0:raise SystemExit('Root service required')
    owner=pwd.getpwnam('xgateway')
    ROOT.mkdir(mode=0o750,exist_ok=True)
    if ROOT.is_symlink() or ROOT.stat().st_uid!=0:raise SystemExit('Unsafe service state directory')
    os.chown(ROOT,0,owner.pw_gid);os.chmod(ROOT,0o750)
    (ROOT/'backups').mkdir(mode=0o700,exist_ok=True)
    if len(sys.argv)==3 and sys.argv[1]=='rollback' and re.fullmatch('[0-9a-f]{32}',sys.argv[2]):
        with open('/run/lock/xcli-update.lock','a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);rollback(ROOT/'backups'/sys.argv[2])
        print('Previous configuration restored; current users and traffic retained.');return
    if len(sys.argv)!=1:raise SystemExit('Invalid arguments')
    Worker().loop()


if __name__=='__main__':main()
