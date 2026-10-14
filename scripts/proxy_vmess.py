"""Bounded VMess link parsing and public-endpoint configuration for the importer."""
import base64
import ipaddress
import json
import re
import socket
import uuid


class InvalidProxy(Exception):
    pass


FIELDS={'address','port','uuid','security','network','tls','server_name','host','path','alpn','fingerprint'}
PUBLIC_FIELDS=('network','security','server_name','host','path','alpn','fingerprint')


def visible(value,maximum=255):
    if not isinstance(value,str) or len(value.encode())>maximum or any(ord(c)<32 or ord(c)==127 for c in value):
        raise InvalidProxy('VMess 字段格式或长度不正确')
    return value


def address(value):
    value=visible(value,253)
    try:
        ip=ipaddress.ip_address(value)
        if ip.version!=4 or not ip.is_global or ip.is_multicast or str(ip)!=value:
            raise InvalidProxy('VMess 服务器必须使用公网 IPv4 或域名')
        return value
    except ValueError:
        pass
    try:value=value.encode('idna').decode('ascii').lower().rstrip('.')
    except UnicodeError:raise InvalidProxy('VMess 服务器域名不正确') from None
    if len(value)>253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?',value):
        raise InvalidProxy('VMess 服务器必须使用公网 IPv4 或有效域名')
    if value.endswith(('.localhost','.local','.internal','.invalid','.test')):
        raise InvalidProxy('不支持本地或保留域名')
    return value


def validate(p):
    if not isinstance(p,dict) or set(p)!=FIELDS:raise InvalidProxy('VMess 代理字段不正确')
    if address(p['address'])!=p['address']:raise InvalidProxy('VMess 服务器地址需要规范化')
    if type(p['port']) is not int or not 1<=p['port']<=65535:raise InvalidProxy('VMess 端口不正确')
    if not isinstance(p['uuid'],str) or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',p['uuid']):
        raise InvalidProxy('VMess UUID 不正确')
    if p['security'] not in ('auto','aes-128-gcm','chacha20-poly1305','none','zero'):
        raise InvalidProxy('不支持此 VMess 加密方式')
    if p['network'] not in ('tcp','ws','grpc'):raise InvalidProxy('VMess 支持 TCP、WebSocket 和 gRPC 传输')
    if type(p['tls']) is not bool:raise InvalidProxy('VMess TLS 开关不正确')
    for k in ('server_name','host'):
        value=visible(p[k],253)
        if value and not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?',value):
            raise InvalidProxy('VMess SNI / Host 格式不正确')
    path=visible(p['path'],1024)
    if p['network']=='ws' and not path.startswith('/'):raise InvalidProxy('WebSocket 路径必须以 / 开头')
    if p['network']=='grpc' and not re.fullmatch(r'[A-Za-z0-9_.-]{1,200}',path):raise InvalidProxy('gRPC 服务名不正确')
    if p['network']=='tcp' and (path or p['host']):raise InvalidProxy('TCP 模式暂不支持 HTTP 伪装或路径')
    alpn=visible(p['alpn'],100)
    if alpn and any(a not in ('h2','http/1.1') for a in alpn.split(',')):raise InvalidProxy('不支持此 ALPN 配置')
    if p['fingerprint'] not in ('','chrome','firefox','safari','ios','android','edge','random','randomized'):
        raise InvalidProxy('不支持此 TLS 指纹')
    if not p['tls'] and (p['server_name'] or p['alpn'] or p['fingerprint']):
        raise InvalidProxy('SNI、ALPN 和 TLS 指纹需要开启 TLS')


def parse_links(text):
    if not isinstance(text,str) or not 1<=len(text.encode())<=12000:raise InvalidProxy('VMess 链接列表过长或为空')
    result=[];seen=set()
    for line in text.splitlines():
        line=line.strip()
        if not line:continue
        if len(result)>=20:raise InvalidProxy('每次最多导入 20 个代理')
        if not line.startswith('vmess://'):raise InvalidProxy('每行必须是一个 vmess:// 分享链接')
        encoded=line[8:].split('#',1)[0]
        if not re.fullmatch(r'[A-Za-z0-9_+/=-]{1,11000}',encoded):raise InvalidProxy('VMess 分享链接编码不正确')
        try:
            data=base64.b64decode(encoded+'='*(-len(encoded)%4),altchars=b'-_',validate=True)
            link=json.loads(data)
        except (ValueError,UnicodeError):raise InvalidProxy('VMess 分享链接无法解析') from None
        if not isinstance(link,dict):raise InvalidProxy('VMess 链接内容必须是对象')
        if set(link)-{'v','ps','add','port','id','aid','scy','net','type','host','path','tls','sni','alpn','fp','allowInsecure','serviceName','mode'}:
            raise InvalidProxy('VMess 链接含有未支持的字段，请使用标准 v2rayN JSON 分享格式')
        if str(link.get('v','2')) not in ('','2'):raise InvalidProxy('仅支持 VMess v2 分享格式')
        if str(link.get('aid','0')) not in ('','0'):raise InvalidProxy('仅支持 VMess AEAD，alterId 必须为 0')
        if link.get('allowInsecure',False) not in (False,0,'0','false',''):raise InvalidProxy('不支持跳过 TLS 证书验证')
        if link.get('mode','') not in ('','gun'):raise InvalidProxy('暂不支持 gRPC multiMode')
        network=link.get('net','tcp')
        if network=='raw':network='tcp'
        if link.get('type','none') not in ('','none') and not (network=='grpc' and link['type']=='gun'):
            raise InvalidProxy('不支持此 VMess 伪装类型')
        try:
            ident=str(uuid.UUID(link.get('id','')))
            raw_port=link.get('port','')
            if not re.fullmatch(r'[0-9]{1,5}',str(raw_port)):raise ValueError()
            port=int(raw_port)
        except (ValueError,TypeError,AttributeError):raise InvalidProxy('VMess UUID 或端口不正确') from None
        tls=link.get('tls','')
        if tls not in ('','none','tls'):raise InvalidProxy('VMess 传输安全仅支持无 TLS 或 TLS')
        path=link.get('path','')
        if network=='ws':path=path or '/'
        elif network=='grpc':path=link.get('serviceName',path)
        p={'address':address(link.get('add','')),'port':port,'uuid':ident,'security':link.get('scy') or 'auto',
           'network':network,'tls':tls=='tls','server_name':link.get('sni',''),'host':link.get('host',''),
           'path':path,
           'alpn':link.get('alpn',''),'fingerprint':link.get('fp','')}
        validate(p)
        key=(p['address'],p['port'])
        if key in seen:raise InvalidProxy('列表包含重复地址和端口')
        seen.add(key);result.append(p)
    if not result:raise InvalidProxy('请填写至少一个 VMess 链接')
    return result


def resolve_public(host):
    # The returned IPv4 is pinned in the actual outbound, preventing a later DNS
    # response from turning a verified public hostname into a private target.
    host=address(host)
    try:return str(ipaddress.IPv4Address(host))
    except ValueError:pass
    try:answers=socket.getaddrinfo(host,None,socket.AF_INET,socket.SOCK_STREAM)
    except OSError:raise InvalidProxy('VMess 服务器域名解析失败') from None
    ips=sorted({a[4][0] for a in answers})
    if not ips:raise InvalidProxy('VMess 服务器没有 IPv4 地址')
    for ip in ips:
        value=ipaddress.ip_address(ip)
        if not value.is_global or value.is_multicast:raise InvalidProxy('VMess 域名解析包含非公网地址')
    return ips[0]


def outbound(p,ip):
    validate(p)
    if address(ip)!=ip or not isinstance(ipaddress.ip_address(ip),ipaddress.IPv4Address):raise InvalidProxy('VMess 服务器解析地址无效')
    stream={'network':p['network'],'security':'tls' if p['tls'] else 'none'}
    if p['network']=='ws':stream['wsSettings']={'path':p['path'],'headers':{'Host':p['host'] or p['address']}}
    if p['network']=='grpc':stream['grpcSettings']={'serviceName':p['path'],'authority':p['host'] or p['server_name'] or p['address']}
    if p['tls']:
        stream['tlsSettings']={'serverName':p['server_name'] or p['host'] or p['address'],'allowInsecure':False,'useSystemCA':True}
        if p['alpn']:stream['tlsSettings']['alpn']=p['alpn'].split(',')
        elif p['network']=='grpc':stream['tlsSettings']['alpn']=['h2']
        if p['fingerprint']:stream['tlsSettings']['fingerprint']=p['fingerprint']
    return {'protocol':'vmess','settings':{'vnext':[{'address':ip,'port':p['port'],'users':[{'id':p['uuid'],'security':p['security']}]}]},'streamSettings':stream}
