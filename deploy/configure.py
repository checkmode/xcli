#!/usr/bin/env python3
import sys,os,json,secrets,subprocess,pathlib,pwd
sys.path.insert(0,'/opt/xray-gateway')
import app
uid=pwd.getpwnam('xgateway').pw_uid;gid=pwd.getpwnam('xgateway').pw_gid
settings=pathlib.Path('/etc/xray-gateway/settings.json')
if not settings.exists():
    out=subprocess.check_output(['/usr/local/lib/xray-gateway/xray','x25519'],text=True)
    fields=dict(line.split(': ',1) for line in out.splitlines() if ': ' in line)
    private=fields['PrivateKey'];public=fields.get('Password (PublicKey)') or fields.get('Password') or fields.get('PublicKey')
    if not public:raise SystemExit('Unexpected x25519 output')
    s={'domain':'gateway.example.com','origin':'https://gateway.example.com','public_ip':'203.0.113.2','reality_sni':'www.bing.com','reality_private':private,'reality_public':public,'short_id':secrets.token_hex(8),'ws_path':'/connect/'+secrets.token_hex(12)}
    settings.write_text(json.dumps(s,indent=2));settings.chmod(0o640);os.chown(settings,0,gid)
else:s=json.loads(settings.read_text())
blocked=['0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','192.0.0.0/24','198.18.0.0/15','224.0.0.0/4','240.0.0.0/4','::/128','::1/128','fc00::/7','fe80::/10','ff00::/8']
core={'log':{'loglevel':'warning','access':'none'},'api':{'tag':'api','listen':'127.0.0.1:10085','services':['HandlerService','StatsService']},'stats':{},'policy':{'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True,'handshake':8,'connIdle':300}}},'inbounds':[
{'tag':'reality','listen':'127.0.0.1','port':10443,'protocol':'vless','settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':'tcp','security':'reality','tcpSettings':{'acceptProxyProtocol':True},'realitySettings':{'show':False,'target':s['reality_sni']+':443','xver':0,'serverNames':[s['reality_sni']],'privateKey':s['reality_private'],'shortIds':[s['short_id']],'maxTimeDiff':120000}}},
{'tag':'websocket','listen':'127.0.0.1','port':10080,'protocol':'vless','settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':'ws','wsSettings':{'path':s['ws_path']}}}],
'outbounds':[{'tag':'direct','protocol':'freedom','settings':{'domainStrategy':'UseIPv4'}},{'tag':'blocked','protocol':'blackhole'}],
'routing':{'domainStrategy':'IPOnDemand','rules':[{'type':'field','ip':blocked+['203.0.113.2/32'],'outboundTag':'blocked'}]}}
p=pathlib.Path('/etc/xray-gateway/core.json');p.write_text(json.dumps(core,indent=2));p.chmod(0o640);os.chown(p,0,gid)
app.init_db()
with app.db() as c:
    if not c.execute('SELECT 1 FROM admin').fetchone():
        password=secrets.token_urlsafe(24)
        c.execute('INSERT INTO admin VALUES(1,?)',(app.password_hash(password),))
        cred=pathlib.Path('/root/xray-gateway-admin.txt');cred.write_text('URL: https://gateway.example.com/\nUsername: admin\nPassword: '+password+'\n');cred.chmod(0o600)
for p in pathlib.Path('/var/lib/xray-gateway').iterdir():os.chown(p,uid,gid)
# Dedicated nginx instance configuration: initial host had no existing sites.
nginx=r'''
include /etc/nginx/modules-enabled/*.conf;
user www-data;
worker_processes auto;
pid /run/nginx.pid;
events { worker_connections 4096; }
stream {
    map $ssl_preread_server_name $xg_backend {
        gateway.example.com 127.0.0.1:8443;
        __REALITY_SNI__ 127.0.0.1:10443;
        default 127.0.0.1:9;
    }
    server { listen 443; ssl_preread on; proxy_pass $xg_backend; proxy_protocol on;
      proxy_connect_timeout 8s; proxy_timeout 600s; }
}
http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    server_tokens off;
    access_log off;
    error_log /var/log/nginx/error.log warn;
    sendfile on;
    client_max_body_size 16k;
    keepalive_timeout 30;
    limit_req_zone $binary_remote_addr zone=login:10m rate=6r/m;
    limit_req_zone $binary_remote_addr zone=sub:10m rate=30r/m;
    map $http_upgrade $connection_upgrade { default upgrade; '' close; }
    server {
        listen 80 default_server;
        server_name gateway.example.com;
        location ^~ /.well-known/acme-challenge/ { root /var/www/acme; }
        location / { return 301 https://gateway.example.com$request_uri; }
    }
    server {
        listen 127.0.0.1:8443 ssl proxy_protocol;
        server_name gateway.example.com;
        set_real_ip_from 127.0.0.1;
        real_ip_header proxy_protocol;
        ssl_certificate /etc/letsencrypt/live/gateway.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/gateway.example.com/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_cache shared:SSL:10m;
        ssl_session_tickets off;
        add_header Strict-Transport-Security "max-age=31536000" always;
        location = __WS_PATH__ {
            proxy_pass http://127.0.0.1:10080;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_set_header Host $host;
            proxy_read_timeout 600s;
            proxy_send_timeout 600s;
            proxy_buffering off;
        }
        location = /api/login {
            limit_req zone=login burst=5 nodelay;
            limit_req_status 429;
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header Host gateway.example.com;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Forwarded-Proto https;
        }
        location /s/ {
            limit_req zone=sub burst=10 nodelay;
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header Host gateway.example.com;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Forwarded-Proto https;
        }
        location / {
            proxy_pass http://127.0.0.1:8080;
            proxy_set_header Host gateway.example.com;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Forwarded-Proto https;
        }
    }
}
'''.replace('__WS_PATH__',s['ws_path']).replace('__REALITY_SNI__',s['reality_sni'])
pathlib.Path('/etc/xray-gateway/nginx-ready.conf').write_text(nginx)
print('Settings, core config, administrator, and nginx configuration prepared. Secrets not printed.')
