"""Xdistribute Gateway: local control plane for a pinned Xray-core.

No shell interpolation, arbitrary commands, or remote config URLs are accepted.
Xray starts with zero clients; SQLite is the source of truth for live users.
"""
from __future__ import annotations
import asyncio, base64, contextlib, hashlib, hmac, io, json, logging, os, re, secrets, signal, sqlite3, subprocess, tempfile, threading, time, uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import quote, urlencode
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ConfigDict
import qrcode

ROOT = Path(__file__).resolve().parent
STATE = Path(os.environ.get('XG_STATE', '/var/lib/xray-gateway'))
SETTINGS = Path(os.environ.get('XG_SETTINGS', '/etc/xray-gateway/settings.json'))
XRAY = os.environ.get('XG_XRAY', '/usr/local/lib/xray-gateway/xray')
API = os.environ.get('XG_API', '127.0.0.1:10085')
LOCK = threading.RLock()
HEALTH = {'core': False, 'updated': 0, 'error': '等待连接', 'version': '26.3.27'}
RATE = defaultdict(deque)
POLL = 5

def config():
    value = json.loads(SETTINGS.read_text())
    if 'admin_origin' in value:
        match = re.fullmatch(r'https://([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*)(?::([0-9]{1,5}))?', value['admin_origin']) if isinstance(value['admin_origin'], str) else None
        if not match or len(match[1]) > 253 or (match[2] is not None and not 1 <= int(match[2]) <= 65535):
            raise ValueError('admin_origin requires a canonical HTTPS DNS origin without a path')
        port=int(match[2]) if match[2] is not None else 443
        value['admin_origin']='https://'+match[1]+('' if port==443 else ':'+str(port))
    return value

@contextlib.contextmanager
def db():
    c = sqlite3.connect(STATE / 'gateway.sqlite', timeout=15)
    try:
        c.row_factory = sqlite3.Row
        c.execute('PRAGMA foreign_keys=ON')
        # sqlite3's context manager commits/rolls back but does not close.
        with c:
            yield c
    finally:
        c.close()

def init_db():
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with db() as c:
        c.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS admin(id INTEGER PRIMARY KEY CHECK(id=1), password TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,name TEXT NOT NULL,uuid TEXT NOT NULL UNIQUE,
          token TEXT NOT NULL UNIQUE,enabled INTEGER NOT NULL DEFAULT 1,quota INTEGER NOT NULL DEFAULT 0,
          expires INTEGER NOT NULL DEFAULT 0,upload INTEGER NOT NULL DEFAULT 0,download INTEGER NOT NULL DEFAULT 0,
          created INTEGER NOT NULL,deleted INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS sessions(hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL,generation TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS samples(ts INTEGER NOT NULL,upload INTEGER NOT NULL,download INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        ''')
    os.chmod(STATE / 'gateway.sqlite', 0o600)

def password_hash(password):
    salt=secrets.token_bytes(16)
    value=hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1,dklen=32)
    return salt.hex()+':'+value.hex()

def password_check(password, encoded):
    salt, expected=encoded.split(':')
    value=hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1,dklen=32)
    return hmac.compare_digest(value.hex(), expected)

def audit(c, action, detail=''):
    c.execute('INSERT INTO events(ts,action,detail) VALUES(?,?,?)',(int(time.time()),action,detail))
    c.execute('DELETE FROM events WHERE id < (SELECT COALESCE(MAX(id),0)-2000 FROM events)')

def active(u, now=None):
    now=now or int(time.time())
    return bool(not u['deleted'] and u['enabled'] and (not u['expires'] or u['expires']>now) and (not u['quota'] or u['upload']+u['download']<u['quota']))

def user_status(u):
    if not u['enabled']: return 'disabled'
    if u['expires'] and u['expires']<=time.time(): return 'expired'
    if u['quota'] and u['upload']+u['download']>=u['quota']: return 'exhausted'
    return 'active'

def public_user(u):
    return {k:u[k] for k in ('id','name','enabled','quota','expires','upload','download','created')} | {'status':user_status(u)}

def get_user(c, uid):
    u=c.execute('SELECT * FROM users WHERE id=? AND deleted=0',(uid,)).fetchone()
    if not u: raise HTTPException(404,'用户不存在')
    return u

def links(u):
    s=config(); domain=s['domain']; name=u['name']
    common={'encryption':'none','fp':'chrome','sni':s['reality_sni'],'pbk':s['reality_public'],'sid':s['short_id'],'type':'tcp','security':'reality','flow':'xtls-rprx-vision'}
    reality=f"vless://{u['uuid']}@{s['public_ip']}:443?{urlencode(common)}#{quote(name+' · REALITY')}"
    ws={'encryption':'none','security':'tls','sni':domain,'type':'ws','host':domain,'path':s['ws_path']}
    websocket=f"vless://{u['uuid']}@{domain}:443?{urlencode(ws)}#{quote(name+' · HTTPS')}"
    return {'reality':reality,'websocket':websocket,'subscription':f"https://{domain}/s/{u['token']}"}

def xapi(command, *args):
    result=subprocess.run([XRAY,'api',command,'--server='+API,'--timeout=3',*args],capture_output=True,text=True,timeout=5)
    if result.returncode: raise RuntimeError('Xray API unavailable: '+command)
    return result.stdout

def generation():
    p=subprocess.run(['systemctl','show','xray-gateway-core','-p','MainPID','--value'],capture_output=True,text=True,timeout=3)
    pid=int(p.stdout.strip() or 0)
    if pid<=1: raise RuntimeError('Xray core is not running')
    return str(pid)+':'+Path(f'/proc/{pid}/stat').read_text().split()[21]

def restart_core():
    # Terminate only our own exact binary. systemd Restart=always brings it back.
    pid=int(generation().split(':')[0])
    if Path(f'/proc/{pid}/exe').resolve()!=Path(XRAY).resolve(): raise RuntimeError('Unexpected core executable')
    os.kill(pid, signal.SIGTERM)

def sample_stats(c, gen):
    payload=json.loads(xapi('statsquery','-pattern','user>>>'))
    delta_up=delta_down=0
    for stat in payload.get('stat',[]):
        name=stat['name']; val=int(stat.get('value',0))
        m=re.fullmatch(r'user>>>([0-9a-f]{32})\.([0-9a-f]{8})@(reality|websocket)>>>traffic>>>(uplink|downlink)',name)
        if not m: continue
        old=c.execute('SELECT value,generation FROM counters WHERE name=?',(name,)).fetchone()
        delta=val if not old or old['generation']!=gen or val<old['value'] else val-old['value']
        c.execute('INSERT OR REPLACE INTO counters VALUES(?,?,?)',(name,val,gen))
        col='upload' if m[4]=='uplink' else 'download'
        c.execute(f'UPDATE users SET {col}={col}+? WHERE id=?',(delta,m[1]))
        if col=='upload': delta_up+=delta
        else: delta_down+=delta
    c.execute('INSERT INTO samples VALUES(?,?,?)',(int(time.time()),delta_up,delta_down))
    c.execute('DELETE FROM samples WHERE ts<?',(int(time.time())-7*86400,))
    return delta_up, delta_down

def desired_users(c, tag):
    return {f"{u['id']}.{u['uuid'][:8]}@{tag}":u for u in c.execute('SELECT * FROM users') if active(u)}

def live_users(tag):
    payload=json.loads(xapi('inbounduser','-tag='+tag))
    users=payload.get('users',[])
    return {u['email']:u for u in users}

def reconcile(c):
    plans=[]
    for tag in ('reality','websocket'):
        desired=desired_users(c,tag); current=live_users(tag)
        remove=set(current)-set(desired); add=set(desired)-set(current)
        plans.append((tag,desired,remove,add))
    if any(p[2] for p in plans):
        # Removal alone leaves established streams alive. Restart guarantees revocation.
        restart_core()
        audit(c,'core_restart','凭据撤销、停用、到期或配额触发；现有连接将重新建立')
        return False
    for tag,desired,remove,add in plans:
        if not add: continue
        clients=[{'id':desired[e]['uuid'],'email':e,'level':0,**({'flow':'xtls-rprx-vision'} if tag=='reality' else {})} for e in sorted(add)]
        value={'inbounds':[{'tag':tag,'listen':'127.0.0.1','port':10443 if tag=='reality' else 10080,'protocol':'vless','settings':{'clients':clients,'decryption':'none'}}]}
        with tempfile.NamedTemporaryFile('w',dir=STATE,suffix='.json') as f:
            json.dump(value,f); f.flush()
            output=xapi('adu',f.name)
            if f'Added {len(clients)} user(s) in total.' not in output: raise RuntimeError('Could not add all users')
    return True

def poll_once():
    with LOCK, db() as c:
        gen=generation()
        up,down=sample_stats(c,gen)
        ok=reconcile(c)
        HEALTH.update(core=ok,updated=int(time.time()),error='' if ok else '正在应用访问权限',upload_rate=up/POLL,download_rate=down/POLL)

async def worker():
    while True:
        try: await asyncio.to_thread(poll_once)
        except Exception as exc:
            HEALTH.update(core=False,error=str(exc)[:100])
            logging.warning('Control loop: %s',type(exc).__name__)
        await asyncio.sleep(POLL)

@asynccontextmanager
async def lifespan(app):
    init_db(); task=asyncio.create_task(worker())
    yield
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError): await task

app=FastAPI(lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)

@app.middleware('http')
async def protection(request:Request, call_next):
    if int(request.headers.get('content-length','0') or 0)>16384:
        return JSONResponse({'detail':'请求过大'},status_code=413)
    if request.method not in ('GET','HEAD','OPTIONS'):
        origin=request.headers.get('origin')
        settings=config()
        if origin!=settings.get('admin_origin',settings['origin']):
            return JSONResponse({'detail':'来源校验失败'},status_code=403)
    response=await call_next(request)
    response.headers.update({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Cache-Control':'no-store','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
    return response

def auth(request, write=False):
    token=request.cookies.get('xg_session','')
    with db() as c:
        row=c.execute('SELECT * FROM sessions WHERE hash=? AND expires>?',(hashlib.sha256(token.encode()).hexdigest(),time.time())).fetchone()
    if not row: raise HTTPException(401,'请先登录')
    if write and not hmac.compare_digest(request.headers.get('x-csrf-token',''),row['csrf']): raise HTTPException(403,'请求校验失败，请刷新页面')
    return row

class Strict(BaseModel):
    model_config=ConfigDict(extra='forbid')
class Login(Strict):
    username: str=Field(max_length=64)
    password: str=Field(max_length=256)
class UserInput(Strict):
    name: str=Field(min_length=1,max_length=60)
    enabled: bool=True
    quota: int=Field(default=0,ge=0,le=10**16)
    expires: int=Field(default=0,ge=0,le=4102444800)
class PasswordInput(Strict):
    current_password:str=Field(max_length=256)
    new_password:str=Field(min_length=16,max_length=256)

@app.post('/api/login')
def login(data:Login,request:Request,response:Response):
    ip=request.client.host; now=time.monotonic()
    with LOCK:
        if len(RATE)>10000: RATE.clear()
        q=RATE[ip]
        while q and q[0]<now-900:q.popleft()
        if len(q)>=8: raise HTTPException(429,'尝试过于频繁，请 15 分钟后重试')
        with db() as c:
            row=c.execute('SELECT password FROM admin WHERE id=1').fetchone()
            ok=row and password_check(data.password,row['password']) and data.username=='admin'
            if not ok:
                q.append(now); audit(c,'login_failed',ip)
            else:
                q.clear(); token=secrets.token_urlsafe(32); csrf=secrets.token_urlsafe(32)
                c.execute('DELETE FROM sessions WHERE expires<?',(time.time(),))
                c.execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),csrf,int(time.time())+8*3600))
                audit(c,'login',ip)
        if not ok: raise HTTPException(401,'账号或密码错误')
    response.set_cookie('xg_session',token,secure=True,httponly=True,samesite='strict',max_age=8*3600,path='/')
    return {'csrf':csrf,'username':'admin'}

@app.get('/api/session')
def session(request:Request):
    row=auth(request); return {'csrf':row['csrf'],'username':'admin'}

@app.post('/api/logout')
def logout(request:Request,response:Response):
    auth(request,True)
    with db() as c:c.execute('DELETE FROM sessions WHERE hash=?',(hashlib.sha256(request.cookies['xg_session'].encode()).hexdigest(),))
    response.delete_cookie('xg_session',secure=True,httponly=True,samesite='strict'); return {'ok':True}

@app.get('/api/overview')
def overview(request:Request):
    auth(request)
    with db() as c:
        users=[public_user(u) for u in c.execute('SELECT * FROM users WHERE deleted=0 ORDER BY created')]
        totals=c.execute('SELECT COALESCE(SUM(upload),0),COALESCE(SUM(download),0) FROM users').fetchone()
        samples=[dict(r) for r in c.execute('SELECT (ts/60)*60 AS ts,SUM(upload) AS upload,SUM(download) AS download FROM samples WHERE ts>? GROUP BY ts/60 ORDER BY ts/60',(time.time()-3600,))]
        events=[dict(r) for r in c.execute('SELECT ts,action,detail FROM events ORDER BY id DESC LIMIT 30')]
    return {'health':HEALTH,'users':users,'totals':{'upload':totals[0],'download':totals[1]},'samples':samples,'events':events,'server':{k:config()[k] for k in ('domain','public_ip','reality_sni')}}

@app.post('/api/users')
def create_user(data:UserInput,request:Request):
    auth(request,True); name=data.name.strip()
    if not name or any(ord(c)<32 for c in name): raise HTTPException(422,'请输入有效名称')
    uid=uuid.uuid4().hex
    with LOCK,db() as c:
        if c.execute('SELECT COUNT(*) FROM users WHERE deleted=0').fetchone()[0]>=500: raise HTTPException(409,'最多支持 500 位用户')
        c.execute('INSERT INTO users(id,name,uuid,token,enabled,quota,expires,created) VALUES(?,?,?,?,?,?,?,?)',(uid,name,str(uuid.uuid4()),secrets.token_urlsafe(32),int(data.enabled),data.quota,data.expires,int(time.time())))
        audit(c,'user_created',name)
    return {'id':uid}

@app.put('/api/users/{uid}')
def update_user(uid:str,data:UserInput,request:Request):
    auth(request,True); name=data.name.strip()
    if not name or any(ord(c)<32 for c in name): raise HTTPException(422,'请输入有效名称')
    with LOCK,db() as c:
        get_user(c,uid)
        c.execute('UPDATE users SET name=?,enabled=?,quota=?,expires=? WHERE id=?',(name,int(data.enabled),data.quota,data.expires,uid))
        audit(c,'user_updated',name)
    return {'ok':True}

@app.delete('/api/users/{uid}')
def delete_user(uid:str,request:Request):
    auth(request,True)
    with LOCK,db() as c:
        u=get_user(c,uid);c.execute('UPDATE users SET deleted=1,enabled=0,token=? WHERE id=?',(secrets.token_urlsafe(32),uid));audit(c,'user_deleted',u['name'])
    return {'ok':True}

@app.post('/api/users/{uid}/rotate')
def rotate_user(uid:str,request:Request):
    auth(request,True)
    with LOCK,db() as c:
        u=get_user(c,uid);c.execute('UPDATE users SET uuid=?,token=? WHERE id=?',(str(uuid.uuid4()),secrets.token_urlsafe(32),uid));audit(c,'credentials_rotated',u['name'])
    return {'ok':True}

@app.post('/api/users/{uid}/reset-traffic')
def reset_traffic(uid:str,request:Request):
    auth(request,True)
    with LOCK,db() as c:
        u=get_user(c,uid); sample_stats(c,generation());c.execute('UPDATE users SET upload=0,download=0 WHERE id=?',(uid,));audit(c,'traffic_reset',u['name'])
    return {'ok':True}

@app.get('/api/users/{uid}/links')
def user_links(uid:str,request:Request):
    auth(request)
    with db() as c:u=get_user(c,uid)
    return links(u)

@app.get('/api/users/{uid}/qr/{kind}')
def user_qr(uid:str,kind:str,request:Request):
    auth(request)
    if kind not in ('subscription','reality','websocket'):raise HTTPException(404)
    with db() as c:u=get_user(c,uid)
    buf=io.BytesIO();qrcode.make(links(u)[kind]).save(buf,format='PNG')
    return Response(buf.getvalue(),media_type='image/png')

@app.post('/api/password')
def change_password(data:PasswordInput,request:Request,response:Response):
    auth(request,True)
    with LOCK,db() as c:
        old=c.execute('SELECT password FROM admin WHERE id=1').fetchone()[0]
        if not password_check(data.current_password,old):raise HTTPException(403,'当前密码错误')
        c.execute('UPDATE admin SET password=? WHERE id=1',(password_hash(data.new_password),));c.execute('DELETE FROM sessions');audit(c,'password_changed')
    response.delete_cookie('xg_session',secure=True,httponly=True,samesite='strict');return {'ok':True}

@app.get('/s/{token}')
def subscription(token:str):
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}',token):raise HTTPException(404)
    with db() as c:u=c.execute('SELECT * FROM users WHERE token=? AND deleted=0',(token,)).fetchone()
    if not u:raise HTTPException(404)
    if not active(u):raise HTTPException(403,'Subscription inactive')
    node=links(u); body=base64.b64encode((node['reality']+'\n'+node['websocket']+'\n').encode())
    return Response(body,media_type='text/plain',headers={'subscription-userinfo':f"upload={u['upload']}; download={u['download']}; total={u['quota']}; expire={u['expires']}",'profile-update-interval':'6','content-disposition':'attachment; filename="xdistribute.txt"'})

@app.get('/healthz')
def healthz():return {'status':'ok'}

@app.get('/')
def index():return FileResponse(ROOT/'static/index.html')

app.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')
