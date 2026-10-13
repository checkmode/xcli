#!/usr/bin/env python3
import sys,json,uuid,secrets,time,pathlib
sys.path.insert(0,'/opt/xray-gateway')
import app
with app.LOCK,app.db() as c:
    u=c.execute('SELECT * FROM users WHERE deleted=0 ORDER BY created LIMIT 1').fetchone()
    if not u:
        uid=uuid.uuid4().hex
        c.execute('INSERT INTO users(id,name,uuid,token,created) VALUES(?,?,?,?,?)',(uid,'我的设备',str(uuid.uuid4()),secrets.token_urlsafe(32),int(time.time())))
        app.audit(c,'user_created','我的设备')
        u=c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
    data=app.links(u)
    p=pathlib.Path('/root/xray-gateway-client.json');p.write_text(json.dumps(data,ensure_ascii=False,indent=2));p.chmod(0o600)
    for kind,value in data.items():
        p=pathlib.Path('/root/xray-gateway-'+kind+'.png');app.qrcode.make(value).save(p);p.chmod(0o600)
print('Initial user prepared. Private links and QR files stored under /root/.')
