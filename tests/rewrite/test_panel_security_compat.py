"""Test enrollment/recovery on disposable panels, including a decoded QR code."""
import base64
from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest
from urllib.parse import quote

from test_panel_password_compat import LEGACY, RUST, free_port, ready, request, stop


def totp(secret):
    step=int(time.time())//30
    value=hmac.new(base64.b32decode(secret),step.to_bytes(8,'big'),hashlib.sha1).digest()
    offset=value[-1]&15
    return f'{(int.from_bytes(value[offset:offset+4],"big")&0x7fffffff)%1000000:06d}'


def decode_qr(path):
    if shutil.which('zbarimg'):
        return subprocess.check_output(['zbarimg','--quiet','--raw',str(path)],stderr=subprocess.DEVNULL).decode().rstrip('\n')
    try:
        import zxingcpp
        from PIL import Image
    except ImportError:
        return None
    decoded=zxingcpp.read_barcode(Image.open(path))
    if decoded is None: raise AssertionError('QR did not decode')
    return decoded.text


@unittest.skipUnless(LEGACY and RUST and Path(LEGACY).is_file() and Path(RUST).is_file(), 'set legacy and Rust panel paths')
class SecurityCompatibility(unittest.TestCase):
    def test_totp_qr_enrollment_recovery_and_disable(self):
        with tempfile.TemporaryDirectory(prefix='xcli-security-compat-') as folder:
            root=Path(folder);old=root/'old';new=root/'new';old.mkdir();new.mkdir()
            key=root/'key';key.write_bytes(bytes(range(32)));key.chmod(0o600)
            settings=root/'settings.json';settings.write_text(json.dumps({'origin':'https://testserver','domain':'testserver',
                'public_ip':'203.0.113.2','reality_sni':'example.com','reality_public':'p'*43,
                'short_id':'aabbccdd','ws_path':'/connect/test'}))
            password='fixture-password';salt=bytes(range(16))
            encoded=salt.hex()+':'+hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1,dklen=32).hex()
            with closing(sqlite3.connect(old/'gateway.sqlite')) as db:
                db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)')
                db.execute('INSERT INTO admin VALUES(1,?)',(encoded,));db.commit()
            ports=[free_port(),free_port()]
            while ports[0]==ports[1]:ports[1]=free_port()
            legacy=None;rust=None
            try:
                legacy=subprocess.Popen([LEGACY,'--state',str(old),'--settings',str(settings),'--static',str(root),
                    '--secret-key',str(key),'--port',str(ports[0]),'--offline','--no-auto-backup'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                ready(legacy,ports[0])
                source=sqlite3.connect(old/'gateway.sqlite');target=sqlite3.connect(new/'gateway.sqlite')
                try:source.backup(target)
                finally:source.close();target.close()
                rust=subprocess.Popen([RUST,'--experimental','--db',str(new/'gateway.sqlite'),'--secret-key',str(key),
                    '--origin','https://testserver','--settings',str(settings),'--port',str(ports[1])],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                ready(rust,ports[1])
                for index,(port,directory) in enumerate(zip(ports,(old,new))):
                    self.assertEqual(request(port,'/api/security')[0],401)
                    sessions=[]
                    for _ in range(2):
                        status,headers,body=request(port,'/api/login','POST',{'username':'admin','password':password,'code':''})
                        self.assertEqual(status,200);sessions.append((headers['set-cookie'].split(';',1)[0],json.loads(body)['csrf']))
                    cookie,csrf=sessions[0]
                    self.assertEqual(json.loads(request(port,'/api/security',cookie=cookie)[2]),{'enabled':False,'recovery_remaining':0})
                    self.assertEqual(request(port,'/api/security/setup','POST',{'current_password':'wrong'},cookie,csrf)[0],403)
                    status,_,body=request(port,'/api/security/setup','POST',{'current_password':password},cookie,csrf)
                    self.assertEqual(status,200);setup=json.loads(body);secret=setup['secret']
                    self.assertEqual(len(secret),32);self.assertTrue(setup['qr'].startswith('data:image/png;base64,'))
                    qr=root/('synthetic-'+str(index)+'.png');qr.write_bytes(base64.b64decode(setup['qr'].split(',',1)[1]))
                    expected='otpauth://totp/'+quote('testserver:admin',safe='')+'?secret='+secret+'&issuer=testserver&algorithm=SHA1&digits=6&period=30'
                    self.assertTrue(qr.read_bytes().startswith(b'\x89PNG\r\n\x1a\n'))
                    decoded=decode_qr(qr)
                    if os.environ.get('XCLI_REQUIRE_QR_DECODER'):self.assertIsNotNone(decoded,'QR decoder required')
                    if decoded is not None:self.assertEqual(decoded,expected)
                    code=totp(secret)
                    confirmation={'current_password':password,'code':code}
                    self.assertEqual(request(port,'/api/security/enable','POST',confirmation,*sessions[1])[0],409)
                    status,_,body=request(port,'/api/security/enable','POST',confirmation,cookie,csrf)
                    self.assertEqual(status,200);original=json.loads(body)['recovery_codes']
                    self.assertEqual(len(set(original)),10)
                    self.assertEqual(request(port,'/api/session',cookie=sessions[1][0])[0],401)
                    self.assertEqual(json.loads(request(port,'/api/security',cookie=cookie)[2]),{'enabled':True,'recovery_remaining':10})
                    with closing(sqlite3.connect(directory/'gateway.sqlite')) as db:
                        encrypted=db.execute('SELECT secret FROM mfa').fetchone()[0]
                        self.assertTrue(base64.b64decode(encrypted).startswith(b'XGB1'))
                        self.assertNotIn(secret,encrypted)
                    status,_,body=request(port,'/api/security/recovery','POST',{'current_password':password,'code':original[0]},cookie,csrf)
                    self.assertEqual(status,200);replacement=json.loads(body)['recovery_codes'];self.assertEqual(len(set(replacement)),10)
                    self.assertEqual(request(port,'/api/security/disable','POST',{'current_password':password,'code':original[0]},cookie,csrf)[0],403)
                    self.assertEqual(request(port,'/api/security/disable','POST',{'current_password':password,'code':replacement[0]},cookie,csrf)[0],200)
                    self.assertEqual(request(port,'/api/session',cookie=cookie)[0],401)
                    self.assertEqual(request(port,'/api/login','POST',{'username':'admin','password':password,'code':''})[0],200)
            finally:stop(rust);stop(legacy)
