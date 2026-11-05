"""Compare Rust traffic accounting against the C++ code using disposable databases."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
import unittest

OLD = os.environ.get('XCLI_LEGACY_TRAFFIC_DRIVER', '')
NEW = os.environ.get('XCLI_TRAFFIC_DRIVER', '')
USER = '0123456789abcdef0123456789abcdef'
OTHER = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'


def counter(user, tag, direction, value):
    return {'name':f'user>>>{user}.abcdef01@{tag}>>>traffic>>>{direction}', 'value':value}


@unittest.skipUnless(OLD and NEW and Path(OLD).is_file() and Path(NEW).is_file(),
                     'set XCLI_LEGACY_TRAFFIC_DRIVER and XCLI_TRAFFIC_DRIVER')
class PanelTrafficCompatibility(unittest.TestCase):
    def test_generations_resets_unknown_counters_and_atomic_overflow(self):
        with tempfile.TemporaryDirectory(prefix='xcli-traffic-compat-') as folder:
            root = Path(folder); state = root / 'state'; settings = root / 'settings.json'
            settings.write_text(json.dumps({'origin':'https://testserver','domain':'testserver','public_ip':'203.0.113.2',
                'reality_sni':'example.com','reality_public':'p'*43,'short_id':'aabbccdd','ws_path':'/connect/test'}))
            old = subprocess.Popen([OLD,str(state),str(settings)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,text=True,bufsize=1)
            new = None
            def call(process, value):
                process.stdin.write(json.dumps(value)+'\n'); process.stdin.flush()
                line = process.stdout.readline(); self.assertTrue(line,'comparison driver stopped')
                return json.loads(line)
            def snapshot(path):
                db = sqlite3.connect(path)
                try:
                    return (db.execute('SELECT id,upload,download FROM users ORDER BY id').fetchall(),
                        db.execute('SELECT name,value,generation FROM counters ORDER BY name').fetchall(),
                        db.execute("SELECT value FROM metadata WHERE key='activity_sample'").fetchall(),
                        db.execute('SELECT user_id,transport,last_seen,sampled,upload_delta,download_delta,interval_seconds FROM device_activity ORDER BY user_id,transport').fetchall(),
                        db.execute('SELECT upload,download FROM samples ORDER BY rowid').fetchall(),
                        db.execute('SELECT COALESCE(SUM(upload),0),COALESCE(SUM(download),0) FROM traffic_history').fetchall())
                finally: db.close()
            try:
                self.assertEqual(json.loads(old.stdout.readline()),{'ready':True})
                old_db = state/'gateway.sqlite'; new_db = root/'new.sqlite'
                source = sqlite3.connect(old_db); dest = sqlite3.connect(new_db); source.backup(dest); dest.close(); source.close()
                new = subprocess.Popen([NEW,str(new_db)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,text=True,bufsize=1)
                up = lambda n: counter(USER,'reality','uplink',n)
                down = lambda n: counter(USER,'residential-01-hy2','downlink',n)
                batches = [
                    ('1:10',[up(100),down(200)]), ('1:10',[up(100),down(200)]),
                    ('1:10',[up(180),down(250)]), ('1:10',[up(5),down(270)]),
                    ('2:11',[up(250),down(1)]),
                    ('2:11',[up(260),counter(OTHER,'websocket','uplink',7),counter(USER,'unknown','uplink',999),
                              counter(USER,'websocket','uplink',-1)]),
                    ('2:11',[up(261),up(262),down(5)]),
                ]
                for generation, counters in batches:
                    payload = {'generation':generation,'counters':counters}
                    expected = call(old,payload); self.assertTrue(expected['ok'])
                    actual = call(new,dict(payload,now=expected['now'])); self.assertTrue(actual['ok'])
                    self.assertEqual((actual['upload'],actual['download']),(expected['upload'],expected['download']))
                    self.assertEqual(snapshot(old_db),snapshot(new_db))
                for path in (old_db,new_db):
                    db = sqlite3.connect(path); db.execute('UPDATE users SET upload=? WHERE id=?',(2**63-1,USER)); db.commit(); db.close()
                before = snapshot(old_db)
                payload = {'generation':'2:11','counters':[counter(USER,'vmess','uplink',1)]}
                expected = call(old,payload); self.assertFalse(expected['ok'])
                actual = call(new,dict(payload,now=int(time.time()))); self.assertFalse(actual['ok'])
                self.assertEqual(snapshot(old_db),before); self.assertEqual(snapshot(new_db),before)
            finally:
                for process in (old,new):
                    if process is None: continue
                    process.stdin.close()
                    try: process.wait(timeout=10)
                    except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=5)
                    process.stdout.close()
