"""Verify legacy and experimental panels exclude each other using a disposable DB."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest

from test_panel_http_integration import free_port, request, stop, wait_ready

OLD=os.environ.get('XCLI_LEGACY_PANEL','')
NEW=os.environ.get('XCLI_PANEL_SERVICE','')


@unittest.skipUnless(OLD and NEW and Path(OLD).is_file() and Path(NEW).is_file(),
                     'set XCLI_LEGACY_PANEL and XCLI_PANEL_SERVICE')
class PanelLockCompatibility(unittest.TestCase):
    def test_legacy_and_rust_never_share_the_controller_lock(self):
        with tempfile.TemporaryDirectory(prefix='xcli-panel-lock-') as folder:
            root=Path(folder);state=root/'state';state.mkdir();settings=root/'settings.json';key=root/'key'
            settings.write_text(json.dumps({'origin':'https://testserver','domain':'testserver','public_ip':'203.0.113.2',
                'reality_sni':'example.com','reality_public':'p'*43,'short_id':'aabbccdd','ws_path':'/connect/test'}))
            key.write_bytes(bytes(range(32)));key.chmod(0o600)
            path=state/'gateway.sqlite';db=sqlite3.connect(path)
            db.execute('CREATE TABLE admin(id INTEGER PRIMARY KEY,password TEXT NOT NULL)')
            db.execute('INSERT INTO admin VALUES(1,?)',('000102030405060708090a0b0c0d0e0f:'
                'afc6691525faf48bd6fd7965166241e1deb78be6f8e199afd0406a9608658dbf',));db.commit();db.close()
            def old_args(port):return [OLD,'--state',str(state),'--settings',str(settings),'--static',str(root),
                '--secret-key',str(key),'--port',str(port),'--offline','--no-auto-backup']
            def new_args(port):return [NEW,'--experimental','--db',str(path),'--secret-key',str(key),
                '--origin','https://testserver','--port',str(port)]
            old_port=free_port();old=subprocess.Popen(old_args(old_port),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            new=None
            try:
                wait_ready(old,old_port)
                duplicate=subprocess.run(new_args(free_port()),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
                self.assertNotEqual(duplicate.returncode,0);self.assertEqual(request(old_port,'/healthz')[0],200)
                stop(old);old=None
                new_port=free_port();new=subprocess.Popen(new_args(new_port),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                wait_ready(new,new_port)
                duplicate=subprocess.run(old_args(free_port()),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
                self.assertNotEqual(duplicate.returncode,0);self.assertEqual(request(new_port,'/healthz')[0],200)
            finally:
                stop(new);stop(old)
