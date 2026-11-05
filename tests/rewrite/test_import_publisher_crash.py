"""Kill disposable publishers before and after their SQLite audit commits."""
import os
from pathlib import Path
import select
import sqlite3
import subprocess
import tempfile
import unittest

DRIVER = os.environ.get('XCLI_IMPORT_PUBLISHER_DRIVER', '')


@unittest.skipUnless(DRIVER and Path(DRIVER).is_file(), 'set XCLI_IMPORT_PUBLISHER_DRIVER')
class PublisherCrashRecovery(unittest.TestCase):
    def test_sigkill_before_and_after_audit_commit_recovers_once(self):
        for mode in ('before', 'after'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='xcli-import-crash-') as folder:
                root=Path(folder);inbox=root/'inbox';inbox.mkdir(mode=0o700);db=root/'gateway.sqlite'
                with sqlite3.connect(db) as conn:
                    conn.execute('CREATE TABLE events(id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,action TEXT NOT NULL,detail TEXT NOT NULL)')
                process=subprocess.Popen([DRIVER,mode,str(inbox),str(db)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,bufsize=1)
                try:
                    self.assertTrue(select.select([process.stdout],[],[],15)[0], 'fixture did not reach the crash point')
                    self.assertEqual(process.stdout.readline().strip(),'ready')
                    self.assertTrue((inbox/'request.xgb').is_file())
                    self.assertTrue((inbox/'pending-publication.xgb').is_file())
                    before=(inbox/'request.xgb').read_bytes()
                    self.assertNotIn(b'synthetic-password',before)
                    self.assertNotIn(b'synthetic-password',(inbox/'pending-publication.xgb').read_bytes())
                    process.kill();process.wait(timeout=5)
                    result=subprocess.run([DRIVER,'recover',str(inbox),str(db)],capture_output=True,text=True,timeout=10)
                    self.assertEqual(result.returncode,0);self.assertEqual(result.stdout.strip(),'recovered')
                    self.assertEqual((inbox/'request.xgb').read_bytes(),before)
                    self.assertFalse((inbox/'pending-publication.xgb').exists())
                    with sqlite3.connect(db) as conn:
                        self.assertEqual(conn.execute("SELECT count(*) FROM events WHERE action='proxy_import_requested'").fetchone()[0],1)
                        self.assertEqual(conn.execute('SELECT count(*) FROM xcli_import_audit_ops').fetchone()[0],1)
                finally:
                    if process.poll() is None:
                        process.kill();process.wait(timeout=5)
                    process.stdout.close()
