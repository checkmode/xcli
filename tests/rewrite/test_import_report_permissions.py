"""Check a disposable root-owned heartbeat is readable but not writable by the panel user."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

DRIVER=os.environ.get('XCLI_IMPORT_REPORT_DRIVER','')
UID=os.environ.get('XCLI_TEST_REPORT_UID','')
GID=os.environ.get('XCLI_TEST_REPORT_GID','')


@unittest.skipUnless(os.geteuid()==0 and DRIVER and Path(DRIVER).is_file() and UID.isdigit() and GID.isdigit()
                     and int(UID)>0 and int(GID)>0, 'set a non-root fixture UID, GID and report driver')
class ImportReportPermissions(unittest.TestCase):
    def test_panel_group_reads_but_cannot_modify_worker_heartbeat(self):
        uid,gid=int(UID),int(GID)
        def drop():
            os.setgroups([]);os.setgid(gid);os.setuid(uid)
        with tempfile.TemporaryDirectory(prefix='xcli-report-permissions-') as folder:
            root=Path(folder);root.chmod(0o755);directory=root/'report';directory.mkdir(mode=0o750)
            os.chown(directory,0,gid);directory.chmod(0o750)
            args=[DRIVER,'write',str(directory),'0',str(gid)]
            subprocess.run(args,check=True,capture_output=True,timeout=5)
            report=directory/'report.json';before=report.read_bytes()
            self.assertEqual(report.stat().st_uid,0);self.assertEqual(report.stat().st_gid,gid)
            self.assertEqual(report.stat().st_mode & 0o777,0o640)
            read=subprocess.run([DRIVER,'read',str(directory),'0',str(gid)],check=True,capture_output=True,text=True,preexec_fn=drop,timeout=5)
            self.assertEqual(json.loads(read.stdout),{'id':'','status':'idle','updated':1000})
            refused=subprocess.run(args,capture_output=True,preexec_fn=drop,timeout=5)
            self.assertNotEqual(refused.returncode,0)
            direct=subprocess.run(['/usr/bin/python3','-c',"import sys;open(sys.argv[1],'w').write('fixture')",str(report)],
                                  capture_output=True,preexec_fn=drop,timeout=5)
            self.assertNotEqual(direct.returncode,0)
            self.assertEqual(report.read_bytes(),before)
