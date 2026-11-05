"""Root-only Certbot hook fixture; all paths are disposable and synthetic."""
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

PROGRAM = os.environ.get('XCLI_CERT_RENEW', '')
UID = os.environ.get('XCLI_TEST_CERT_UID', '')
GID = os.environ.get('XCLI_TEST_CERT_GID', '')


@unittest.skipUnless(os.geteuid() == 0 and PROGRAM and Path(PROGRAM).is_file() and UID and GID,
                     'requires root, an explicit fixture binary and unprivileged uid/gid')
class CertRenewCli(unittest.TestCase):
    def test_scope_permissions_mismatch_and_existing_target_protection(self):
        with tempfile.TemporaryDirectory(prefix='xcli-cert-fixture-', dir='/var/lib') as folder:
            root = Path(folder); certbot = root/'certbot'; lineage = certbot/'live'/'localhost'
            archive = certbot/'archive'/'localhost'; target_dir = root/'target'
            lineage.mkdir(parents=True); archive.mkdir(parents=True); target_dir.mkdir()
            certs=[]; keys=[]
            for number in (1, 2):
                cert=archive/f'fullchain{number}.pem'; key=archive/f'privkey{number}.pem'
                subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2',
                    '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(cert)],
                    check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=20)
                key.chmod(0o600); certs.append(cert);keys.append(key)
            (lineage/'fullchain.pem').symlink_to('../../archive/localhost/fullchain1.pem')
            (lineage/'privkey.pem').symlink_to('../../archive/localhost/privkey1.pem')
            target=target_dir/'bundle.pem'
            args=[PROGRAM,'--experimental','--certbot-root',str(certbot),'--lineage','localhost','--domain','localhost',
                  '--target',str(target),'--validator-uid',UID,'--validator-gid',GID,'--output-gid',GID]
            def invoke(renewed=None, command=args):
                env={'PATH':'/usr/bin:/bin'}
                if renewed is not None:env['RENEWED_LINEAGE']=str(renewed)
                result=subprocess.run(command,env=env,capture_output=True,timeout=20)
                self.assertNotIn(b'PRIVATE KEY',result.stdout+result.stderr)
                return result
            self.assertNotEqual(invoke().returncode,0)
            self.assertEqual(invoke(certbot/'live'/'unrelated').returncode,0)
            self.assertFalse(target.exists())
            self.assertEqual(invoke(lineage).returncode,0)
            info=target.stat()
            self.assertEqual((info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)),(0,int(GID),0o640))
            before=target.read_bytes()
            (lineage/'fullchain.pem').unlink();(lineage/'fullchain.pem').symlink_to('../../archive/localhost/fullchain2.pem')
            self.assertNotEqual(invoke(lineage).returncode,0)
            self.assertEqual(target.read_bytes(),before)
            (lineage/'privkey.pem').unlink();(lineage/'privkey.pem').symlink_to('../../archive/localhost/privkey2.pem')
            self.assertEqual(invoke(lineage).returncode,0)
            updated=target.read_bytes();self.assertNotEqual(updated,before)
            self.assertTrue(updated.startswith(certs[1].read_bytes()));self.assertTrue(updated.endswith(keys[1].read_bytes()))
            target.unlink(); target.symlink_to(root/'victim')
            victim=root/'victim';victim.write_bytes(b'unchanged')
            self.assertNotEqual(invoke(lineage).returncode,0);self.assertEqual(victim.read_bytes(),b'unchanged')
            target.unlink();shutil.copyfile(certs[1],target);target.chmod(0o640)
            existing=target.read_bytes();target_dir.chmod(0o777)
            self.assertNotEqual(invoke(lineage).returncode,0);self.assertEqual(target.read_bytes(),existing)
