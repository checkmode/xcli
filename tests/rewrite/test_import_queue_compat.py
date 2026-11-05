"""Check the isolated Rust inbox against the old Python XGB1 request format."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
DRIVER=os.environ.get('XCLI_IMPORT_QUEUE_DRIVER','')


@unittest.skipUnless(DRIVER and Path(DRIVER).is_file(), 'set import queue driver')
class ImportQueueCompatibility(unittest.TestCase):
    def test_python_request_is_authenticated_and_claimed_only_once(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        sys.path.insert(0,str(ROOT/'scripts'))
        spec=importlib.util.spec_from_file_location('legacy_import_queue',ROOT/'scripts/proxy_import.py')
        legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)
        key=bytes([42])*32;nonce=bytes(range(12));context=b'xcli:proxy-import:request:v1'
        request={'id':'a'*32,'action':'preview','requested_at':1000,'protocol':'socks',
            'password':'synthetic-only-password'}
        plaintext=json.dumps(request).encode()
        encrypted=AESGCM(key).encrypt(nonce,plaintext,context)
        payload=b'XGB1'+nonce+encrypted[-16:]+encrypted[:-16]
        self.assertEqual(legacy.unseal(payload,key),request)
        with tempfile.TemporaryDirectory(prefix='xcli-queue-fixture-') as directory:
            base=Path(directory);inbox=base/'inbox';state=base/'state';old=base/'old'
            for path in (inbox,state,old):path.mkdir(mode=0o700)
            legacy_file=old/'processed.json'
            (inbox/'request.xgb').write_bytes(payload)
            def claim():
                out=subprocess.check_output([DRIVER,str(inbox),str(state),str(legacy_file)],text=True,timeout=5)
                self.assertNotIn('synthetic-only-password',out)
                return json.loads(out)
            self.assertEqual(claim(),{'claimed':True,'id':'a'*32,'action':'Preview'})
            self.assertEqual(claim(),{'claimed':False})
            self.assertNotIn('synthetic-only-password',(state/'request-replay.json').read_text())
            damaged=bytearray(payload);damaged[-1]^=1;(inbox/'request.xgb').write_bytes(damaged)
            self.assertEqual(claim(),{'error':True})
