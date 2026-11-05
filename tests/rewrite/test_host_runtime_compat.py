"""Compare host samples from both implementations with disposable proc files."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

OLD=os.environ.get('XCLI_LEGACY_HOST_DRIVER','')
NEW=os.environ.get('XCLI_HOST_DRIVER','')

@unittest.skipUnless(OLD and NEW and Path(OLD).is_file() and Path(NEW).is_file(), 'set host fixture binaries')
class HostCompatibility(unittest.TestCase):
    def test_known_and_missing_sources(self):
        with tempfile.TemporaryDirectory(prefix='xcli-host-compat-') as folder:
            root=Path(folder)
            (root/'uptime').write_text('1234.5 600.0\n')
            (root/'loadavg').write_text('1.25 2.50 3.75 1/10 123\n')
            (root/'meminfo').write_text('MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 500 kB\nSwapFree: 200 kB\n')
            (root/'stat').write_text('cpu 100 20 30 500 50 10 20 30 90 10\nbtime 1000\n')
            def compare():
                old=json.loads(subprocess.check_output([OLD,str(root),str(root)],timeout=5))
                new=json.loads(subprocess.check_output([NEW,str(root),str(root)],timeout=5))
                for key in ('uptime_seconds','memory','swap','load','cpu_ticks','booted_at'):
                    self.assertEqual(old.get(key),new.get(key),key)
                self.assertGreater(new['disk']['total'],0)
            compare()
            (root/'meminfo').unlink();(root/'stat').unlink()
            compare()
