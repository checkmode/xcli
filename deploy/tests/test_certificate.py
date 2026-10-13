import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import certificate


class CertificateTests(unittest.TestCase):
    def test_validated_private_copy_and_wrong_host_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key, dest = root / 'cert.pem', root / 'key.pem', root / 'installed'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                '-subj', '/CN=panel.example.com', '-addext', 'subjectAltName=DNS:panel.example.com',
                '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
            certificate.install_tls('panel.example.com', cert, key, dest)
            self.assertEqual((dest / 'privkey.pem').stat().st_mode & 0o777, 0o640)
            self.assertEqual(dest.stat().st_mode & 0o777, 0o750)
            self.assertEqual((dest / 'fullchain.pem').read_bytes(), cert.read_bytes())
            before = (dest / 'fullchain.pem').read_bytes(), (dest / 'privkey.pem').read_bytes()
            with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                certificate.install_tls('wrong.example.com', cert, key, dest)
            self.assertEqual(before, ((dest / 'fullchain.pem').read_bytes(), (dest / 'privkey.pem').read_bytes()))
            other = root / 'other.key'
            subprocess.run(['openssl', 'genrsa', '-out', str(other), '2048'], check=True, capture_output=True)
            with self.assertRaises(ValueError):
                certificate.install_tls('panel.example.com', cert, other, dest)
            link = root / 'link';link.symlink_to(dest)
            with self.assertRaises(ValueError):
                certificate.install_tls('panel.example.com', cert, key, link)


if __name__ == '__main__':
    unittest.main()
