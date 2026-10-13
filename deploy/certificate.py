#!/usr/bin/env python3
"""Validate and publish the certificate pair read by the unprivileged QUIC core."""
import argparse
import grp
import json
import os
from pathlib import Path
import subprocess
import tempfile


def openssl(*args):
    return subprocess.check_output(['openssl', *map(str, args)], stderr=subprocess.PIPE, timeout=15)


def install_tls(domain, certificate, private_key, destination, group=None):
    certificate, private_key, destination = Path(certificate), Path(private_key), Path(destination)
    # OpenSSL 3.0 can exit zero even when -checkhost reports a mismatch.
    checked = openssl('x509', '-in', certificate, '-noout', '-checkhost', domain)
    if checked.strip() != ('Hostname ' + domain + ' does match certificate').encode():
        raise ValueError('证书与域名不匹配')
    openssl('x509', '-in', certificate, '-noout', '-checkend', '86400')
    if openssl('x509', '-in', certificate, '-pubkey', '-noout').strip() != openssl(
            'pkey', '-in', private_key, '-pubout', '-passin', 'pass:').strip():
        raise ValueError('证书与私钥不匹配')
    if destination.is_symlink():
        raise ValueError('证书目录不能是符号链接')
    destination.mkdir(mode=0o750, exist_ok=True)
    gid = grp.getgrnam(group).gr_gid if group else os.getgid()
    os.chmod(destination, 0o750)
    if os.geteuid() == 0:
        os.chown(destination, 0, gid)
    for source, name in ((certificate, 'fullchain.pem'), (private_key, 'privkey.pem')):
        fd, temporary = tempfile.mkstemp(prefix='.renew-', dir=destination)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(source.read_bytes())
                stream.flush()
                os.fsync(stream.fileno())
                os.fchmod(stream.fileno(), 0o640)
                if os.geteuid() == 0:
                    os.fchown(stream.fileno(), 0, gid)
            os.replace(temporary, destination / name)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--certificate', type=Path)
    parser.add_argument('--private-key', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('请使用 sudo 执行')
    if bool(args.certificate) != bool(args.private_key):
        parser.error('证书和私钥必须一起提供')
    settings = json.loads(Path('/etc/xray-gateway/settings.json').read_text())
    if not settings.get('hysteria2_port', 0):
        return
    live = Path('/etc/letsencrypt/live') / settings['domain']
    # Certbot invokes global deploy hooks for unrelated certificates too.
    if not args.certificate and os.environ.get('RENEWED_LINEAGE') and Path(os.environ['RENEWED_LINEAGE']) != live:
        return
    install_tls(settings['domain'], args.certificate or live / 'fullchain.pem',
                args.private_key or live / 'privkey.pem', Path('/etc/xray-gateway/hysteria-tls'), 'xgateway')
    print('Hysteria 2 证书已更新；核心在证书重载周期内读取新文件。')


if __name__ == '__main__':
    main()
