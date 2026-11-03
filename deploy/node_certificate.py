#!/usr/bin/env python3
"""Update an independent node's validated TLS pair after certificate renewal."""
import argparse
import json
import os
from pathlib import Path
from certificate import install_tls


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--certificate', type=Path)
    parser.add_argument('--private-key', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('需要 root 权限')
    if bool(args.certificate) != bool(args.private_key):
        raise SystemExit('证书与私钥必须一起提供')
    settings = json.loads(Path('/etc/xcli-node/settings.json').read_text())
    live = Path('/etc/letsencrypt/live') / settings['domain']
    if not args.certificate and os.environ.get('RENEWED_LINEAGE') and Path(os.environ['RENEWED_LINEAGE']) != live:
        return
    install_tls(settings['domain'], args.certificate or live / 'fullchain.pem',
                args.private_key or live / 'privkey.pem', Path('/etc/xcli-node/tls'), 'xgateway')


if __name__ == '__main__':
    main()
