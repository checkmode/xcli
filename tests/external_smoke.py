#!/usr/bin/env python3
"""Test the deployed public endpoints from a separate device, without leaking links."""
import base64
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
from urllib.parse import parse_qs, unquote, urlsplit

ROOT = pathlib.Path(__file__).resolve().parents[1]
XRAY = sys.argv[1]
links = json.loads((ROOT / 'private/client-links.json').read_text())


def curl(url, proxy=None, timeout=30):
    args = ['curl', '-fsS', '--max-time', str(timeout), '--noproxy', '' if proxy else '*']
    if proxy:
        args += ['--proxy', proxy]
    return subprocess.run(args + [url], capture_output=True, timeout=timeout + 3)


def require(ok, message):
    if not ok:
        raise RuntimeError(message)
    print('PASS:', message, flush=True)


response = curl('https://gateway.example.com/healthz')
require(response.returncode == 0 and json.loads(response.stdout)['status'] == 'ok',
        'Public HTTPS and certificate verification')
response = curl(links['subscription'])
require(response.returncode == 0, 'Public subscription download')
nodes = base64.b64decode(response.stdout).decode().splitlines()
require(len(nodes) == 2 and all(n.startswith('vless://') for n in nodes),
        'Subscription contains both VLESS nodes')

with tempfile.TemporaryDirectory(prefix='xg-external-') as directory:
    work = pathlib.Path(directory)
    os.chmod(work, 0o700)
    for index, kind in enumerate(('reality', 'websocket')):
        uri = urlsplit(links[kind])
        query = {k: v[0] for k, v in parse_qs(uri.query).items()}
        stream = {'network': query['type'], 'security': query['security']}
        if kind == 'reality':
            stream['realitySettings'] = {
                'serverName': query['sni'], 'fingerprint': query['fp'],
                'publicKey': query['pbk'], 'shortId': query['sid'],
            }
        else:
            stream['tlsSettings'] = {'serverName': query['sni']}
            stream['wsSettings'] = {'path': query['path'], 'headers': {'Host': query['host']}}
        port = 18981 + index
        user = {'id': unquote(uri.username), 'encryption': 'none'}
        if 'flow' in query:
            user['flow'] = query['flow']
        config = {
            'log': {'loglevel': 'warning'},
            'inbounds': [{'listen': '127.0.0.1', 'port': port, 'protocol': 'socks',
                          'settings': {'auth': 'noauth', 'udp': True}}],
            'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [
                {'address': uri.hostname, 'port': uri.port, 'users': [user]}
            ]}, 'streamSettings': stream}],
        }
        path = work / (kind + '.json')
        path.write_text(json.dumps(config))
        path.chmod(0o600)
        with (work / (kind + '.log')).open('wb') as log:
            process = subprocess.Popen([XRAY, 'run', '-config', str(path)], stdout=log, stderr=log)
            try:
                time.sleep(1)
                proxy = 'socks5h://127.0.0.1:' + str(port)
                response = curl('https://api.ipify.org', proxy)
                require(response.returncode == 0 and response.stdout.strip() == b'203.0.113.2',
                        kind + ' public authenticated egress is 203.0.113.2')
                started = time.monotonic()
                response = curl('https://speed.cloudflare.com/__down?bytes=1048576', proxy, timeout=60)
                elapsed = time.monotonic() - started
                if response.returncode or len(response.stdout) != 1048576:
                    print('Transfer diagnostic:', 'curl_exit=', response.returncode,
                          'bytes=', len(response.stdout), response.stderr.decode()[:240], flush=True)
                require(response.returncode == 0 and len(response.stdout) == 1048576,
                        kind + ' downloaded 1 MiB through the tunnel')
                print('Transfer:', kind, f'{elapsed:.2f}s',
                      f'{len(response.stdout) * 8 / elapsed / 1e6:.2f} Mbps', flush=True)
                response = curl('http://169.254.169.254/opc/v2/instance/', proxy, timeout=5)
                require(response.returncode != 0, kind + ' metadata access rejected')
            finally:
                process.terminate()
                process.wait(timeout=5)

print('External acceptance completed; temporary clients and credentials removed.', flush=True)
