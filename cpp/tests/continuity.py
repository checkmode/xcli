"""Hold both public node connections over a management-only deployment."""
import argparse
import concurrent.futures
import contextlib
import datetime
import json
import os
import pathlib
import subprocess
import tempfile
import time
from urllib.parse import parse_qs, urlsplit

parser = argparse.ArgumentParser()
parser.add_argument('--xray', required=True)
parser.add_argument('--links', type=pathlib.Path, required=True)
parser.add_argument('--output', type=pathlib.Path, required=True)
parser.add_argument('--count', type=int, default=91)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
links = json.loads(args.links.read_text())


def observe(kind, port):
    command = ['curl', '-fsS', '--no-buffer', '--noproxy', '', '--proxy', 'socks5h://127.0.0.1:' + str(port),
        '--connect-timeout', '8', '--max-time', '10', '--rate', '30/m', '-w', '%{json}\n']
    for _ in range(args.count):
        command += ['-o', '/dev/null', 'https://www.cloudflare.com/cdn-cgi/trace']
    records = []
    with (args.output / (kind + '-curl.log')).open('w') as errors:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=errors, text=True, bufsize=1) as process:
            for line in process.stdout:
                value = json.loads(line)
                record = {key: value.get(key) for key in ('http_code', 'exitcode', 'time_total', 'num_connects')}
                record['at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                records.append(record)
                with (args.output / (kind + '.jsonl')).open('a') as stream:
                    stream.write(json.dumps(record) + '\n')
            process.wait(timeout=15)
    return {'kind': kind, 'requests': len(records), 'success': sum(r['http_code'] == 200 and r['exitcode'] == 0 for r in records),
            'connections': sum(r['num_connects'] for r in records), 'first': records[0]['at'], 'last': records[-1]['at']}


with tempfile.TemporaryDirectory(prefix='xg-cpp-continuity-') as directory:
    root = pathlib.Path(directory);root.chmod(0o700)
    clients = []
    try:
        for index, kind in enumerate(('reality', 'websocket')):
            uri = urlsplit(links[kind]);q = {key: values[0] for key, values in parse_qs(uri.query).items()}
            stream = {'network': q['type'], 'security': q['security']}
            user = {'id': uri.username, 'encryption': 'none'}
            if kind == 'reality':
                stream['realitySettings'] = {'serverName': q['sni'], 'fingerprint': q['fp'], 'publicKey': q['pbk'], 'shortId': q['sid']}
                user['flow'] = q['flow']
            else:
                stream['tlsSettings'] = {'serverName': q['sni']}
                stream['wsSettings'] = {'path': q['path'], 'headers': {'Host': q['host']}}
            config = {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1', 'port': 19081 + index,
                'protocol': 'socks', 'settings': {'auth': 'noauth'}}], 'outbounds': [{'protocol': 'vless',
                'settings': {'vnext': [{'address': uri.hostname, 'port': uri.port, 'users': [user]}]}, 'streamSettings': stream}]}
            path = root / (kind + '.json');path.write_text(json.dumps(config));path.chmod(0o600)
            log = (root / (kind + '.log')).open('wb')
            proc = subprocess.Popen([args.xray, 'run', '-config', str(path)], stdout=log, stderr=log)
            clients.append((proc, log))
        time.sleep(1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda item: observe(*item), [('reality', 19081), ('websocket', 19082)]))
        (args.output / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
        print(json.dumps(results))
    finally:
        for process, log in clients:
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=5)
            if process.poll() is None:
                process.kill();process.wait()
            log.close()
