#!/usr/bin/env python3
"""Exercise candidate routing with isolated Xray instances and throwaway users."""
import argparse
import copy
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import uuid


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def verify(binary, candidate, user_id, origin):
    server_port = port()
    identities = {
        'target': user_id + '.12345678@hysteria2',
        'other': ('b' if user_id[0] != 'b' else 'c') * 32 + '.12345678@hysteria2',
        'invalid-suffix': user_id + '.invalid@hysteria2',
    }
    credentials = {name: str(uuid.uuid4()) for name in identities}
    local_ports = {name: port() for name in identities}
    server = {'log': {'loglevel': 'error', 'access': 'none'},
              'inbounds': [{'tag': 'hysteria2', 'listen': '127.0.0.1', 'port': server_port,
                            'protocol': 'vless', 'settings': {'decryption': 'none', 'clients': [
                                {'id': credentials[name], 'email': email} for name, email in identities.items()]}}],
              'outbounds': copy.deepcopy(candidate['outbounds']),
              'routing': copy.deepcopy(candidate['routing'])}
    client = {'log': {'loglevel': 'error', 'access': 'none'}, 'inbounds': [], 'outbounds': [],
              'routing': {'rules': []}}
    for name in identities:
        client['inbounds'].append({'tag': name, 'listen': '127.0.0.1', 'port': local_ports[name],
                                  'protocol': 'socks', 'settings': {'auth': 'noauth'}})
        client['outbounds'].append({'tag': name, 'protocol': 'vless', 'settings': {'vnext': [
            {'address': '127.0.0.1', 'port': server_port, 'users': [
                {'id': credentials[name], 'encryption': 'none'}]}]}})
        client['routing']['rules'].append({'type': 'field', 'inboundTag': [name], 'outboundTag': name})
    processes = []
    with tempfile.TemporaryDirectory(prefix='xcli-subscription-https-test-') as directory:
        root = Path(directory)
        try:
            for name, config in [('server', server), ('client', client)]:
                path = root / (name + '.json')
                path.write_text(json.dumps(config)); path.chmod(0o600)
                subprocess.run([binary, 'run', '-test', '-config', str(path)],
                               capture_output=True, check=True)
                processes.append(subprocess.Popen([binary, 'run', '-config', str(path)],
                                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            for number in [server_port] + list(local_ports.values()):
                for attempt in range(50):
                    if any(p.poll() is not None for p in processes):
                        raise RuntimeError('An isolated core exited')
                    try:
                        with socket.create_connection(('127.0.0.1', number), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise RuntimeError('An isolated listener did not become ready')
            cases = [
                ('target-https', 'target', origin + '/', True),
                ('other-account-denied', 'other', origin + '/', False),
                ('malformed-email-denied', 'invalid-suffix', origin + '/', False),
                ('target-http-denied', 'target', origin.replace('https://', 'http://') + '/', False),
                ('target-private-denied', 'target', 'http://127.0.0.1:8080/healthz', False),
                ('target-normal-internet', 'target', 'https://api.github.com/zen', True),
                ('other-normal-internet', 'other', 'https://api.github.com/zen', True),
            ]
            results = []
            for label, name, url, allowed in cases:
                value = subprocess.run(['curl', '--silent', '--show-error', '--noproxy', '',
                                        '--socks5-hostname', '127.0.0.1:' + str(local_ports[name]),
                                        '--max-time', '10', '--output', '/dev/null',
                                        '--write-out', '%{http_code}', url], capture_output=True, text=True)
                success = value.returncode == 0 and value.stdout == '200'
                result = {'case': label, 'curl_exit': value.returncode, 'http_status': value.stdout,
                          'passed': success if allowed else value.returncode != 0 and value.stdout == '000'}
                results.append(result)
                if not result['passed']:
                    raise AssertionError(json.dumps(result))
            return results
        finally:
            for process in reversed(processes):
                process.terminate()
            for process in reversed(processes):
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--user-id', required=True)
    parser.add_argument('--origin', required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.binary, json.loads(args.candidate.read_text()), args.user_id, args.origin), indent=2))
