#!/usr/bin/env python3
"""Probe enabled public VLESS and Hysteria 2 entries; standard library + Xray + curl.

The server self-test verifies the local host -> public entry -> Internet path.
Run this same tool on an external machine to test its actual access network.
Configuration contains a dedicated probe credential: keep it private.
"""
import argparse
import concurrent.futures
import contextlib
import json
import os
import pathlib
import secrets
import signal
import socket
import struct
import subprocess
import tempfile
import time


def recv_exact(sock, length):
    data = b''
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise RuntimeError('SOCKS connection closed')
        data += part
    return data


def udp_dns(port):
    started = time.monotonic()
    with socket.create_connection(('127.0.0.1', port), timeout=6) as control:
        control.settimeout(6)
        control.sendall(b'\x05\x01\x00')
        if recv_exact(control, 2) != b'\x05\x00':
            raise RuntimeError('SOCKS authentication failed')
        control.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
        head = recv_exact(control, 4)
        if head[:3] != b'\x05\x00\x00':
            raise RuntimeError('SOCKS UDP association failed')
        if head[3] == 1:
            host = socket.inet_ntoa(recv_exact(control, 4))
        elif head[3] == 3:
            host = recv_exact(control, recv_exact(control, 1)[0]).decode('ascii')
        elif head[3] == 4:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(control, 16))
        else:
            raise RuntimeError('SOCKS address invalid')
        relay_port = struct.unpack('!H', recv_exact(control, 2))[0]
        if host in ('0.0.0.0', '::'):
            host = '127.0.0.1'
        ident = secrets.randbits(16)
        question = b'\x07example\x03com\x00\x00\x01\x00\x01'
        packet = struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0) + question
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(6)
            udp.connect((host, relay_port))
            udp.send(b'\x00\x00\x00\x01' + socket.inet_aton('1.1.1.1') + struct.pack('!H', 53) + packet)
            data = udp.recv(4096)
        if len(data) < 22 or data[:4] != b'\x00\x00\x00\x01' or data[4:10] != socket.inet_aton('1.1.1.1') + struct.pack('!H', 53):
            raise RuntimeError('UDP response invalid')
        reply_id, flags, _, answers, _, _ = struct.unpack('!HHHHHH', data[10:22])
        if reply_id != ident or not flags & 0x8000 or flags & 0xf or not answers:
            raise RuntimeError('DNS response invalid')
    return round((time.monotonic() - started) * 1000)


def available_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def client_config(config, kind, port):
    user = {'id': config['uuid'], 'encryption': 'none'}
    if kind == 'reality':
        user['flow'] = 'xtls-rprx-vision'
        host = config['public_ip']
        stream = {'network': 'tcp', 'security': 'reality', 'realitySettings': {
            'serverName': config['reality_sni'], 'fingerprint': 'chrome',
            'publicKey': config['reality_public'], 'shortId': config['short_id']}}
    elif kind == 'websocket':
        host = config['domain']
        stream = {'network': 'ws', 'security': 'tls',
            'tlsSettings': {'serverName': config['domain'], 'allowInsecure': False, 'useSystemCA': True},
            'wsSettings': {'path': config['ws_path'], 'headers': {'Host': config['domain']}}}
    if kind == 'hysteria2':
        outbound = {'protocol': 'hysteria', 'settings': {'version': 2, 'address': config['public_ip'],
            'port': config['hysteria2_port']}, 'streamSettings': {'network': 'hysteria', 'security': 'tls',
            'hysteriaSettings': {'version': 2, 'auth': config['uuid']},
            'tlsSettings': {'serverName': config['domain'], 'allowInsecure': False,
                'useSystemCA': True, 'alpn': ['h3']},
            'finalmask': {'quicParams': {'congestion': 'bbr'}}}}
    elif kind in ('reality', 'websocket'):
        outbound = {'protocol': 'vless', 'settings': {'vnext': [
            {'address': host, 'port': 443, 'users': [user]}]}, 'streamSettings': stream}
    else:
        raise ValueError('Unsupported transport')
    return {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port,
        'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True}}],
        'outbounds': [outbound]}


def check(config, kind, port):
    result = {'transport': kind, 'status': 'failed', 'https_ms': None, 'udp_ms': None,
              'error': '', 'last_success': 0}
    errors = []
    started = time.monotonic()
    try:
        response = subprocess.run(['curl', '-q', '-fsS', '--max-time', '15', '--connect-timeout', '8',
            '--noproxy', '', '--proxy', f'socks5h://127.0.0.1:{port}',
            'https://www.cloudflare.com/cdn-cgi/trace'], capture_output=True, timeout=18)
        fields = dict(line.split('=', 1) for line in response.stdout.decode('ascii', errors='ignore').splitlines() if '=' in line)
        if response.returncode != 0:
            errors.append('HTTPS connection failed')
        elif fields.get('ip') != config['public_ip']:
            errors.append('Unexpected egress IP')
        else:
            result['https_ms'] = round((time.monotonic() - started) * 1000)
    except (OSError, subprocess.TimeoutExpired):
        errors.append('HTTPS probe unavailable')
    try:
        result['udp_ms'] = udp_dns(port)
    except (OSError, RuntimeError, ValueError, struct.error):
        errors.append('UDP DNS probe failed')
    result['error'] = '; '.join(errors)
    if not errors:
        result['status'] = 'healthy'
        result['last_success'] = int(time.time())
    return result


def atomic_report(path, report):
    payload = (json.dumps(report, ensure_ascii=False) + '\n').encode()
    fd, temporary = tempfile.mkstemp(prefix='.report-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o640)
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=pathlib.Path, required=True)
    parser.add_argument('--xray', default='/usr/local/lib/xray-gateway/xray')
    parser.add_argument('--output', type=pathlib.Path)
    parser.add_argument('--scope', choices=['server', 'external'], default='external')
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--interval', type=int, default=60)
    args = parser.parse_args()
    if not 30 <= args.interval <= 3600:
        parser.error('interval must be 30..3600 seconds')
    config = json.loads(args.config.read_text())
    kinds = ['reality', 'websocket'] + (['hysteria2'] if config.get('hysteria2_port', 0) else [])
    if args.config.stat().st_mode & 0o007:
        parser.error('configuration must not be world-readable')
    stopped = False
    def stop(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    last_success = {}
    if args.output and args.output.exists():
        with contextlib.suppress(ValueError, KeyError, TypeError):
            previous = json.loads(args.output.read_text())
            last_success = {c['transport']: c['last_success'] for c in previous['checks']}
    with tempfile.TemporaryDirectory(prefix='xcli-probe-') as directory:
        clients = {}
        try:
            while not stopped:
                started = time.monotonic()
                for kind in kinds:
                    if kind in clients and clients[kind][0].poll() is None:
                        continue
                    port = available_port()
                    path = pathlib.Path(directory) / (kind + '.json')
                    path.write_text(json.dumps(client_config(config, kind, port)))
                    path.chmod(0o600)
                    process = subprocess.Popen([args.xray, 'run', '-config', str(path)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    clients[kind] = (process, port)
                    for _ in range(40):
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=.1):
                                break
                        except OSError:
                            if process.poll() is not None:
                                break
                            time.sleep(.05)
                with concurrent.futures.ThreadPoolExecutor(max_workers=len(kinds)) as pool:
                    futures = [pool.submit(check, config, kind, port) for kind, (_, port) in clients.items()]
                    checks = [future.result() for future in futures]
                for result in checks:
                    kind = result['transport']
                    if result['status'] == 'healthy':
                        last_success[kind] = result['last_success']
                    else:
                        result['last_success'] = last_success.get(kind, 0)
                report = {'schema': 1, 'scope': args.scope, 'updated': int(time.time()),
                    'status': 'healthy' if all(c['status'] == 'healthy' for c in checks) else 'failed', 'checks': checks}
                if args.output:
                    atomic_report(args.output, report)
                if args.once:
                    print(json.dumps(report))
                    return 0 if report['status'] == 'healthy' else 1
                while not stopped and time.monotonic() - started < args.interval:
                    time.sleep(.2)
        finally:
            for process, _ in clients.values():
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
