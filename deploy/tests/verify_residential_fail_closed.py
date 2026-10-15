#!/usr/bin/env python3
"""Test a copy of live routing with real loopback Hysteria 2 and upstream faults.

Production services, files and firewall rules are never changed. The isolated
server uses throwaway authentication, loopback listeners and the existing TLS
certificate; upstream credentials remain inside its private temporary directory.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import uuid


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def receive(sock, count):
    result = b''
    while len(result) < count:
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise RuntimeError('SOCKS control connection closed')
        result += chunk
    return result


def udp_probe(port, destination, destination_port, payload, timeout=1.5):
    with socket.create_connection(('127.0.0.1', port), timeout=3) as control:
        control.settimeout(3)
        control.sendall(b'\x05\x01\x00')
        assert receive(control, 2) == b'\x05\x00'
        control.sendall(b'\x05\x03\x00\x01' + b'\x00' * 6)
        head = receive(control, 4)
        assert head[:3] == b'\x05\x00\x00'
        if head[3] == 1:
            host = socket.inet_ntoa(receive(control, 4))
        elif head[3] == 4:
            host = socket.inet_ntop(socket.AF_INET6, receive(control, 16))
        else:
            host = receive(control, receive(control, 1)[0]).decode()
        relay = struct.unpack('!H', receive(control, 2))[0]
        if host in ('0.0.0.0', '::'):
            host = '127.0.0.1'
        try:
            address = b'\x01' + socket.inet_aton(destination)
        except OSError:
            encoded = destination.encode('ascii')
            address = b'\x03' + bytes([len(encoded)]) + encoded
        packet = b'\x00\x00\x00' + address + struct.pack('!H', destination_port) + payload
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
            datagram.settimeout(timeout)
            datagram.sendto(packet, (host, relay))
            try:
                return datagram.recv(4096)
            except socket.timeout:
                return None


class FaultHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            self.request.recv(4096)
            if self.server.fault == 'http-407':
                self.request.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                                     b'Content-Length: 0\r\nConnection: close\r\n\r\n')
            else:
                self.server.finished.wait(9)
        except OSError:
            pass


class FaultServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait()


def run_phase(binary, original, domain, user_id, exit_tag, exit_ip, phase, output):
    processes = []
    fault_server = None
    refused = None
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='xcli-egress-fault-') as temporary:
        directory = Path(temporary)
        api_port, hy2_port = free_port(), free_port()
        ports = {'residential': free_port(), 'ordinary': free_port()}
        identity = str(uuid.uuid4())
        auth = {'residential': identity + '.' + exit_tag + '-hy2', 'ordinary': identity}
        config = copy.deepcopy(original)
        inbound = copy.deepcopy(next(i for i in original['inbounds'] if i['tag'] == 'hysteria2'))
        inbound.update({'listen': '127.0.0.1', 'port': hy2_port})
        inbound['settings']['clients'] = [
            {'auth': auth[name], 'email': user_id + '.' + identity[:8] + '@' + tag, 'level': 0}
            for name, tag in [('residential', exit_tag + '-hy2'), ('ordinary', 'hysteria2')]]
        config['inbounds'] = [inbound]
        config['api'] = {'tag': 'api', 'listen': '127.0.0.1:' + str(api_port),
                         'services': ['HandlerService', 'StatsService']}
        config['log'] = {'loglevel': 'info', 'access': str(directory / 'access.log'),
                         'error': str(directory / 'error.log')}
        upstream = next(o for o in config['outbounds'] if o['tag'] == exit_tag + '-exit')
        assert upstream['protocol'] == 'http', 'This verifier expects an HTTP residential upstream'
        if phase == 'connection-refused':
            refused = socket.socket()
            refused.bind(('127.0.0.1', 0))  # Reserve without listening: deterministic refusal.
            fault_port = refused.getsockname()[1]
        elif phase in ('http-407', 'upstream-timeout'):
            fault_server = FaultServer(('127.0.0.1', 0), FaultHandler)
            fault_server.fault = phase
            fault_server.finished = threading.Event()
            threading.Thread(target=fault_server.serve_forever, daemon=True).start()
            fault_port = fault_server.server_address[1]
        if phase not in ('baseline', 'recovery'):
            upstream['settings'] = {'servers': [{'address': '127.0.0.1', 'port': fault_port}]}
        clients = {'log': {'loglevel': 'error'}, 'inbounds': [], 'outbounds': [], 'routing': {'rules': []}}
        for name, port in ports.items():
            clients['inbounds'].append({'tag': name, 'listen': '127.0.0.1', 'port': port,
                                       'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True}})
            clients['outbounds'].append({'tag': name, 'protocol': 'hysteria',
                'settings': {'version': 2, 'address': '127.0.0.1', 'port': hy2_port},
                'streamSettings': {'network': 'hysteria', 'security': 'tls',
                    'hysteriaSettings': {'version': 2, 'auth': auth[name]},
                    'tlsSettings': {'serverName': domain, 'allowInsecure': False,
                                    'useSystemCA': True, 'alpn': ['h3']}}})
            clients['routing']['rules'].append({'type': 'field', 'inboundTag': [name], 'outboundTag': name})
        try:
            for name, value in [('server', config), ('clients', clients)]:
                path = directory / (name + '.json')
                path.write_text(json.dumps(value)); path.chmod(0o600)
                checked = subprocess.run([binary, 'run', '-test', '-config', str(path)], capture_output=True)
                assert checked.returncode == 0, 'Isolated configuration rejected'
                processes.append(subprocess.Popen([binary, 'run', '-config', str(path)],
                                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            for port in [api_port] + list(ports.values()):
                for attempt in range(60):
                    assert all(p.poll() is None for p in processes), 'Isolated process exited'
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise RuntimeError('Isolated listener not ready')
            results = []
            for name, url in [('residential', 'https://claude.ai/cdn-cgi/trace'),
                              ('ordinary', 'https://api.github.com/zen')]:
                body = directory / (name + '.body')
                response = subprocess.run(['curl', '--silent', '--show-error', '--noproxy', '',
                    '--proxy', 'socks5h://127.0.0.1:' + str(ports[name]), '--max-time', '7',
                    '--output', str(body), '--write-out', '%{http_code}', url], capture_output=True, text=True)
                value = {'route': name, 'curl_exit': response.returncode, 'http_status': response.stdout}
                if name == 'residential' and phase in ('baseline', 'recovery'):
                    assert response.returncode == 0 and response.stdout == '200', 'Residential baseline failed'
                    fields = dict(line.split('=', 1) for line in body.read_text().splitlines() if '=' in line)
                    value['exit_ip'] = fields.get('ip')
                    assert value['exit_ip'] == exit_ip, 'Residential egress changed'
                elif name == 'residential':
                    assert response.returncode != 0 and response.stdout == '000', 'Residential upstream failed open'
                else:
                    assert response.returncode == 0 and response.stdout == '200', 'Ordinary control failed'
                results.append(value)
            udp_results = []
            if phase == 'baseline':
                ident = secrets.randbits(16)
                question = struct.pack('!HHHHHH', ident, 0x0100, 1, 0, 0, 0) + b'\x07example\x03com\x00\x00\x01\x00\x01'
                reply = udp_probe(ports['ordinary'], '1.1.1.1', 53, question, timeout=5)
                assert reply and reply[:4] == b'\x00\x00\x00\x01' and struct.unpack('!H', reply[10:12])[0] == ident, 'Ordinary UDP control failed'
                udp_results.append({'case': 'ordinary-dns-control', 'response': True})
                assert udp_probe(ports['residential'], '1.1.1.1', 53, question) is None, 'Residential UDP DNS escaped'
                udp_results.append({'case': 'residential-dns-denied', 'response': False})
                for host, port in [('claude.ai', 443), ('claude.ai', 3478), ('api.anthropic.com', 443)]:
                    stun = struct.pack('!HHI', 1, 0, 0x2112a442) + secrets.token_bytes(12)
                    assert udp_probe(ports['residential'], host, port, stun) is None, 'Unexpected Claude UDP response'
                    udp_results.append({'case': host + ':' + str(port), 'response': False})
            time.sleep(.2)
            access = (directory / 'access.log').read_text()
            (output / (phase + '-access.json')).write_text(json.dumps(
                [re.sub(r' email:.*', '', line) for line in access.splitlines()], indent=2))
            routes = [re.sub(r' email:.*', '', line) for line in access.splitlines()
                      if any(host in line for host in ('claude.ai', 'api.anthropic.com', 'api.github.com', '1.1.1.1'))]
            # Hysteria UDP dispatch does not create a TCP-style access message.
            # Record dispatcher decisions as positive evidence of UDP rejection.
            decisions = [line for line in (directory / 'error.log').read_text().splitlines()
                         if 'app/dispatcher:' in line and
                         ('taking detour [' in line or 'default route for ' in line)]
            (output / (phase + '-decisions.json')).write_text(json.dumps(decisions, indent=2))
            assert any('tcp:claude.ai:443' in line and '-> ' + exit_tag + '-exit]' in line for line in routes)
            assert not any(('claude.ai' in line or 'api.anthropic.com' in line) and
                           ('default route for ' in line or 'taking detour [direct]' in line)
                           for line in decisions), 'Claude traffic escaped to direct'
            if phase == 'baseline':
                for host, port in [('1.1.1.1', 53), ('claude.ai', 443), ('claude.ai', 3478),
                                   ('api.anthropic.com', 443)]:
                    assert any('for [udp:' + host + ':' + str(port) + ']' in line and
                               'taking detour [blocked]' in line for line in decisions), 'UDP route not proved'
            result = {'phase': phase, 'passed': True, 'seconds': round(time.monotonic() - started, 2),
                      'tcp': results, 'udp': udp_results, 'routes': routes, 'decisions': decisions}
            (output / (phase + '.json')).write_text(json.dumps(result, indent=2))
            return result
        finally:
            for process in reversed(processes):
                stop(process)
            if fault_server:
                fault_server.finished.set(); fault_server.shutdown(); fault_server.server_close()
            if refused:
                refused.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='/usr/local/lib/xray-gateway/xray')
    parser.add_argument('--core', type=Path, default=Path('/etc/xray-gateway/core.json'))
    parser.add_argument('--settings', type=Path, default=Path('/etc/xray-gateway/settings.json'))
    parser.add_argument('--user-id', required=True)
    parser.add_argument('--exit-tag', default='residential-28')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    assert re.fullmatch(r'[0-9a-f]{32}', args.user_id)
    before = args.core.read_bytes()
    original = json.loads(before)
    settings = json.loads(args.settings.read_text())
    exit = next(e for e in settings['residential_exits'] if e['tag'] == args.exit_tag)
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    service_args = ['systemctl', 'show', 'xray-gateway-core', 'xray-gateway-panel', 'nginx',
                    'xray-gateway-monitor', '-p', 'Id', '-p', 'MainPID']
    processes = subprocess.check_output(service_args)
    results = []
    for phase in ('baseline', 'connection-refused', 'http-407', 'upstream-timeout', 'recovery'):
        result = run_phase(args.binary, original, settings['domain'], args.user_id,
                           args.exit_tag, exit['exit_ip'], phase, args.output)
        results.append(result)
        print(json.dumps(result), flush=True)
    assert args.core.read_bytes() == before, 'Production configuration changed during test'
    assert subprocess.check_output(service_args) == processes, 'Production services changed during test'
    report = {'passed': True, 'scope': 'isolated copy of production routing; real loopback Hysteria 2',
              'production_core_sha256': hashlib.sha256(before).hexdigest(),
              'production_files_and_processes_preserved': True, 'phases': results}
    (args.output / 'report.json').write_text(json.dumps(report, indent=2))
    print(json.dumps({'passed': True, 'production_files_and_processes_preserved': True}), flush=True)


if __name__ == '__main__':
    main()
