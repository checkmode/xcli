#!/usr/bin/env python3
"""Opt-in public system DNS over HTTPS for a systemd-resolved gateway."""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time

CONFIG = Path('/etc/xcli-doh.toml')
UNIT = Path('/etc/systemd/system/xcli-doh.service')
RESOLVED = Path('/etc/systemd/resolved.conf.d/90-xcli-doh.conf')
STOCK = ['dnscrypt-proxy.service', 'dnscrypt-proxy.socket', 'dnscrypt-proxy-resolvconf.service']


def stamp(address, hostname=None, path='/dns-query'):
    def lp(text):
        value = text.encode('ascii')
        if len(value) > 255:
            raise ValueError('DNS stamp field is too long')
        return bytes([len(value)]) + value
    # DoH, unspecified provider properties, fixed address, standard CA validation.
    value = b'\x02' + b'\0' * 8 + lp(address) + b'\0' + lp(hostname or address) + lp(path)
    return 'sdns://' + base64.urlsafe_b64encode(value).decode().rstrip('=')


def configuration(servers=None):
    servers = servers or [('primary', '1.1.1.1', None), ('secondary', '1.0.0.1', None)]
    result = """# No resolver lists or plaintext bootstrap queries are required.
listen_addresses = ['127.0.0.1:5053']
server_names = %s
ignore_system_dns = true
bootstrap_resolvers = []
netprobe_address = '1.1.1.1:443'
netprobe_timeout = 5
http3 = false
cache = true
log_level = 2
""" % repr([name for name, _, _ in servers])
    for name, address, hostname in servers:
        result += "\n[static.'%s']\nstamp = '%s'\n" % (name, stamp(address, hostname))
    return result


SERVICE = """[Unit]
Description=Xcli public DNS over HTTPS
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
DynamicUser=true
ExecStart=/usr/sbin/dnscrypt-proxy -config /etc/xcli-doh.toml
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
UMask=0077

[Install]
WantedBy=multi-user.target
"""

RESOLVER = """# Route public names through DoH. More-specific per-link private domains remain.
[Resolve]
DNS=
DNS=127.0.0.1:5053
FallbackDNS=
Domains=~.
DNSOverTLS=no
"""


def run(*args, check=True, timeout=120):
    result = subprocess.run(list(map(str, args)), capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(str(args[0]) + ' failed: ' + result.stderr.decode(errors='replace')[-2000:])
    return result


def write(path, content, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.xcli-doh-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def query(address='127.0.0.1', port=5053, domain='example.com', record=1):
    ident = int.from_bytes(os.urandom(2), 'big')
    wire = b''.join(bytes([len(label)]) + label.encode() for label in domain.split('.')) + b'\0'
    request = struct.pack('!6H', ident, 0x100, 1, 0, 0, 0) + wire + struct.pack('!2H', record, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(8)
        sock.connect((address, port))
        sock.send(request)
        response = sock.recv(65535)
    if len(response) < 12:
        raise RuntimeError('Truncated DNS response')
    header = struct.unpack('!6H', response[:12])
    if header[0] != ident or not header[1] & 0x8000 or header[1] & 15 or not header[3]:
        raise RuntimeError('DNS query did not return a successful answer')
    return header[3]


def ready():
    for _ in range(10):
        try:
            query()
            return
        except (OSError, RuntimeError):
            time.sleep(.5)
    raise RuntimeError('DoH did not become ready')


def restore(backup):
    manifest = json.loads((backup / 'manifest.json').read_text())
    # Restore the normal resolver before stopping its current upstream.
    RESOLVED.unlink(missing_ok=True)
    run('systemctl', 'restart', 'systemd-resolved')
    run('systemctl', 'disable', '--now', 'xcli-doh.service', check=False)
    for path in (CONFIG, UNIT):
        path.unlink(missing_ok=True)
    run('systemctl', 'daemon-reload')
    if manifest['installed_package']:
        # Keep the distribution package available, but leave its default services off.
        run('systemctl', 'disable', '--now', *STOCK, check=False)
        run('systemctl', 'unmask', *STOCK, check=False)
    print('Previous system DNS restored; proxy services and accounts retained.')


def apply(backup):
    if backup.parent != Path('/root') or backup.exists():
        raise ValueError('Choose an unused backup directory directly under /root')
    for path in (CONFIG, UNIT, RESOLVED):
        if path.exists() or path.is_symlink():
            raise ValueError('Refusing to overwrite existing file: ' + str(path))
    run('systemctl', 'is-active', '--quiet', 'systemd-resolved')
    if Path('/etc/resolv.conf').resolve() != Path('/run/systemd/resolve/stub-resolv.conf'):
        raise ValueError('Requires the existing systemd-resolved stub; no resolv.conf replacement is performed')
    for unit in STOCK:
        if run('systemctl', 'is-active', '--quiet', unit, check=False).returncode == 0:
            raise ValueError('An existing DNSCrypt service is active; preserve its configuration')
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.bind(('127.0.0.1', 5053))
    installed = not Path('/usr/sbin/dnscrypt-proxy').exists()
    if installed:
        for unit in STOCK:
            for base in ('/etc/systemd/system', '/run/systemd/system'):
                path = Path(base) / unit
                if path.exists() or path.is_symlink():
                    raise ValueError('Preserve existing DNSCrypt unit override: ' + str(path))
    backup.mkdir(mode=0o700)
    write(backup / 'manifest.json', json.dumps({'installed_package': installed}), 0o600)
    shutil.copyfile(__file__, backup / 'doh.py')
    os.chmod(backup / 'doh.py', 0o600)
    write(backup / 'rollback.sh', '#!/bin/sh\nset -eu\nexec /usr/bin/python3 "$(dirname -- "$0")/doh.py" restore "$(dirname -- "$0")"\n', 0o700)
    write(backup / 'resolved-before.txt', run('resolvectl', 'status').stdout.decode(), 0o600)
    try:
        if installed:
            # Suppress the distribution's default resolver and automatic resolvconf hook.
            run('systemctl', 'mask', *STOCK)
            run('apt-get', 'install', '-y', '--no-install-recommends', 'dnscrypt-proxy', timeout=300)
            run('systemctl', 'disable', *STOCK, check=False)
        write(CONFIG, configuration())
        run('/usr/sbin/dnscrypt-proxy', '-config', CONFIG, '-check')
        write(UNIT, SERVICE)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', '--now', 'xcli-doh.service')
        ready()
        write(RESOLVED, RESOLVER)
        run('systemctl', 'restart', 'systemd-resolved')
        selected = run('resolvectl', 'dns').stdout.decode().splitlines()[0].split(':', 1)[1].strip()
        if selected != '127.0.0.1:5053':
            raise RuntimeError('Another system DNS setting overrides the DoH upstream')
        query('127.0.0.53', 53)
        print('Public system DNS now uses verified DoH; rollback: ' + str(backup / 'rollback.sh'))
    except BaseException:
        restore(backup)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['apply', 'restore'])
    parser.add_argument('backup', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run as root')
    (apply if args.action == 'apply' else restore)(args.backup)


if __name__ == '__main__':
    main()
