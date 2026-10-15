#!/usr/bin/env python3
"""Prepare a narrowly scoped HTTPS bootstrap exception; never apply it implicitly."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re


def rule_for(address, user_id):
    address = ipaddress.IPv4Address(address)
    if not address.is_global or address.is_multicast or not re.fullmatch(r'[0-9a-f]{32}', user_id):
        raise ValueError('Expected a public IPv4 address and a 32-character user ID')
    return {
        'type': 'field', 'ruleTag': 'subscription-https-' + user_id,
        'user': ['regexp:^' + user_id + r'\.[0-9a-f]{8}@'],
        'ip': [str(address) + '/32'], 'port': '443', 'network': 'tcp',
        'outboundTag': 'direct',
    }


def core_candidate(core, address, user_id):
    rule = rule_for(address, user_id)
    if not any(item.get('tag') == 'direct' and item.get('protocol') == 'freedom'
               for item in core.get('outbounds', [])):
        raise ValueError('The existing direct outbound is missing')
    rules = core['routing']['rules']
    if any(item.get('ruleTag') == rule['ruleTag'] for item in rules):
        raise ValueError('This account already has a bootstrap rule; review it first')
    if not any(item.get('outboundTag') == 'blocked' and str(address) + '/32' in item.get('ip', [])
               for item in rules):
        raise ValueError('The expected self-address block is missing')
    result = copy.deepcopy(core)
    result['routing']['rules'].insert(0, rule)
    return result


def firewall_candidate(source, address):
    address = str(ipaddress.IPv4Address(address))
    if not ipaddress.IPv4Address(address).is_global or ipaddress.IPv4Address(address).is_multicast:
        raise ValueError('Expected a public IPv4 address')
    command = f'iptables -w -A XG_OUT -d {address}/32 -p tcp --dport 443 -j RETURN'
    if command in source:
        raise ValueError('The HTTPS firewall exception already exists')
    lines = source.splitlines(keepends=True)
    anchors = [i for i, line in enumerate(lines)
               if line.lstrip().startswith('for net in ') and address + '/32' in line
               and 'iptables -w -A XG_OUT' in line and '-j REJECT' in line]
    if len(anchors) != 1:
        raise ValueError('Cannot identify the existing self-address firewall block')
    lines.insert(anchors[0], '    ' + command + '\n')
    return ''.join(lines)


def prepare(core_path, firewall_path, output, address, user_id):
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sources = {str(core_path): Path(core_path).read_bytes(),
               str(firewall_path): Path(firewall_path).read_bytes()}
    candidate = core_candidate(json.loads(sources[str(core_path)]), address, user_id)
    firewall = firewall_candidate(sources[str(firewall_path)].decode(), address)
    for name, value in [('core.candidate.json', json.dumps(candidate, indent=2) + '\n'),
                        ('firewall.candidate.sh', firewall)]:
        path = output / name
        path.write_text(value)
        path.chmod(0o600)
    manifest = {
        'user_id': user_id, 'destination': str(address) + ':443/tcp',
        'baseline': {name: hashlib.sha256(value).hexdigest() for name, value in sources.items()},
        'changes': {'core': 'prepend one account-specific rule',
                    'firewall': 'allow only the public self-address on TCP 443'},
        'requires_core_restart': True,
    }
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--firewall', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--public-ip', required=True)
    parser.add_argument('--user-id', required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.core, args.firewall, args.output, args.public_ip, args.user_id), indent=2))
