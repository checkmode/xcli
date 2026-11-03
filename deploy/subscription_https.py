#!/usr/bin/env python3
"""Prepare a narrowly scoped HTTPS bootstrap exception; never apply it implicitly."""
import copy
import hashlib
import ipaddress
import json
from pathlib import Path
import re

ALL_USERS_TAG = 'subscription-https-all'
ALL_USERS_PATTERN = r'regexp:^[0-9a-f]{32}\.[0-9a-f]{8}@'


def all_users_rule_for(address, public_port=443):
    address = ipaddress.IPv4Address(address)
    if not address.is_global or address.is_multicast or type(public_port) is not int or not 1 <= public_port <= 65535:
        raise ValueError('Expected a public IPv4 address and a valid port')
    return {'type': 'field', 'ruleTag': ALL_USERS_TAG, 'user': [ALL_USERS_PATTERN],
            'ip': [str(address) + '/32'], 'port': str(public_port), 'network': 'tcp', 'outboundTag': 'direct'}


def rule_for(address, user_id, public_port=443):
    address = ipaddress.IPv4Address(address)
    if not address.is_global or address.is_multicast or not re.fullmatch(r'[0-9a-f]{32}', user_id) or type(public_port) is not int or not 1 <= public_port <= 65535:
        raise ValueError('Expected a public IPv4 address and a 32-character user ID')
    return {
        'type': 'field', 'ruleTag': 'subscription-https-' + user_id,
        'user': ['regexp:^' + user_id + r'\.[0-9a-f]{8}@'],
        'ip': [str(address) + '/32'], 'port': str(public_port), 'network': 'tcp',
        'outboundTag': 'direct',
    }


def core_candidate(core, address, user_id, public_port=443):
    rule = rule_for(address, user_id, public_port)
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


def all_users_candidate(core, address, public_port=443):
    """Replace only known account exceptions; keep every other rule unchanged."""
    rule = all_users_rule_for(address, public_port)
    if not any(item.get('tag') == 'direct' and item.get('protocol') == 'freedom'
               for item in core.get('outbounds', [])):
        raise ValueError('The existing direct outbound is missing')
    rules = core['routing']['rules']
    if not any(item.get('outboundTag') == 'blocked' and str(address) + '/32' in item.get('ip', []) for item in rules):
        raise ValueError('The expected self-address block is missing')
    retained = []
    for item in rules:
        tag = item.get('ruleTag', '')
        if tag == ALL_USERS_TAG:
            if item != rule:
                raise ValueError('Existing all-user rule does not match the safe scope')
            continue
        match = re.fullmatch(r'subscription-https-([0-9a-f]{32})', tag) if isinstance(tag, str) else None
        if match:
            if item != rule_for(address, match.group(1), public_port):
                raise ValueError('Existing account rule does not match the safe scope')
            continue
        retained.append(copy.deepcopy(item))
    result = copy.deepcopy(core)
    result['routing']['rules'] = [rule] + retained
    return result


def is_bootstrap_rule(rule, settings, core):
    """Recognize only exact generated exceptions with their existing protections."""
    try:
        address, port = settings['public_ip'], settings.get('public_port', 443)
        tag = rule.get('ruleTag', '')
        match = re.fullmatch(r'subscription-https-([0-9a-f]{32})', tag) if isinstance(tag, str) else None
        expected = all_users_rule_for(address, port) if tag == ALL_USERS_TAG else rule_for(address, match.group(1), port) if match else None
        return (expected is not None and rule == expected and
                any(x.get('tag') == 'direct' and x.get('protocol') == 'freedom' for x in core.get('outbounds', [])) and
                any(x.get('outboundTag') == 'blocked' and str(address) + '/32' in x.get('ip', [])
                    for x in core['routing']['rules']))
    except (ValueError, KeyError, TypeError):
        return False


def firewall_candidate(source, address, public_port=443):
    address = str(ipaddress.IPv4Address(address))
    if not ipaddress.IPv4Address(address).is_global or ipaddress.IPv4Address(address).is_multicast or type(public_port) is not int or not 1 <= public_port <= 65535:
        raise ValueError('Expected a public IPv4 address')
    command = f'iptables -w -A XG_OUT -d {address}/32 -p tcp --dport {public_port} -j RETURN'
    if command in source:
        raise ValueError('The HTTPS firewall exception already exists')
    lines = source.splitlines(keepends=True)
    anchors = [i for i, line in enumerate(lines)
               if line.lstrip().startswith('for net in ') and address + '/32' in line
               and 'iptables -w -A XG_OUT' in line and '-j REJECT' in line]
    if len(anchors) != 1:
        raise ValueError('Cannot identify the existing self-address firewall block')
    local_blocks = [i for i, line in enumerate(lines)
                    if 'iptables -w -A XG_OUT' in line and '--dst-type LOCAL' in line and '-j REJECT' in line]
    if len(local_blocks) > 1:
        raise ValueError('Cannot identify the existing local-address firewall block')
    # A public address assigned to this host also matches ADDRTYPE LOCAL.
    # The exception must precede both local and explicit self-address rejects.
    position = min(anchors + local_blocks)
    lines.insert(position, '    ' + command + '\n')
    return ''.join(lines)


def all_users_firewall_candidate(source, address, public_port=443):
    """Preserve an existing exact exception, repairing its order if necessary."""
    address = str(ipaddress.IPv4Address(address))
    command = f'iptables -w -A XG_OUT -d {address}/32 -p tcp --dport {public_port} -j RETURN'
    lines = source.splitlines(keepends=True)
    found = [i for i, line in enumerate(lines) if line.strip() == command]
    if len(found) > 1:
        raise ValueError('Multiple HTTPS firewall exceptions require review')
    if not found:
        return firewall_candidate(source, address, public_port)
    # Validate and regenerate from the same input without the one exact line.
    stripped = ''.join(line for i, line in enumerate(lines) if i != found[0])
    return firewall_candidate(stripped, address, public_port)


def prepare(core_path, firewall_path, output, address, user_id, public_port=443):
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    sources = {str(core_path): Path(core_path).read_bytes(),
               str(firewall_path): Path(firewall_path).read_bytes()}
    candidate = core_candidate(json.loads(sources[str(core_path)]), address, user_id, public_port)
    firewall = firewall_candidate(sources[str(firewall_path)].decode(), address, public_port)
    for name, value in [('core.candidate.json', json.dumps(candidate, indent=2) + '\n'),
                        ('firewall.candidate.sh', firewall)]:
        path = output / name
        path.write_text(value)
        path.chmod(0o600)
    manifest = {
        'user_id': user_id, 'destination': str(address) + ':' + str(public_port) + '/tcp',
        'baseline': {name: hashlib.sha256(value).hexdigest() for name, value in sources.items()},
        'changes': {'core': 'prepend one account-specific rule',
                    'firewall': 'allow only the public self-address on the configured TCP port'},
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
    parser.add_argument('--public-port', type=int, default=443)
    args = parser.parse_args()
    print(json.dumps(prepare(args.core, args.firewall, args.output, args.public_ip, args.user_id, args.public_port), indent=2))
