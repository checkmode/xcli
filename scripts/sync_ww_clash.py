#!/usr/bin/env python3
"""Generate the current profile's ww-only script; inherit public policy from each subscription update."""
import argparse
import copy
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import yaml
import local_network_policy

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE = pathlib.Path(__file__).with_name('ww_clash.js')
DEFAULT_BYPASS = ['127.0.0.1', '192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12',
                  'localhost', '*.local', '*.crashlytics.com', '<local>']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def script_policy(text):
    if not text.startswith('// xcli ww local policy:'):
        # Never overwrite another user's script.
        stripped = re.sub(r'//[^\n]*', '', text).strip()
        if not re.fullmatch(r'function\s+main\s*\(config(?:,\s*profileName)?\)\s*\{\s*return config;?\s*\}', stripped):
            raise ValueError('Existing script is not an empty template or an xcli ww script')
        return None
    found = re.search(r'^const WW_POLICY = (.*);$', text, re.M)
    if not found:
        raise ValueError('Malformed managed script')
    return json.loads(found[1])


def remove_legacy(merge, rules, subscription, previous):
    """One-time migration of known ww entries and identical subscription copies."""
    dns = merge.get('dns', {})
    for key, value in list(dns.items()):
        if key not in ('nameserver-policy', 'fake-ip-filter', 'direct-nameserver-follow-policy'):
            if subscription.get('dns', {}).get(key) == value:
                del dns[key]
    mapping = dns.get('nameserver-policy', {})
    owned = {'+.' + k: [v] for k, v in previous['dns'].items()}
    for key, value in list(mapping.items()):
        if owned.get(key) == value or subscription.get('dns', {}).get('nameserver-policy', {}).get(key) == value:
            del mapping[key]
    if not mapping:
        dns.pop('nameserver-policy', None)
    if 'fake-ip-filter' in dns:
        dns['fake-ip-filter'] = [v for v in dns['fake-ip-filter'] if v not in ['+.' + s for s in previous['suffixes']]]
        if not dns['fake-ip-filter']:
            del dns['fake-ip-filter']
    if previous['dns'] and dns.get('direct-nameserver-follow-policy') is True:
        del dns['direct-nameserver-follow-policy']
    if not dns:
        merge.pop('dns', None)
    removable = set(local_network_policy.rules(previous) + subscription.get('rules', []))
    rules['prepend'] = [v for v in rules.get('prepend', []) if v not in removable]


def merge_mapping(base, patch):
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            merge_mapping(base[key], value)
        else:
            base[key] = copy.deepcopy(value)
    return base


def run_script(script, config):
    # Node is used only for the preview. Verge runs the same script in its JS engine.
    runner = script + '\nprocess.stdout.write(JSON.stringify(main(JSON.parse(require("fs").readFileSync(0,"utf8")))));'
    result = subprocess.run(['node', '-e', runner], input=json.dumps(config), text=True, capture_output=True)
    if result.returncode:
        raise ValueError('Generated script validation failed: ' + result.stderr[:800])
    return json.loads(result.stdout)


def prepare(config_dir, output, zprofile, legacy_policy=None):
    policy = local_network_policy.load(zprofile)
    profiles_path = config_dir / 'profiles.yaml'
    profiles = yaml.safe_load(profiles_path.read_text())
    active = next(p for p in profiles['items'] if p['uid'] == profiles['current'])
    files = {x['uid']: x['file'] for x in profiles['items'] if x.get('file')}
    targets = {k: config_dir / 'profiles' / files[active['option'][k]] for k in ('merge', 'rules', 'script')}
    for kind, target in targets.items():
        if target.parent.resolve() != (config_dir / 'profiles').resolve() or target.is_symlink():
            raise ValueError('Unexpected profile path')
        if active['option'][kind] in ('Merge', 'Script') or any(
            p['uid'] != active['uid'] and p.get('option', {}).get(kind) == active['option'][kind]
            for p in profiles['items']
        ):
            raise ValueError('Refusing to change a shared/global extension')
    original = {k: p.read_bytes() for k, p in targets.items()}
    old = script_policy(original['script'].decode())
    merge = yaml.safe_load(original['merge']) or {}
    rules = yaml.safe_load(original['rules']) or {}
    source = config_dir / 'profiles' / active['file']
    subscription = yaml.safe_load(source.read_text())
    inputs = [profiles_path, source, pathlib.Path(zprofile), TEMPLATE]
    if legacy_policy:
        if old:
            raise ValueError('Legacy migration is only valid before the first managed script')
        previous = json.loads(pathlib.Path(legacy_policy).read_text())
        remove_legacy(merge, rules, subscription, previous)
        inputs.append(pathlib.Path(legacy_policy))
    else:
        previous = {'system_bypass': []}
    verge_path = config_dir / 'verge.yaml'
    verge = yaml.safe_load(verge_path.read_text()) or {}
    inputs.append(verge_path)
    current_bypass = [v.strip() for v in (verge.get('system_proxy_bypass') or ','.join(DEFAULT_BYPASS)).split(',') if v.strip()]
    owned_bypass = old.get('bypass', []) if old else previous['system_bypass']
    base = old.get('bypass_base', DEFAULT_BYPASS) if old else DEFAULT_BYPASS
    # Shared baseline items survive even if ww removes the same item.
    bypass_base = [v for v in current_bypass if v not in owned_bypass or v in base]
    data = {'rules': local_network_policy.rules(policy),
            'dns': {'+.' + k: [v] for k, v in policy['dns'].items()},
            'filters': ['+.' + s for s in policy['suffixes']] + policy['exact'],
            'bypass': policy['system_bypass'], 'bypass_base': bypass_base}
    script = TEMPLATE.read_text().replace('__WW_POLICY__', json.dumps(data, ensure_ascii=False))
    # Preview starts from the downloaded subscription, never yesterday's runtime.
    candidate = copy.deepcopy(subscription)
    candidate['rules'] = rules.get('prepend', []) + [r for r in candidate.get('rules', []) if r not in rules.get('delete', [])] + rules.get('append', [])
    global_merge = config_dir / 'profiles' / files.get('Merge', 'Merge.yaml')
    if global_merge.exists():
        merge_mapping(candidate, yaml.safe_load(global_merge.read_text()) or {})
        inputs.append(global_merge)
    merge_mapping(candidate, merge)
    candidate = run_script(script, candidate)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    artifacts = {'merge.yaml': yaml.safe_dump(merge, sort_keys=False), 'rules.yaml': yaml.safe_dump(rules, sort_keys=False),
                 'script.js': script, 'candidate.yaml': yaml.safe_dump(candidate, allow_unicode=True, sort_keys=False),
                 'policy.json': json.dumps(policy, ensure_ascii=False, indent=2),
                 'bypass.txt': ','.join(dict.fromkeys(bypass_base + policy['system_bypass']))}
    for name, value in artifacts.items():
        path = output / name
        path.write_text(value)
        path.chmod(0o600)
    manifest = {'targets': {k: str(v) for k, v in targets.items()},
                'sha256': {str(p): digest(p) for p in list(targets.values()) + inputs},
                'artifacts': {name: digest(output / name) for name in artifacts},
                'profile_uid': active['uid']}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2))
    return policy


def apply(output):
    manifest = json.loads((output / 'manifest.json').read_text())
    for name, expected in manifest['sha256'].items():
        if digest(pathlib.Path(name)) != expected:
            raise ValueError('Profile or input changed since preparation: ' + name)
    for name, expected in manifest['artifacts'].items():
        if digest(output / name) != expected:
            raise ValueError('Prepared artifact changed: ' + name)
    backup = output / ('backup-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    backup.mkdir(mode=0o700)
    for target in manifest['targets'].values():
        shutil.copy2(target, backup / pathlib.Path(target).name)
    changed = []
    try:
        for kind, target in manifest['targets'].items():
            path = pathlib.Path(target)
            artifact = 'script.js' if kind == 'script' else kind + '.yaml'
            temporary = path.with_suffix(path.suffix + '.ww-tmp')
            temporary.write_bytes((output / artifact).read_bytes())
            temporary.chmod(path.stat().st_mode & 0o777)
            os.replace(temporary, path)
            changed.append(path)
    except Exception:
        for path in changed:
            shutil.copy2(backup / path.name, path)
        raise
    print('Local profile extensions saved. Backup: ' + str(backup))
    print('Reactivate Profiles. Replace the custom System Proxy bypass list with bypass.txt (do not append).')


if __name__ == '__main__':
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config-dir', type=pathlib.Path, default=pathlib.Path.home() / 'Library/Application Support/io.github.clash-verge-rev.clash-verge-rev')
    p.add_argument('--output', type=pathlib.Path, default=ROOT / 'private/ww-clash')
    p.add_argument('--zprofile', type=pathlib.Path, default=pathlib.Path.home() / '.zprofile')
    p.add_argument('--legacy-policy', type=pathlib.Path, help='One-time migration: previously applied ww policy.json')
    p.add_argument('--apply', action='store_true')
    a = p.parse_args()
    if a.apply:
        apply(a.output)
    else:
        policy = prepare(a.config_dir, a.output, a.zprofile, a.legacy_policy)
        print(json.dumps({'suffixes': policy['suffixes'], 'dns': policy['dns'], 'rules': len(local_network_policy.rules(policy))}, ensure_ascii=False))
