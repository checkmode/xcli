#!/usr/bin/env python3
"""Compare subscription output on private copies of an existing panel state.

Run as root inside a private network namespace. Only aggregate outcomes are
printed. The production database and configuration are opened read-only; the
copies and synthetic administrator credential are removed when the test ends.
"""
import argparse
from collections import Counter
from contextlib import closing, suppress
import hashlib
import http.client
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import time


def request(port, path, method='GET', body=None, cookie='', origin=''):
    headers = {'Content-Type': 'application/json'}
    if origin: headers['Origin'] = origin
    if cookie: headers['Cookie'] = cookie
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=20)
    try:
        conn.request(method, path, body, headers)
        response = conn.getresponse()
        return response.status, dict((key.lower(), value) for key, value in response.getheaders()), response.read()
    finally:
        conn.close()


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def ready(process, port):
    end = time.monotonic() + 20
    while time.monotonic() < end:
        if process.poll() is not None:
            return False
        try:
            if request(port, '/healthz')[0] == 200: return True
        except OSError:
            pass
        time.sleep(.1)
    return False


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try: process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5)


def rule_changes(old, new):
    removed, added = Counter(old) - Counter(new), Counter(new) - Counter(old)
    allowed = {'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6',
               'GEOIP', 'RULE-SET', 'FINAL', 'MATCH', 'USER-AGENT', 'PROCESS-NAME'}
    def types(items):
        result = Counter()
        for line, count in items.items():
            kind = str(line).split(',', 1)[0].strip().upper()
            result[kind if kind in allowed else 'OTHER'] += count
        return dict(sorted(result.items()))
    return {'removed_by_type': types(removed), 'added_by_type': types(added)}


GOOGLE_DOMAINS = {'google.com', 'google.cn', 'google.com.hk', 'google.com.sg', 'google.com.tw',
                  'google.com.au', 'google.co.jp', 'google.co.uk', 'google.co.in', 'google.com.br',
                  'google.de', 'google.fr', 'g.co', 'android.com', 'googleapis.com', 'gstatic.com',
                  'googleusercontent.com', 'googleplay.com', 'ggpht.com', 'gvt1.com', 'gvt2.com',
                  'google-analytics.com', 'googletagmanager.com', 'googleadservices.com', 'googlesyndication.com'}


def google_rule(line):
    fields = str(line).split(',')
    return (len(fields) >= 3 and ((fields[0] == 'RULE-SET' and fields[1] == 'category-Google')
            or (fields[0] == 'DOMAIN-SUFFIX' and fields[1] in GOOGLE_DOMAINS)
            or (fields[0] == 'DOMAIN-KEYWORD' and fields[1] == 'google')))


def earlier(rules, first, second):
    try: return rules.index(first) < rules.index(second)
    except ValueError: return False


def clash_service_before_google(config, hostname, target):
    rules, providers = config.get('rules', []), config.get('rule-providers', {})
    try: limit = rules.index('RULE-SET,category-Google,独立 · Google')
    except ValueError: return False
    def matches(value):
        fields = value.split(',')
        if len(fields) < 2: return False
        kind, name = fields[0], fields[1]
        return (kind == 'DOMAIN' and hostname == name or
                kind == 'DOMAIN-SUFFIX' and (hostname == name or hostname.endswith('.' + name)) or
                kind == 'DOMAIN-KEYWORD' and name in hostname)
    for line in rules[:limit]:
        parts = str(line).split(',')
        if len(parts) < 3 or parts[-1] != target: continue
        if parts[0] == 'RULE-SET':
            provider = providers.get(parts[1], {})
            if any(isinstance(item, str) and matches(item) for item in provider.get('payload', [])):
                return True
        elif matches(line):
            return True
    return False


def diagnostics(label, old_body, new_body):
    # Report only section sizes and rule types, never node names, domains,
    # credentials, subscription paths or raw configuration values.
    if label == 'Clash':
        import yaml
        before, after = yaml.safe_load(old_body), yaml.safe_load(new_body)
        if not isinstance(before, dict) or not isinstance(after, dict): return {'shape': 'non-object'}
        summary = {}
        for field in ('proxies', 'proxy-groups', 'rules'):
            a, b = before.get(field, []), after.get(field, [])
            if isinstance(a, list) and isinstance(b, list): summary[field + '_counts'] = [len(a), len(b)]
        for name in ('独立 · AI', '独立 · Google'):
            summary['has_' + name] = [any(isinstance(x, dict) and x.get('name') == name for x in before.get('proxy-groups', [])),
                                      any(isinstance(x, dict) and x.get('name') == name for x in after.get('proxy-groups', []))]
        if isinstance(before.get('rules'), list) and isinstance(after.get('rules'), list):
            summary['rule_changes'] = rule_changes(before['rules'], after['rules'])
            summary['non_google_rules_unchanged'] = ([v for v in before['rules'] if not google_rule(v)] ==
                                                       [v for v in after['rules'] if not google_rule(v)])
            summary['ai_before_google'] = clash_service_before_google(after, 'gemini.google.com', '独立 · AI')
            summary['youtube_before_google'] = clash_service_before_google(after, 'youtube.com', '独立 · YouTube')
            added = Counter(after['rules']) - Counter(before['rules'])
            removed = Counter(before['rules']) - Counter(after['rules'])
            summary['google_rule_targets_correct'] = (not removed and added == Counter({
                'RULE-SET,category-Google,独立 · Google': 1, 'RULE-SET,category-Google,REJECT': 1}))
        summary['proxies_unchanged'] = before.get('proxies') == after.get('proxies')
        summary['other_groups_unchanged'] = ([g for g in before.get('proxy-groups', []) if g.get('name') != '独立 · Google'] ==
                                             [g for g in after.get('proxy-groups', []) if g.get('name') != '独立 · Google'])
        before_provider, after_provider = before.get('rule-providers', {}), after.get('rule-providers', {})
        summary['other_providers_unchanged'] = ({k: v for k, v in before_provider.items() if k != 'category-Google'} ==
                                                {k: v for k, v in after_provider.items() if k != 'category-Google'})
        payload = after_provider.get('category-Google', {}).get('payload', [])
        summary['google_provider_correct'] = (len(payload) == len(GOOGLE_DOMAINS) and
                                               set(payload) == {'DOMAIN-SUFFIX,' + d for d in GOOGLE_DOMAINS})
        before_dns, after_dns = before.get('dns', {}), after.get('dns', {})
        before_policy, after_policy = before_dns.get('nameserver-policy', {}), after_dns.get('nameserver-policy', {})
        dns_keys = {'+.' + domain for domain in GOOGLE_DOMAINS}
        summary['other_dns_unchanged'] = (
            {k: v for k, v in before_dns.items() if k != 'nameserver-policy'} ==
            {k: v for k, v in after_dns.items() if k != 'nameserver-policy'} and
            {k: v for k, v in before_policy.items() if k not in dns_keys} ==
            {k: v for k, v in after_policy.items() if k not in dns_keys})
        resolvers = ['https://1.1.1.1/dns-query#独立 · Google', 'https://1.0.0.1/dns-query#独立 · Google']
        summary['google_dns_correct'] = all(after_policy.get(k) == before_policy.get(k, resolvers) for k in dns_keys)
        summary['other_fields_unchanged'] = (
            {k: v for k, v in before.items() if k not in ('rules', 'proxy-groups', 'rule-providers', 'dns')} ==
            {k: v for k, v in after.items() if k not in ('rules', 'proxy-groups', 'rule-providers', 'dns')})
        return summary
    if label == '小火箭配置':
        def sections(body):
            values, current = {}, None
            for line in body.decode('utf-8').splitlines():
                text = line.strip()
                if text.startswith('[') and text.endswith(']'):
                    current = text[1:-1]
                    values.setdefault(current, [])
                elif current and text and not text.startswith('#'):
                    values[current].append(text)
            return values
        before, after = sections(old_body), sections(new_body)
        result = {section + '_counts': [len(before.get(section, [])), len(after.get(section, []))]
                  for section in ('Proxy', 'Proxy Group', 'Rule')}
        result['rule_changes'] = rule_changes(before.get('Rule', []), after.get('Rule', []))
        before_rules, after_rules = before.get('Rule', []), after.get('Rule', [])
        result['non_google_rules_unchanged'] = ([v for v in before_rules if not google_rule(v)] ==
                                                [v for v in after_rules if not google_rule(v)])
        before_groups, after_groups = before.get('Proxy Group', []), after.get('Proxy Group', [])
        keep = lambda row: row.split('=', 1)[0].strip() != 'XCLI-独立 · Google'
        result['other_groups_unchanged'] = ([v for v in before_groups if keep(v)] == [v for v in after_groups if keep(v)])
        result['google_group_added'] = (all(keep(v) for v in before_groups) and
                                        sum(not keep(v) for v in after_groups) == 1)
        result['other_sections_unchanged'] = ({k: v for k, v in before.items() if k not in ('Rule', 'Proxy Group')} ==
                                               {k: v for k, v in after.items() if k not in ('Rule', 'Proxy Group')})
        google = 'DOMAIN-SUFFIX,google.com,XCLI-独立 · Google'
        result['ai_before_google'] = earlier(after_rules, 'DOMAIN-SUFFIX,gemini.google.com,XCLI-独立 · AI', google)
        result['youtube_before_google'] = earlier(after_rules, 'DOMAIN-SUFFIX,youtube.com,XCLI-独立 · YouTube', google)
        added, removed = Counter(after_rules) - Counter(before_rules), Counter(before_rules) - Counter(after_rules)
        result['google_rule_targets_correct'] = (
            all(google_rule(row) for row in removed) and
            all(google_rule(row) and row.split(',')[-1].strip() in ('XCLI-独立 · Google', 'REJECT') for row in added))
        result['comments_unchanged'] = ([line for line in old_body.decode('utf-8').splitlines() if line.strip().startswith('#')] ==
                                        [line for line in new_body.decode('utf-8').splitlines() if line.strip().startswith('#')])
        return result
    return {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--settings', type=Path, required=True)
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--legacy-bin', type=Path, required=True)
    parser.add_argument('--rust-bin', type=Path, required=True)
    parser.add_argument('--service-user', required=True)
    parser.add_argument('--scratch', type=Path, required=True)
    parser.add_argument('--allow-google-upgrade', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0 or os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
        raise RuntimeError('需要 root 和独立网络命名空间')
    account = pwd.getpwnam(args.service_user)
    if account.pw_uid == 0:
        raise RuntimeError('测试服务账户不能是 root')
    old = new = None
    with tempfile.TemporaryDirectory(prefix='xcli-compat-', dir=args.scratch) as directory:
        root = Path(directory)
        os.chmod(root, 0o700); os.chown(root, account.pw_uid, account.pw_gid)
        settings, key = root / 'settings.json', root / 'security.key'
        shutil.copyfile(args.settings, settings); shutil.copyfile(args.key, key)
        for file in (settings, key):
            os.chmod(file, 0o600); os.chown(file, account.pw_uid, account.pw_gid)
        origin = json.loads(settings.read_text())['origin']
        legacy_state, rust_state = root / 'legacy', root / 'rust'
        for state in (legacy_state, rust_state):
            state.mkdir(mode=0o700); os.chown(state, account.pw_uid, account.pw_gid)
        with closing(sqlite3.connect('file:' + str(args.state / 'gateway.sqlite') + '?mode=ro', uri=True)) as source:
            with closing(sqlite3.connect(legacy_state / 'gateway.sqlite')) as target:
                source.backup(target)
        password = 'fixture-password-123'
        salt = bytes(range(16))
        digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
        with closing(sqlite3.connect(legacy_state / 'gateway.sqlite')) as snapshot:
            snapshot.execute('UPDATE admin SET password=? WHERE id=1', (salt.hex() + ':' + digest.hex(),))
            snapshot.execute('UPDATE mfa SET enabled=0 WHERE id=1')
            snapshot.execute('DELETE FROM sessions')
            snapshot.execute('DELETE FROM mfa_sessions')
            snapshot.commit()
            with closing(sqlite3.connect(rust_state / 'gateway.sqlite')) as destination:
                snapshot.backup(destination)
        for state in (legacy_state, rust_state):
            database = state / 'gateway.sqlite'
            os.chmod(database, 0o600); os.chown(database, account.pw_uid, account.pw_gid)
            dynamic = args.state / 'webshare/config.xgb'
            if dynamic.is_file():
                (state / 'webshare').mkdir(mode=0o700)
                shutil.copyfile(dynamic, state / 'webshare/config.xgb')
                os.chown(state / 'webshare', account.pw_uid, account.pw_gid)
                os.chown(state / 'webshare/config.xgb', account.pw_uid, account.pw_gid)
                os.chmod(state / 'webshare/config.xgb', 0o600)
        with closing(sqlite3.connect(legacy_state / 'gateway.sqlite')) as snapshot:
            tokens = [row[0] for row in snapshot.execute('SELECT token FROM users WHERE deleted=0')]
        old_port, new_port = free_port(), free_port()
        common = {'user': account.pw_uid, 'group': account.pw_gid, 'extra_groups': [],
                  'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL}
        try:
            old = subprocess.Popen([str(args.legacy_bin), '--state', str(legacy_state), '--settings', str(settings),
                '--static', str(root), '--secret-key', str(key), '--port', str(old_port), '--offline', '--no-auto-backup'], **common)
            if not ready(old, old_port): raise RuntimeError('旧版快照服务未启动')
            new = subprocess.Popen([str(args.rust_bin), '--experimental', '--db', str(rust_state / 'gateway.sqlite'),
                '--settings', str(settings), '--secret-key', str(key), '--origin', origin, '--port', str(new_port),
                '--experimental-strict-settings', 'true'], **common)
            if not ready(new, new_port): raise RuntimeError('Rust 快照服务未通过配置或启动检查')
            for implementation, port in (('旧版', old_port), ('Rust', new_port)):
                status, headers, _ = request(port, '/api/login', 'POST',
                    json.dumps({'username': 'admin', 'password': password}).encode(), origin=origin)
                if status != 200 or 'set-cookie' not in headers: raise RuntimeError('快照管理员登录未通过')
                path = '/api/overview' if implementation == '旧版' else '/api/users'
                status = request(port, path, cookie=headers['set-cookie'].split(';', 1)[0], origin=origin)[0]
                if status != 200:
                    raise RuntimeError(f'{implementation}快照用户列表不可用（HTTP {status}）')
            results = {}
            for label, suffix in (('通用', ''), ('Clash', '/clash.yaml'),
                                  ('小火箭安装', '/shadowrocket.json'), ('小火箭配置', '/shadowrocket.conf')):
                matching = 0
                expected = 0
                failures = Counter()
                for token in tokens:
                    path = '/s/' + token + suffix
                    old_status, old_headers, old_body = request(old_port, path)
                    new_status, new_headers, new_body = request(new_port, path)
                    if suffix.endswith('.json'):
                        with suppress(ValueError, UnicodeError):
                            old_body, new_body = json.loads(old_body), json.loads(new_body)
                    compared_headers = ('content-type', 'subscription-userinfo', 'profile-update-interval', 'content-disposition')
                    same_headers = all(old_headers.get(name) == new_headers.get(name) for name in compared_headers)
                    if old_status == new_status and old_body == new_body and same_headers:
                        matching += 1
                    else:
                        failures['status'] += old_status != new_status
                        failures['body'] += old_body != new_body
                        failures['headers'] += not same_headers
                        if old_status == new_status == 200 and old_body != new_body:
                            try:
                                summary = diagnostics(label, old_body, new_body)
                                if summary:
                                    failures[json.dumps(summary, ensure_ascii=False, sort_keys=True)] += 1
                                    required = ['non_google_rules_unchanged', 'other_groups_unchanged',
                                                'ai_before_google', 'youtube_before_google', 'google_rule_targets_correct']
                                    if label == 'Clash':
                                        required += ['proxies_unchanged', 'other_providers_unchanged',
                                                     'other_dns_unchanged', 'other_fields_unchanged',
                                                     'google_provider_correct', 'google_dns_correct']
                                        planned = summary.get('has_独立 · Google') == [False, True]
                                    else:
                                        required += ['other_sections_unchanged', 'google_group_added', 'comments_unchanged']
                                        planned = label == '小火箭配置'
                                    if args.allow_google_upgrade and same_headers and planned and all(summary.get(k) is True for k in required):
                                        expected += 1
                            except Exception:
                                failures['diagnostics_unavailable'] += 1
                results[label] = (matching, len(tokens), expected, failures)
            print('管理员登录和用户管理接口：新旧版本均通过')
            for label, (matching, total, expected, failures) in results.items():
                print(f'{label}订阅：{matching}/{total} 响应一致')
                if expected: print(f'  另有 {expected} 项为已确认的独立 Google 分组升级')
                for detail, count in failures.items():
                    if count: print(f'  {detail}: {count}')
            if any(matching + expected != total for matching, total, expected, _ in results.values()):
                raise RuntimeError('新旧订阅存在差异，需要继续排查')
        finally:
            stop(new); stop(old)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, sqlite3.Error, subprocess.SubprocessError) as error:
        # Do not print request paths, configuration, credentials or process output.
        print('快照对照未通过：' + (str(error) if isinstance(error, RuntimeError) else type(error).__name__))
        raise SystemExit(1)
