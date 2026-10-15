#!/usr/bin/env python3
"""Collect minimal Clash routing observations; analyze on the designated server.
No configuration-writing or approval bypass exists in this tool.
"""
import argparse
import collections
import concurrent.futures
import datetime as dt
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import socket
import tempfile
import urllib.parse
import urllib.request

VERSION = 1
MAX_INPUT = 4 * 1024 * 1024
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
ROUTE = re.compile(r'\[(?:TCP|UDP)\].*?--> (\S+) match (.*?) using (.*?)(?:"\s*)?$')
STAMP = re.compile(r'time="([^" ]+)"')
RULE = re.compile(r'^(Domain|DomainSuffix|DomainKeyword|GeoSite|GeoIP|IPCIDR|RuleSet|Match|MATCH)(?:\(([A-Za-z0-9_.!@/+:-]{1,253})\))?$')

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')


def host(value, allow_local=False):
    value = value.lower().rstrip('.')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if len(value) > 253 or ('.' not in value and not allow_local) or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in value.split('.')):
        raise ValueError('Invalid public host')
    if not allow_local and value.endswith(('.localhost', '.local', '.internal', '.invalid', '.test')):
        raise ValueError('Local-only host')
    return value


def public_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def atomic(path, value):
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(value)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def collect(directory, policy=None):
    import local_network_policy
    if policy is None:
        policy = local_network_policy.load()
    local_counts = collections.Counter()
    counts = collections.Counter()
    first = last = None
    files = matched = skipped = 0
    for path in sorted(pathlib.Path(directory).glob('sidecar/*.log')):
        if path.is_symlink() or path.stat().st_size > 32 * 1024 * 1024:
            continue
        files += 1
        with path.open(errors='replace') as stream:
            for line in stream:
                match = ROUTE.search(line)
                if not match:
                    continue
                endpoint, rule, chain = match.groups()
                try:
                    raw_target = endpoint.rsplit(':', 1)[0].strip('[]')
                    local_reason = local_network_policy.match(raw_target, policy)
                    target = host(raw_target, allow_local=bool(local_reason))
                    if not local_reason and (':' in target or re.fullmatch(r'[0-9.]+', target)):
                        if not public_ip(target):
                            skipped += 1
                            continue
                except ValueError:
                    skipped += 1
                    continue
                # Do not transmit arbitrary log payloads, proxy labels or source endpoints.
                rule = rule if RULE.fullmatch(rule) else 'Other'
                action = 'DIRECT' if chain == 'DIRECT' else 'REJECT' if chain.startswith('REJECT') else 'PROXY'
                if local_reason:
                    local_counts[(target, rule, action, local_reason)] += 1
                else:
                    counts[(target, rule, action)] += 1
                matched += 1
                stamp = STAMP.search(line)
                if stamp:
                    try:
                        normalized = dt.datetime.fromisoformat(re.sub(r'(\.\d{6})\d+', r'\1', stamp[1]).replace('Z', '+00:00')).astimezone(dt.timezone.utc).isoformat(timespec='seconds')
                        first = min(first or normalized, normalized)
                        last = max(last or normalized, normalized)
                    except ValueError:
                        pass
    return {'schema': VERSION, 'collected_at': now(), 'coverage': {'files': files, 'events': matched, 'skipped': skipped, 'first': first, 'last': last},
            'local_observations': [{'host': h, 'rule': r, 'action': a, 'reason': why, 'count': c} for (h, r, a, why), c in sorted(local_counts.items())],
            'observations': [{'host': h, 'rule': r, 'action': a, 'count': c} for (h, r, a), c in sorted(counts.items())]}


def fetch(url, limit=8 * 1024 * 1024):
    request = urllib.request.Request(url, headers={'User-Agent': 'xcli-routing-audit/1', 'Accept': 'application/dns-json' if url.startswith('https://cloudflare-dns.com/dns-query') else 'application/json, text/plain'})
    with OPENER.open(request, timeout=10) as response:
        body = response.read(limit + 1)
        if len(body) > limit:
            raise ValueError('Response too large')
        return body


def safe_json(url):
    try:
        return json.loads(fetch(url, 1024 * 1024)), None
    except Exception as error:
        return {}, type(error).__name__


def load_rules():
    meta, error = safe_json('https://api.github.com/repos/Loyalsoldier/clash-rules/commits/release')
    revision = meta.get('sha', '')
    if error or not re.fullmatch('[0-9a-f]{40}', revision):
        return {}, {'status': 'unavailable', 'error': error or 'InvalidRevision'}
    sets, hashes = {}, {}
    try:
        for name in ('direct', 'proxy', 'gfw'):
            data = fetch('https://raw.githubusercontent.com/Loyalsoldier/clash-rules/' + revision + '/' + name + '.txt')
            exact, suffix = set(), set()
            for line in data.decode().splitlines():
                text = line.strip()
                if not text.startswith('- '):
                    continue
                entry = text[2:].strip().strip("'\"")
                is_suffix = entry.startswith('+.')
                try:
                    entry = host(entry[2:] if is_suffix else entry)
                except ValueError:
                    continue
                (suffix if is_suffix else exact).add(entry)
            if not exact and not suffix:
                raise ValueError('EmptyRuleSet')
            sets[name] = (exact, suffix)
            hashes[name] = hashlib.sha256(data).hexdigest()
    except Exception as failure:
        return {}, {'status': 'unavailable', 'error': type(failure).__name__, 'revision': revision}
    return sets, {'status': 'ok', 'repository': 'https://github.com/Loyalsoldier/clash-rules', 'revision': revision, 'sha256': hashes, 'fetched_at': now()}


def rule_match(name, rules):
    exact, suffix = rules
    if name in exact:
        return name
    pieces = name.split('.')
    return next((candidate for i in range(len(pieces)) if (candidate := '.'.join(pieces[i:])) in suffix), None)


def resolve(name):
    if public_ip(name):
        return {'literal': {'addresses': [name], 'cnames': [], 'error': None}}
    results = {}
    for label, base in [('cloudflare', 'https://cloudflare-dns.com/dns-query'), ('alidns', 'https://dns.alidns.com/resolve')]:
        addresses, cnames, errors = set(), set(), []
        for kind in ('A', 'AAAA'):
            value, error = safe_json(base + '?' + urllib.parse.urlencode({'name': name, 'type': kind}))
            if error or value.get('Status') != 0:
                errors.append(error or 'DNSStatus:' + str(value.get('Status')))
            for answer in value.get('Answer', []):
                data = answer.get('data', '')
                if answer.get('type') in (1, 28) and public_ip(data):
                    addresses.add(str(ipaddress.ip_address(data)))
                elif answer.get('type') == 5:
                    try:
                        cnames.add(host(data))
                    except ValueError:
                        pass
        results[label] = {'addresses': sorted(addresses), 'cnames': sorted(cnames), 'error': ','.join(errors) or None}
    return results


def lookup_ip(address):
    # Geolocation and ASN are clues, not website ownership or a routing decision.
    geo, error = safe_json('https://ipwho.is/' + urllib.parse.quote(address, safe=':'))
    value = {'ip': address, 'source': 'https://ipwho.is/', 'queried_at': now(), 'status': 'unavailable'}
    if not error and geo.get('success') is True and geo.get('ip') == address:
        connection = geo.get('connection', {})
        def clean(v):
            return ''.join(c for c in str(v)[:160] if c.isprintable())
        value.update(status='ok', country=clean(geo.get('country_code', '')), asn=clean(connection.get('asn', '')),
                     org=clean(connection.get('org', '')), isp=clean(connection.get('isp', '')))
    else:
        value['error'] = error or 'ProviderUnavailable'
    return value


def classify(observation, sets, dns, ips):
    name = observation['host']
    direct = rule_match(name, sets['direct']) if sets else None
    conflicts = {key: rule_match(name, sets[key]) for key in ('proxy', 'gfw')} if sets else {}
    conflicts = {key: value for key, value in conflicts.items() if value}
    proxied = observation['actions'].get('PROXY', 0) > 0
    countries = sorted({i['country'] for i in ips if i.get('status') == 'ok'})
    if not proxied:
        state, reason = 'already_direct' if observation['actions'].get('DIRECT') else 'no_proxy_observed', '日志没有记录该目标经代理转发'
    elif direct and not conflicts:
        state, reason = 'review_direct', '国内域名规则库收录且无代理库冲突；建议人工确认精确域名直连'
    elif direct and conflicts:
        state, reason = 'conflict', '国内与代理规则库冲突，需要人工判断具体服务'
    elif conflicts:
        state, reason = 'keep_proxy', '代理规则库收录；IP 位于中国也不自动改变分流'
    elif countries == ['CN']:
        state, reason = 'review_ownership', '已查到的 IP 均定位中国；这不足以证明业务归属或国内可访问'
    else:
        state, reason = 'unknown', '缺少充分证据；保留现有规则'
    return {**observation, 'state': state, 'reason': reason, 'direct_match': direct, 'proxy_matches': conflicts,
            'dns': dns, 'ip_evidence': ips, 'countries_observed': countries}


def markdown(report):
    labels = {'already_direct': '已直连', 'no_proxy_observed': '未观察到代理', 'review_direct': '待确认直连', 'review_ownership': '待核实归属', 'keep_proxy': '保留代理', 'conflict': '规则冲突', 'unknown': '证据不足'}
    def cell(value):
        return str(value).replace('|', '\\|').replace('\n', ' ')
    lines = ['# Clash 分流审计', '', '生成时间（UTC）：' + report['generated_at'], '',
             '**本报告未修改任何订阅、分流规则或 DNS 配置。所有新增规则都需要用户确认。**', '',
             '## 样本与证据', '', '日志覆盖：' + json.dumps(report['coverage'], ensure_ascii=False), '',
             '分析位置：Oracle；DNS 查询使用 Cloudflare 和 AliDNS 的公共 HTTPS 接口。即便使用国内 DNS，境外查询也不等同于中国本地解析。', '',
             'IP/ASN 来源：ipwho.is。IP 地理位置、ASN/运营商与网站业务归属不是同一概念；第三方结果仅供核查。未访问用户网页或发送完整 URL。', '',
             '规则库状态：' + report['rule_sources']['status'] + '；版本：' + report['rule_sources'].get('revision', '不可用'), '',
             '数据源：https://github.com/Loyalsoldier/clash-rules ，https://ipwho.is/', '',
             'IP 查询覆盖：' + json.dumps(report.get('ip_lookup_coverage', {}), ensure_ascii=False), '',
             '日志条数是连接事件数，不是字节数、流量大小或独立访问次数。轮转删除的日志不在样本中。', '',
             '## 分析结果', '', '| 目标 | 直连 / 代理事件 | 判断 | IP 国家 | 证据 |', '|---|---:|---|---|---|']
    for row in report['results']:
        evidence = ('国内库：' + row['direct_match']) if row['direct_match'] else row['reason']
        lines.append('| ' + ' | '.join(map(cell, [row['host'], str(row['actions'].get('DIRECT', 0)) + ' / ' + str(row['actions'].get('PROXY', 0)), labels[row['state']], ', '.join(row['countries_observed']) or '未知', evidence])) + ' |')
    lines += ['', '## 待审批规则', '', '仅对“待确认直连”生成精确 DOMAIN 候选，不扩大为整个主域名；DNS 配套建议与路由一起审批。', '', '```json', json.dumps(report['proposal'], ensure_ascii=False, indent=2), '```', '',
              '完整的 DNS、CNAME、IP、ASN、命中规则和查询失败记录见同目录 report.json。查不到或有冲突的目标保持原状。', '']
    return '\n'.join(lines)


def analyze(snapshot, output, max_hosts=200, max_ips=80):
    if pathlib.Path(snapshot).stat().st_size > MAX_INPUT:
        raise ValueError('Snapshot too large')
    value = json.loads(pathlib.Path(snapshot).read_bytes())
    if value.get('schema') != VERSION:
        raise ValueError('Invalid snapshot')
    grouped = {}
    observations = value.get('observations', [])
    if not isinstance(observations, list) or len(observations) > 20000:
        raise ValueError('Too many observations')
    for row in observations:
        name = host(row['host'])
        if (':' in name or re.fullmatch(r'[0-9.]+', name)) and not public_ip(name):
            continue
        action, count, rule = row['action'], row['count'], row['rule']
        if action not in ('DIRECT', 'PROXY', 'REJECT') or type(count) is not int or not 0 < count < 10000000 or not (rule == 'Other' or RULE.fullmatch(rule)):
            raise ValueError('Invalid observation')
        item = grouped.setdefault(name, {'host': name, 'actions': {}, 'rules': {}})
        item['actions'][action] = item['actions'].get(action, 0) + count
        item['rules'][rule] = item['rules'].get(rule, 0) + count
    ordered = sorted(grouped.values(), key=lambda x: (-x['actions'].get('PROXY', 0), x['host']))
    selected = ordered[:max_hosts]
    sets, sources = load_rules()
    print(json.dumps({'stage': 'dns', 'hosts': len(selected), 'rules': sources['status']}), flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers:
        dns_values = list(workers.map(resolve, [r['host'] for r in selected]))
    # Round-robin across hosts so a large CDN does not consume the entire lookup budget.
    per_host = [sorted({a for resolver in dns.values() for a in resolver['addresses']}, key=lambda a: (':' in a, a)) for dns in dns_values]
    addresses = list(dict.fromkeys(a for i in range(max(map(len, per_host), default=0)) for group in per_host for a in group[i:i+1]))
    print(json.dumps({'stage': 'ip_lookup', 'unique_ips': len(addresses), 'lookup_limit': max_ips}), flush=True)
    # Keep repeated runs bounded; successful IP data expires after 24 hours.
    out = pathlib.Path(output)
    try:
        cache = json.loads((out / 'ip-cache.json').read_text())
    except (OSError, ValueError):
        cache = {}
    fresh = {}
    for address in addresses:
        entry = cache.get(address, {})
        try:
            age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(entry['queried_at'])).total_seconds()
            if entry.get('status') == 'ok' and 0 <= age < 86400:
                fresh[address] = entry
        except (KeyError, TypeError, ValueError):
            pass
    for address in [a for a in addresses if a not in fresh][:max_ips]:
        fresh[address] = lookup_ip(address)
    atomic(out / 'ip-cache.json', json.dumps(fresh))
    results = []
    for observation, dns in zip(selected, dns_values):
        ips = sorted({a for resolver in dns.values() for a in resolver['addresses']})
        evidence = [fresh.get(a, {'ip': a, 'status': 'not_queried', 'reason': 'budget_limit'}) for a in ips]
        results.append(classify(observation, sets, dns, evidence))
    candidates = [r['host'] for r in results if r['state'] == 'review_direct' and not public_ip(r['host'])]
    proposal = {'status': 'awaiting_user_approval', 'rules': ['DOMAIN,' + h + ',DIRECT' for h in candidates],
                'nameserver_policy': {h: ['https://223.5.5.5/dns-query#DIRECT', 'https://1.12.12.12/dns-query#DIRECT'] for h in candidates}}
    report = {'schema': VERSION, 'generated_at': now(), 'execution_host': socket.gethostname(), 'coverage': value['coverage'],
              'snapshot_sha256': hashlib.sha256(pathlib.Path(snapshot).read_bytes()).hexdigest(), 'rule_sources': sources,
              'total_hosts': len(ordered), 'analyzed_hosts': len(results), 'deferred_hosts': [r['host'] for r in ordered[max_hosts:]],
              'results': results, 'proposal': proposal, 'config_modified': False}
    report['ip_lookup_coverage'] = {'unique_ips': len(addresses), 'queried_or_cached': len(fresh), 'not_queried': len(addresses) - len(fresh)}
    summary = {'states': dict(collections.Counter(r['state'] for r in results)), 'hosts': len(results), 'proposal_count': len(candidates)}
    fingerprint = hashlib.sha256(json.dumps([(r['host'], r['state'], r['direct_match'], r['proxy_matches']) for r in sorted(results, key=lambda x: x['host'])], sort_keys=True).encode()).hexdigest()
    try:
        previous = json.loads((out / 'summary.json').read_text())
    except (OSError, ValueError):
        previous = {}
    summary.update(fingerprint=fingerprint, meaningful_change=previous.get('fingerprint') != fingerprint, generated_at=report['generated_at'])
    atomic(out / 'report.json', json.dumps(report, ensure_ascii=False, indent=2))
    atomic(out / 'report.md', markdown(report))
    atomic(out / 'proposal.json', json.dumps(proposal, ensure_ascii=False, indent=2))
    atomic(out / 'summary.json', json.dumps(summary, ensure_ascii=False, indent=2))
    print(json.dumps(summary, ensure_ascii=False), flush=True)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    c = commands.add_parser('collect');c.add_argument('--logs', required=True);c.add_argument('--output', required=True)
    a = commands.add_parser('analyze');a.add_argument('--input', required=True);a.add_argument('--output', required=True)
    a.add_argument('--max-hosts', type=int, default=200);a.add_argument('--max-ips', type=int, default=80)
    args = parser.parse_args()
    if args.command == 'collect':
        result = collect(args.logs);atomic(args.output, json.dumps(result, ensure_ascii=False, indent=2))
        print(json.dumps(result['coverage']))
    else:
        if not 1 <= args.max_hosts <= 500 or not 1 <= args.max_ips <= 500:
            parser.error('Invalid analysis budget')
        analyze(args.input, args.output, args.max_hosts, args.max_ips)

if __name__ == '__main__':
    main()
