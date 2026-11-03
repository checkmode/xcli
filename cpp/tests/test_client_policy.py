"""Paired subscription contracts for categorized routing and a unified AI group."""
import base64
import json
import re
import subprocess
from urllib.parse import quote, unquote, urlsplit

import pytest
import yaml
from test_http import Client, fixture, BINARY
from test_clash import SERVICE_SETTINGS
from test_shadowrocket_services import BASE

POLICY = {
    "hysteria2_port": 443, "vmess_ws_path": "/connect/test/vmess", "vmess_port": 10081,
    "residential_exits": SERVICE_SETTINGS["residential_exits"],
    "client_policies": {"__USER_ID__": {"ai_outbound": "residential-28"}},
    "shadowrocket_base_profiles": {"__USER_ID__": BASE},
}


@pytest.mark.parametrize('fixture', [{**POLICY, 'shadowrocket_base_profiles': {'__USER_ID__': BASE.replace(
    'FINAL,PROXY', 'DOMAIN-KEYWORD,google,PROXY\nDOMAIN-KEYWORD,unrelated,PROXY\nFINAL,PROXY')}}], indirect=True)
def test_legacy_google_keyword_uses_independent_group(fixture):
    _, shadow, _ = exports(fixture)
    assert 'DOMAIN-KEYWORD,google,XCLI-独立 · Google' in shadow
    assert 'DOMAIN-KEYWORD,google,XCLI-PROXY' not in shadow
    assert 'DOMAIN-KEYWORD,unrelated,XCLI-PROXY' in shadow
    assert shadow.index('DOMAIN-SUFFIX,gemini.google.com,XCLI-独立 · AI') < shadow.index('DOMAIN-KEYWORD,google,XCLI-独立 · Google')
    assert shadow.index('DOMAIN-SUFFIX,youtube.com,XCLI-独立 · YouTube') < shadow.index('DOMAIN-KEYWORD,google,XCLI-独立 · Google')


@pytest.mark.parametrize('fixture', [{**POLICY, 'shadowrocket_base_profiles': {'__USER_ID__': BASE.replace(
    'FINAL,PROXY', 'DOMAIN-KEYWORD,google,DIRECT\nDOMAIN-KEYWORD,google,REJECT\nFINAL,PROXY')}}], indirect=True)
def test_legacy_google_direct_and_reject_are_preserved(fixture):
    _, shadow, _ = exports(fixture)
    assert 'DOMAIN-KEYWORD,google,DIRECT' in shadow
    assert 'DOMAIN-KEYWORD,google,REJECT' in shadow
    assert 'DOMAIN-KEYWORD,google,XCLI-独立 · Google' not in shadow


DNS_BASE = BASE.replace('dns-server = system', '''dns-server = system
dns-server = 8.8.8.8
fallback-dns-server = system
direct-dns-server = system
proxy-dns-server = system
dns-fallback-system = true
dns-direct-system = true
dns-direct-fallback-proxy = true
always-ip-address = true
use-local-host-item-for-proxy = true
hijack-dns = 8.8.8.8:53''').replace('localhost = 127.0.0.1', 'localhost = 127.0.0.1\ntestserver = 192.0.2.99')


@pytest.mark.parametrize('fixture', [
    {**POLICY, 'shadowrocket_base_profiles': {'__USER_ID__': base}}
    for base in (DNS_BASE, DNS_BASE.replace('\n', '\r\n'),
                 DNS_BASE.replace('[Host]\nlocalhost = 127.0.0.1\ntestserver = 192.0.2.99\n', ''))
], indirect=True)
def test_integrated_dns_overrides_old_resolvers_without_changing_proxy_routes(fixture):
    clash, shadow, links = exports(fixture)
    section = ''; values = {}; keys = []
    for line in shadow.splitlines():
        if line.startswith('['): section = line
        elif section == '[General]' and '=' in line and not line.startswith('#'):
            key, value = (x.strip() for x in line.split('=', 1))
            keys.append(key); values[key] = value
    assert len(keys) == len(set(keys))
    domestic = 'https://223.5.5.5/dns-query,https://1.12.12.12/dns-query'
    assert values['direct-dns-server'] == values['proxy-dns-server'] == domestic
    label = next(unquote(urlsplit(link).fragment) for link in links
                 if link.startswith('vless://') and unquote(urlsplit(link).fragment).endswith(' · HTTPS')
                 and '固定' not in unquote(urlsplit(link).fragment))
    # The fallback binds an actual imported node, not an unverified DNS group alias.
    assert values['dns-server'] == 'https://1.1.1.1/dns-query#proxy=' + quote(label, safe='')
    assert values['fallback-dns-server'] == 'https://1.0.0.1/dns-query#proxy=' + quote(label, safe='')
    for key in ('dns-fallback-system', 'dns-direct-system', 'dns-direct-fallback-proxy',
                'always-ip-address', 'use-local-host-item-for-proxy'):
        assert values[key] == 'false'
    assert values['hijack-dns'] == ':53'
    assert values['ipv6'] == 'true'
    assert values['udp-policy-not-supported-behaviour'] == 'REJECT'
    assert shadow.count('testserver = 203.0.113.2') == 1
    assert 'testserver = 192.0.2.99' not in shadow
    assert shadow.count('[Host]') == 1
    assert 'DOMAIN-SUFFIX,local.example,DIRECT' in shadow
    assert 'DOMAIN-SUFFIX,claude.ai,XCLI-独立 · AI' in shadow
    assert 'DOMAIN-SUFFIX,youtube.com,XCLI-独立 · YouTube' in shadow
    assert '[MITM]\nenable = false' in shadow.replace('\r\n', '\n')
    setup = Client(fixture['client'].port).json('/s/' + fixture['token'] + '/shadowrocket.json')
    assert setup['dns_routing'] == 'integrated'


def exports(fixture):
    path = "/s/" + fixture["token"]
    result = []
    for suffix in ("/clash.yaml", "/shadowrocket.conf", ""):
        status, _, content = Client(fixture["client"].port).call(path + suffix)
        assert status == 200
        result.append(content)
    return yaml.safe_load(result[0]), result[1].decode(), base64.b64decode(result[2]).decode().splitlines()


def validate_graph(groups, nodes):
    def visit(name, path):
        assert name not in path, (name, path)
        assert name in groups or name in nodes or name in {"DIRECT", "REJECT"}
        for target in groups.get(name, []):
            visit(target, path + [name])
    for name in groups:
        visit(name, [])


@pytest.mark.parametrize('fixture', [POLICY], indirect=True)
def test_google_group_preserves_ai_youtube_and_residential_choices(fixture):
    clash, shadow, _ = exports(fixture)
    groups = {g['name']: g for g in clash['proxy-groups']}
    google = groups['独立 · Google']['proxies']
    assert google[:2] == ['故障转移', '自动选择']
    assert '住宅分组 · 新加坡' in google
    assert all(node in google for node in ('REALITY', 'HTTPS', 'Hysteria 2'))
    payload = clash['rule-providers']['category-Google']['payload']
    assert 'DOMAIN-SUFFIX,google.com' in payload
    assert 'DOMAIN-SUFFIX,googleapis.com' in payload
    assert 'DOMAIN-SUFFIX,google.com.sg' in payload
    rules = clash['rules']
    google_rule = rules.index('RULE-SET,category-Google,独立 · Google')
    assert rules.index('RULE-SET,category-AI,独立 · AI') < google_rule
    assert rules.index('RULE-SET,category-YouTube,独立 · YouTube') < google_rule
    assert rules[google_rule + 1] == 'RULE-SET,category-Google,REJECT'
    dns = clash['dns']['nameserver-policy']
    assert dns['+.google.com'][0].endswith('#独立 · Google')
    assert dns['+.gemini.google.com'][0].endswith('#独立 · AI')
    assert 'XCLI-独立 · Google = select,' in shadow
    assert 'DOMAIN-SUFFIX,google.com,XCLI-独立 · Google' in shadow
    assert shadow.index('DOMAIN-SUFFIX,gemini.google.com,XCLI-独立 · AI') < shadow.index('DOMAIN-SUFFIX,google.com,XCLI-独立 · Google')


@pytest.mark.parametrize("fixture", [POLICY], indirect=True)
def test_both_formats_share_ai_categories_nodes_and_priority(fixture):
    clash, shadow, links = exports(fixture)
    groups = {g["name"]: g for g in clash["proxy-groups"]}
    nodes = {p["name"] for p in clash["proxies"]}
    validate_graph({k: v["proxies"] for k, v in groups.items()}, nodes)
    assert groups['EaseLian']['proxies'][:2] == ['PROXY', 'DIRECT']
    assert 'DOMAIN-SUFFIX,easelian.com' in clash['rule-providers']['category-EaseLian']['payload']
    assert 'RULE-SET,category-EaseLian,EaseLian' in clash['rules']
    assert clash['dns']['nameserver-policy']['+.easelian.com'] == [
        'https://223.5.5.5/dns-query#EaseLian', 'https://1.12.12.12/dns-query#EaseLian']
    assert clash['dns']['direct-nameserver'] == [
        'https://223.5.5.5/dns-query#DIRECT', 'https://1.12.12.12/dns-query#DIRECT']
    assert clash['dns']['direct-nameserver-follow-policy'] is False
    assert clash['dns']['nameserver'] == [
        'https://1.1.1.1/dns-query#PROXY', 'https://1.0.0.1/dns-query#PROXY']
    assert 'DOMAIN-SUFFIX,easelian.com,XCLI-EaseLian' in shadow
    assert 'XCLI-EaseLian = select,XCLI-PROXY,DIRECT,' in shadow
    assert 'direct-dns-server = https://223.5.5.5/dns-query,https://1.12.12.12/dns-query' in shadow
    assert 'dns-direct-fallback-proxy = false' in shadow
    assert 'use-local-host-item-for-proxy = false' in shadow
    assert groups["PROXY"]["proxies"][:2] == ["故障转移", "自动选择"]
    assert "IPRoyal ISP 28 · 8.8.4.4" not in groups["PROXY"]["proxies"]
    assert groups["独立 · AI"]["proxies"][0] == "IPRoyal ISP 28 · 8.8.4.4"
    assert groups["IPRoyal ISP 28 · 8.8.4.4"]["proxies"][0].endswith(" · HTTPS")
    for name in ("故障转移", "自动选择"):
        assert groups[name]["proxies"] == ["REALITY", "HTTPS", "VMess TLS", "Hysteria 2"]
        assert groups[name]["interval"] == 120
    assert groups["独立 · STUN"]["proxies"] == groups["故障转移"]["proxies"]
    assert "RULE-SET,stun-endpoints,独立 · STUN" in clash["rules"]
    assert all(server.endswith("#独立 · STUN") for server in clash["dns"]["nameserver-policy"]["stun.l.google.com"])
    for name in ("Apple", "哔哩哔哩"):
        assert name not in groups
        assert "XCLI-" + name not in shadow
        assert "RULE-SET,category-" + name + ",DIRECT" in clash["rules"]
        for payload in clash["rule-providers"]["category-" + name]["payload"]:
            kind, domain = payload.split(",")
            key = "+." + domain if kind == "DOMAIN-SUFFIX" else domain
            assert all(server.endswith("#DIRECT") for server in clash["dns"]["nameserver-policy"][key])
    assert clash["rules"][-1] == "MATCH,其他流量"
    assert "CLAUDE" not in groups and "GITHUB" not in groups
    assert "XCLI-CLAUDE" not in shadow and "XCLI-GITHUB" not in shadow
    assert "DOMAIN-SUFFIX,github.com," not in shadow
    assert "DOMAIN-SUFFIX,claude.ai,XCLI-独立 · AI" in shadow
    ai = clash["rule-providers"]["category-AI"]["payload"]
    for host in ("claude.ai", "chatgpt.com", "gemini.google.com", "githubcopilot.com", "perplexity.ai", "grok.com"):
        assert "DOMAIN-SUFFIX," + host in ai
        assert clash["dns"]["nameserver-policy"]["+." + host][0].endswith("#独立 · AI")
        assert "DOMAIN-SUFFIX," + host + ",XCLI-独立 · AI" in shadow
    assert "DOMAIN-SUFFIX,google.com" not in ai
    assert "DOMAIN-SUFFIX,github.com" not in ai
    assert "DOMAIN-SUFFIX,deepseek.com" not in ai
    assert shadow.index("AND,((DOMAIN-SUFFIX,claude.ai),(PROTOCOL,UDP)),REJECT") < shadow.index("DOMAIN-SUFFIX,claude.ai,XCLI-独立 · AI")
    assert "NETWORK,UDP" not in shadow and "3478/443" not in shadow
    assert "OR,((DST-PORT,3478),(DST-PORT,443))" in shadow
    assert "IP-CIDR,2001:b28:f23d::/48,XCLI-独立 · Telegram,no-resolve" in shadow
    assert "FINAL,XCLI-其他流量" in shadow and "FINAL,PROXY" not in shadow
    assert "localhost = 127.0.0.1" in shadow and "[MITM]\nenable = false" in shadow
    assert shadow.count("[Proxy Group]") == 1

    # Every generated Shadowrocket member resolves to a group or an actual
    # imported node name, including encoded usernames and VMess JSON labels.
    labels = set()
    for link in links:
        if link.startswith("vmess://"):
            labels.add(json.loads(base64.b64decode(link[8:]))["ps"])
        else:
            labels.add(unquote(urlsplit(link).fragment))
    shadow_groups = {}
    for line in shadow.splitlines():
        if line.startswith("XCLI-"):
            name, definition = line.split(" = ", 1)
            shadow_groups[name] = [x for x in definition.split(",")[1:] if "=" not in x]
    validate_graph(shadow_groups, labels)
    assert set(shadow_groups) == {"XCLI-" + name for name in groups}
    for name in ("AI", "Telegram", "YouTube", "Netflix", "国外媒体", "哔哩哔哩", "Apple"):
        for payload in clash["rule-providers"]["category-" + name]["payload"]:
            kind, value, *flags = payload.split(",")
            if kind == "IP-CIDR6":
                kind = "IP-CIDR"
            target = "DIRECT" if name in ("Apple", "哔哩哔哩") else "XCLI-独立 · " + name
            expected = f"{kind},{value},{target}" + ("," + ",".join(flags) if flags else "")
            assert expected in shadow


@pytest.mark.parametrize("fixture", [POLICY,
    {**POLICY, "client_policies": {"__USER_ID__": {"ai_outbound": "proxy"}}}], indirect=True)
def test_main_direct_option_cannot_redirect_independent_groups(fixture):
    clash, shadow, _ = exports(fixture)
    graphs = [{g["name"]: g["proxies"] for g in clash["proxy-groups"]}, {}]
    for line in shadow.splitlines():
        if line.startswith("XCLI-"):
            name, definition = line.split(" = ", 1)
            graphs[1][name] = [x for x in definition.split(",")[1:] if "=" not in x]
    for graph, prefix in zip(graphs, ("", "XCLI-")):
        main, direct, other = (prefix + x for x in ("PROXY", "直连", "其他流量"))
        assert direct in graph[main] and graph[direct] == ["DIRECT"]
        roots = [prefix + "独立 · " + name for name in ("AI", "Telegram", "YouTube", "Netflix", "国外媒体", "STUN")]

        def reachable(name):
            return {name}.union(*(reachable(child) for child in graph.get(name, [])))

        def resolve(name, selected):
            while name in graph:
                name = selected.get(name, graph[name][0])
            return name

        for name in roots:
            assert reachable(name).isdisjoint({main, direct, other, "DIRECT"})
            original = resolve(name, {})
            assert resolve(name, {main: direct}) == original
        assert resolve(other, {main: direct}) == "DIRECT"
        assert resolve(other, {}) != "DIRECT"
    assert not any(g["name"] in ("AI", "Telegram", "YouTube", "Netflix", "国外媒体", "STUN")
                   for g in clash["proxy-groups"])


@pytest.mark.parametrize("fixture", [POLICY], indirect=True)
def test_opt_in_is_scoped_and_both_formats_follow_revocation(fixture):
    c = fixture["client"]; c.login()
    other = c.json("/api/users", "POST", {"name": "unaffected"})["id"]
    links = c.json("/api/users/" + other + "/links")
    path = urlsplit(links["subscription"]).path
    plain = yaml.safe_load(c.call(path + "/clash.yaml")[2])
    assert not any(g["name"] == "独立 · AI" for g in plain["proxy-groups"])
    assert c.call(path + "/shadowrocket.conf")[0] == 404
    current = "/s/" + fixture["token"]
    c.json("/api/users/" + fixture["uid"] + "/rotate", "POST", {})
    for suffix in ("", "/clash.yaml", "/shadowrocket.conf"):
        assert c.call(current + suffix)[0] == 404
    new_path = urlsplit(c.json("/api/users/" + fixture["uid"] + "/links")["subscription"]).path
    c.json("/api/users/" + fixture["uid"], "PUT", {"name": "disabled", "enabled": False})
    for suffix in ("", "/clash.yaml", "/shadowrocket.conf"):
        assert c.call(new_path + suffix)[0] == 403


@pytest.mark.parametrize("fixture", [{**POLICY, "residential_exits": [], "hysteria2_port": 0}], indirect=True)
def test_missing_ai_exit_stays_rejected_and_optional_transports_are_omitted(fixture):
    clash, shadow, _ = exports(fixture)
    groups = {g["name"]: g for g in clash["proxy-groups"]}
    assert groups["独立 · AI"]["proxies"][0] == "REJECT"
    assert "XCLI-独立 · AI = select,REJECT," in shadow
    assert groups["故障转移"]["proxies"] == ["REALITY", "HTTPS", "VMess TLS"]
    assert "住宅节点" not in groups


@pytest.mark.parametrize("fixture", [{**POLICY, "shadowrocket_base_profiles": {"__USER_ID__":
    BASE.replace("FINAL,PROXY", "DOMAIN-SUFFIX,claude.ai,PROXY\nDOMAIN-SUFFIX,bilibili.com,DIRECT\n"
        "DOMAIN-SUFFIX,apple.com,PROXY\nIP-CIDR,91.108.4.0/22,PROXY,no-resolve\nFINAL,PROXY # preserve comment").replace("\n", "\r\n")}}],
    indirect=True)
def test_existing_generic_duplicates_follow_the_same_category(fixture):
    _, shadow, _ = exports(fixture)
    assert "DOMAIN-SUFFIX,claude.ai,PROXY" not in shadow
    assert shadow.count("DOMAIN-SUFFIX,claude.ai,XCLI-独立 · AI") == 2
    assert shadow.count("DOMAIN-SUFFIX,bilibili.com,DIRECT") == 2
    assert shadow.count("DOMAIN-SUFFIX,apple.com,DIRECT") == 2
    assert "DOMAIN-SUFFIX,apple.com,PROXY" not in shadow
    assert "XCLI-哔哩哔哩" not in shadow and "XCLI-Apple" not in shadow
    assert "IP-CIDR,91.108.4.0/22,PROXY" not in shadow
    assert "FINAL,XCLI-其他流量 # preserve comment\r\n" in shadow


def test_invalid_policy_requires_explicit_base_and_ai_merge(fixture):
    original = json.loads((fixture["tmp"] / "settings.json").read_text())
    for index, override in enumerate([
        {"client_policies": {fixture["uid"]: {"ai_outbound": "wrong"}}},
        {"client_policies": {fixture["uid"]: {"ai_outbound": "proxy"}}},
        {**POLICY, "clash_service_routes": SERVICE_SETTINGS["clash_service_routes"]},
    ]):
        override = json.loads(json.dumps(override).replace("__USER_ID__", fixture["uid"]))
        settings = fixture["tmp"] / f"bad-policy-{index}.json"
        settings.write_text(json.dumps({**original, **override}))
        result = subprocess.run([str(BINARY), "--state", str(fixture["state"]),
            "--settings", str(settings), "--offline", "--preflight"], capture_output=True, timeout=10)
        assert result.returncode != 0
