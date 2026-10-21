"""Paired subscription contracts for categorized routing and a unified AI group."""
import base64
import json
import re
import subprocess
from urllib.parse import unquote, urlsplit

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


@pytest.mark.parametrize("fixture", [POLICY], indirect=True)
def test_both_formats_share_ai_categories_nodes_and_priority(fixture):
    clash, shadow, links = exports(fixture)
    groups = {g["name"]: g for g in clash["proxy-groups"]}
    nodes = {p["name"] for p in clash["proxies"]}
    validate_graph({k: v["proxies"] for k, v in groups.items()}, nodes)
    assert groups["PROXY"]["proxies"][:2] == ["故障转移", "自动选择"]
    assert "IPRoyal ISP 28 · 8.8.4.4" not in groups["PROXY"]["proxies"]
    assert groups["AI"]["proxies"][0] == "IPRoyal ISP 28 · 8.8.4.4"
    assert groups["IPRoyal ISP 28 · 8.8.4.4"]["proxies"][0].endswith(" · HTTPS")
    for name in ("故障转移", "自动选择"):
        assert groups[name]["proxies"] == ["REALITY", "HTTPS", "VMess TLS", "Hysteria 2"]
        assert groups[name]["interval"] == 120
    assert groups["STUN"]["proxies"] == groups["故障转移"]["proxies"]
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
    assert "DOMAIN-SUFFIX,claude.ai,XCLI-AI" in shadow
    ai = clash["rule-providers"]["category-AI"]["payload"]
    for host in ("claude.ai", "chatgpt.com", "gemini.google.com", "githubcopilot.com", "perplexity.ai", "grok.com"):
        assert "DOMAIN-SUFFIX," + host in ai
        assert clash["dns"]["nameserver-policy"]["+." + host][0].endswith("#AI")
        assert "DOMAIN-SUFFIX," + host + ",XCLI-AI" in shadow
    assert "DOMAIN-SUFFIX,google.com" not in ai
    assert "DOMAIN-SUFFIX,github.com" not in ai
    assert "DOMAIN-SUFFIX,deepseek.com" not in ai
    assert shadow.index("AND,((DOMAIN-SUFFIX,claude.ai),(PROTOCOL,UDP)),REJECT") < shadow.index("DOMAIN-SUFFIX,claude.ai,XCLI-AI")
    assert "NETWORK,UDP" not in shadow and "3478/443" not in shadow
    assert "OR,((DST-PORT,3478),(DST-PORT,443))" in shadow
    assert "IP-CIDR,2001:b28:f23d::/48,XCLI-Telegram,no-resolve" in shadow
    assert "FINAL,XCLI-其他流量" in shadow and "FINAL,PROXY" not in shadow
    assert "[Host]\nlocalhost = 127.0.0.1" in shadow and "[MITM]\nenable = false" in shadow
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
            target = "DIRECT" if name in ("Apple", "哔哩哔哩") else "XCLI-" + name
            expected = f"{kind},{value},{target}" + ("," + ",".join(flags) if flags else "")
            assert expected in shadow


@pytest.mark.parametrize("fixture", [POLICY], indirect=True)
def test_opt_in_is_scoped_and_both_formats_follow_revocation(fixture):
    c = fixture["client"]; c.login()
    other = c.json("/api/users", "POST", {"name": "unaffected"})["id"]
    links = c.json("/api/users/" + other + "/links")
    path = urlsplit(links["subscription"]).path
    plain = yaml.safe_load(c.call(path + "/clash.yaml")[2])
    assert not any(g["name"] == "AI" for g in plain["proxy-groups"])
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
    assert groups["AI"]["proxies"][0] == "REJECT"
    assert "XCLI-AI = select,REJECT," in shadow
    assert groups["故障转移"]["proxies"] == ["REALITY", "HTTPS", "VMess TLS"]
    assert "住宅节点" not in groups


@pytest.mark.parametrize("fixture", [{**POLICY, "shadowrocket_base_profiles": {"__USER_ID__":
    BASE.replace("FINAL,PROXY", "DOMAIN-SUFFIX,claude.ai,PROXY\nDOMAIN-SUFFIX,bilibili.com,DIRECT\n"
        "DOMAIN-SUFFIX,apple.com,PROXY\nIP-CIDR,91.108.4.0/22,PROXY,no-resolve\nFINAL,PROXY # preserve comment").replace("\n", "\r\n")}}],
    indirect=True)
def test_existing_generic_duplicates_follow_the_same_category(fixture):
    _, shadow, _ = exports(fixture)
    assert "DOMAIN-SUFFIX,claude.ai,PROXY" not in shadow
    assert shadow.count("DOMAIN-SUFFIX,claude.ai,XCLI-AI") == 2
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
