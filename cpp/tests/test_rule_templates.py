"""Published routing templates are isolated, validated and shared by both clients."""
from urllib.parse import urlsplit

import pytest
import yaml

from test_http import Client, PASSWORD, fixture
from test_client_policy import POLICY
from test_shadowrocket_services import BASE


def subscription(client, user_id):
    return urlsplit(client.json('/api/users/' + user_id + '/links')['subscription']).path


def clash(client, path):
    status, _, content = client.call(path + '/clash.yaml')
    assert status == 200
    return yaml.safe_load(content)


def group_names(config):
    return {item['name'] for item in config['proxy-groups']}


def test_custom_groups_are_published_with_rules_and_preserve_old_templates(fixture):
    c = fixture['client']; c.login(); path = '/s/' + fixture['token']
    initial = clash(c, path)
    spec = next(t['spec'] for t in c.json('/api/rule-templates')['templates'] if t['id'] == 'independent')
    spec['groups'] = [{'name': '工作服务', 'default': '故障转移'}]
    spec['rules'] = 'DOMAIN-SUFFIX,work.example,工作服务\n' + spec['rules']
    tid = c.json('/api/rule-templates', 'POST', {'name': 'with groups', 'spec': spec})['id']
    assert clash(c, path) == initial
    c.json('/api/rule-templates/' + tid + '/publish', 'POST', {'expected_revision': 1})
    c.json('/api/users/' + fixture['uid'] + '/rule-template', 'POST', {'template_id': tid})
    config = clash(c, path)
    group = next(g for g in config['proxy-groups'] if g['name'] == '工作服务')
    assert group['type'] == 'select' and group['proxies'][0] == '故障转移'
    assert 'PROXY' in group['proxies'] and 'DIRECT' in group['proxies']
    assert 'DOMAIN-SUFFIX,work.example,工作服务' in config['rules']
    assert 'DOMAIN-SUFFIX,work.example,REJECT' in config['rules']
    assert config['dns']['nameserver-policy']['+.work.example'][0].endswith('#工作服务')
    shadow = c.call(path + '/shadowrocket.conf')[2].decode()
    assert 'XCLI-工作服务 = select,' in shadow
    assert 'DOMAIN-SUFFIX,work.example,XCLI-工作服务' in shadow
    saved = next(t['spec'] for t in c.json('/api/rule-templates')['templates'] if t['id'] == tid)
    assert saved['groups'] == spec['groups']
    for invalid in ([{'name': 'PROXY', 'default': 'DIRECT'}],
                    [{'name': 'Bad,Name', 'default': 'DIRECT'}],
                    [{'name': 'Same', 'default': 'PROXY'}, {'name': 'Same', 'default': 'DIRECT'}]):
        c.json('/api/rule-templates/validate', 'POST', {'name': 'bad', 'spec': {**spec, 'groups': invalid}}, expected=422)
    c.json('/api/rule-templates/validate', 'POST', {'name': 'bad', 'spec': {**spec, 'groups': []}}, expected=422)


def test_standard_template_group_without_rules_is_exported_for_shadowrocket(fixture):
    c = fixture['client']; c.login(); path = '/s/' + fixture['token']
    spec = next(t['spec'] for t in c.json('/api/rule-templates')['templates'] if t['id'] == 'standard')
    spec['groups'] = [{'name': 'Office', 'default': 'DIRECT'}]
    tid = c.json('/api/rule-templates', 'POST', {'name': 'standard group', 'spec': spec})['id']
    c.json('/api/rule-templates/' + tid + '/publish', 'POST', {'expected_revision': 1})
    c.json('/api/users/' + fixture['uid'] + '/rule-template', 'POST', {'template_id': tid})
    group = next(g for g in clash(c, path)['proxy-groups'] if g['name'] == 'Office')
    assert group['proxies'][0] == 'DIRECT' and 'PROXY' in group['proxies']
    assert 'XCLI-Office = select,DIRECT,' in c.call(path + '/shadowrocket.conf')[2].decode()
    bad = {**spec, 'groups': [{'name': 'Office', 'default': '故障转移'}]}
    c.json('/api/rule-templates/validate', 'POST', {'name': 'bad default', 'spec': bad}, expected=422)


def test_google_group_respects_published_custom_rules(fixture):
    c = fixture['client']; c.login()
    path = '/s/' + fixture['token']
    original = clash(c, path)
    assert '独立 · Google' not in group_names(original)
    template = next(t['spec'] for t in c.json('/api/rule-templates')['templates'] if t['id'] == 'independent')
    template['rules'] = ('DOMAIN,office.google.com,DIRECT\n'
                         'DOMAIN-SUFFIX,gemini.google.com,独立 · AI\n'
                         'DOMAIN,custom.example,独立 · Google\n')
    tid = c.json('/api/rule-templates', 'POST', {'name': 'google override', 'spec': template})['id']
    c.json('/api/rule-templates/' + tid + '/publish', 'POST', {'expected_revision': 1})
    c.json('/api/users/' + fixture['uid'] + '/rule-template', 'POST', {'template_id': tid})
    config = clash(c, path)
    assert '独立 · Google' in group_names(config)
    rules = config['rules']
    default = rules.index('RULE-SET,category-Google,独立 · Google')
    assert rules.index('DOMAIN,office.google.com,DIRECT') < default
    assert rules.index('DOMAIN-SUFFIX,gemini.google.com,独立 · AI') < default
    assert rules.index('DOMAIN,custom.example,独立 · Google') < default
    assert config['dns']['nameserver-policy']['office.google.com'][0].endswith('#DIRECT')
    assert config['dns']['nameserver-policy']['+.gemini.google.com'][0].endswith('#独立 · AI')


def test_oracle_cloud_system_group_precedes_template_and_uses_direct_dns(fixture):
    c = fixture['client']; c.login()
    path = '/s/' + fixture['token']
    initial = clash(c, path)
    generic_before = c.call(path)[2]

    def verify(config):
        groups = {group['name']: group for group in config['proxy-groups']}
        assert groups['oracle-cloud'] == {'name': 'oracle-cloud', 'type': 'select', 'proxies': ['DIRECT']}
        provider = config['rule-providers']['xcli-oracle-cloud']
        assert provider['type'] == 'inline' and provider['behavior'] == 'classical'
        for entry in ('DOMAIN-SUFFIX,oracle.com', 'DOMAIN-SUFFIX,oraclecloud.com',
                      'DOMAIN-SUFFIX,oraclecloudapps.com', 'DOMAIN-SUFFIX,oraclecloud.net',
                      'DOMAIN-SUFFIX,oraclegovcloud.com', 'DOMAIN-SUFFIX,oracleinfinity.io',
                      'DOMAIN-SUFFIX,oracleimg.com', 'DOMAIN-SUFFIX,ocir.io',
                      'DOMAIN,oracle.112.2o7.net', 'DOMAIN,consent.trustarc.com'):
            assert entry in provider['payload']
        rules = config['rules']
        assert rules.index('DOMAIN-SUFFIX,todesk.com,DIRECT') < rules.index('RULE-SET,xcli-oracle-cloud,oracle-cloud')
        assert rules.index('RULE-SET,xcli-oracle-cloud,oracle-cloud') < rules.index('GEOSITE,private,DIRECT')
        dns = config['dns']['nameserver-policy']
        assert next(iter(dns)) == 'rule-set:xcli-oracle-cloud'
        assert all(server.endswith('#DIRECT') for server in dns['rule-set:xcli-oracle-cloud'])

    verify(initial)
    spec = {'base': 'standard', 'ai_outbound': 'proxy',
            'rules': 'DOMAIN,cloud.oracle.com,PROXY\nDOMAIN-SUFFIX,example.org,PROXY\n'}
    tid = c.json('/api/rule-templates', 'POST', {'name': 'custom policy', 'spec': spec})['id']
    c.json('/api/rule-templates/' + tid + '/publish', 'POST', {'expected_revision': 1})
    c.json('/api/users/' + fixture['uid'] + '/rule-template', 'POST', {'template_id': tid})
    managed = clash(c, path); verify(managed)
    assert managed['rules'].index('RULE-SET,xcli-oracle-cloud,oracle-cloud') < managed['rules'].index('DOMAIN,cloud.oracle.com,PROXY')
    assert c.call(path)[2] == generic_before


@pytest.mark.parametrize('fixture', [POLICY], indirect=True)
def test_oracle_cloud_group_in_categorized_shadowrocket(fixture):
    c = fixture['client']; c.login()
    path = '/s/' + fixture['token']
    profile = c.call(path + '/shadowrocket.conf')[2].decode()
    assert 'XCLI-oracle-cloud = select,DIRECT' in profile
    assert 'DOMAIN-SUFFIX,oraclecloud.com,XCLI-oracle-cloud' in profile
    assert 'DOMAIN,consent.trustarc.com,XCLI-oracle-cloud' in profile
    assert 'DOMAIN-SUFFIX,trustarc.com,XCLI-oracle-cloud' not in profile


@pytest.mark.parametrize('fixture', [POLICY], indirect=True)
def test_drafts_publish_assignment_and_paired_subscriptions(fixture):
    c = fixture['client']; c.login()
    existing_path = '/s/' + fixture['token']
    old_user = clash(c, existing_path)
    other_id = c.json('/api/users', 'POST', {'name': 'other'})['id']
    other_path = subscription(c, other_id)
    generic_before = c.call(other_path)[2]
    other_before = clash(c, other_path)
    assert '独立 · AI' in group_names(old_user)
    assert '独立 · AI' not in group_names(other_before)

    catalog = c.json('/api/rule-templates')
    independent = next(t['spec'] for t in catalog['templates'] if t['id'] == 'independent')
    assert 'DOMAIN-SUFFIX,claude.ai,独立 · AI' in independent['rules']
    created = c.json('/api/rule-templates', 'POST', {'name': 'custom', 'spec': independent})
    tid = created['id']
    c.json('/api/users/' + other_id + '/rule-template', 'POST', {'template_id': tid}, expected=409)
    assert clash(c, other_path) == other_before
    assert clash(c, existing_path) == old_user

    c.json('/api/rule-templates/' + tid + '/publish', 'POST', {'expected_revision': 1})
    assert clash(c, other_path) == other_before
    c.json('/api/users/' + other_id + '/rule-template', 'POST', {'template_id': tid})
    initial = clash(c, other_path)
    assert '独立 · AI' in group_names(initial)
    assert '独立 · YouTube' in group_names(initial)
    assert c.json(other_path + '/shadowrocket.json')['dns_routing'] == 'integrated'
    shadow = c.call(other_path + '/shadowrocket.conf')
    assert shadow[0] == 200 and b'include = default.conf' in shadow[2]
    assert clash(c, existing_path) == old_user
    assert c.call(other_path)[2] == generic_before

    edited = dict(independent)
    edited['rules'] = edited['rules'].replace('DOMAIN-SUFFIX,claude.ai,独立 · AI\n',
                                               'DOMAIN-SUFFIX,claude.ai,DIRECT\n')
    edited['rules'] += 'DOMAIN-SUFFIX,example.org,独立 · AI\n'
    result = c.json('/api/rule-templates/' + tid, 'PUT',
                    {'name': 'custom', 'spec': edited, 'expected_revision': 1})
    assert result['revision'] == 2
    assert clash(c, other_path) == initial
    c.json('/api/rule-templates/' + tid + '/publish', 'POST', {'expected_revision': 1}, expected=409)
    published = c.json('/api/rule-templates/' + tid + '/publish', 'POST', {'expected_revision': 2})
    assert published['affected_users'] == 1
    updated = clash(c, other_path); rules = updated['rules']
    assert 'DOMAIN-SUFFIX,claude.ai,DIRECT' in rules
    assert 'DOMAIN-SUFFIX,example.org,独立 · AI' in rules
    assert 'AND,((DOMAIN-SUFFIX,example.org),(NETWORK,UDP)),REJECT' in rules
    assert 'DOMAIN-SUFFIX,example.org,REJECT' in rules
    assert updated['dns']['nameserver-policy']['+.claude.ai'][0].endswith('#DIRECT')
    assert rules.index('IP-CIDR,10.0.0.0/8,DIRECT,no-resolve') < rules.index('DOMAIN-SUFFIX,claude.ai,DIRECT')
    mobile = c.call(other_path + '/shadowrocket.conf')[2].decode()
    assert 'DOMAIN-SUFFIX,claude.ai,DIRECT' in mobile
    assert 'DOMAIN-SUFFIX,example.org,XCLI-独立 · AI' in mobile
    assert 'PROTOCOL,UDP' in mobile
    assert clash(c, existing_path) == old_user

    c.json('/api/users/' + other_id + '/rule-template', 'POST', {'template_id': 'legacy'})
    assert clash(c, other_path) == other_before


@pytest.mark.parametrize('fixture', [{
    **POLICY,
    'shadowrocket_base_profiles': {'__USER_ID__': BASE.replace('FINAL,PROXY',
        'DOMAIN-SUFFIX,claude.ai,PROXY\nFINAL,PROXY')},
}], indirect=True)
def test_removed_classification_is_removed_from_preserved_mobile_base(fixture):
    c = fixture['client']; c.login()
    spec = next(t['spec'] for t in c.json('/api/rule-templates')['templates'] if t['id'] == 'independent')
    spec['rules'] = spec['rules'].replace('DOMAIN-SUFFIX,claude.ai,独立 · AI\n', '')
    tid = c.json('/api/rule-templates', 'POST', {'name': 'edited', 'spec': spec})['id']
    c.json('/api/rule-templates/' + tid + '/publish', 'POST', {'expected_revision': 1})
    c.json('/api/users/' + fixture['uid'] + '/rule-template', 'POST', {'template_id': tid})
    path = '/s/' + fixture['token']
    assert not any('claude.ai' in r for r in clash(c, path)['rules'])
    mobile = c.call(path + '/shadowrocket.conf')[2].decode()
    assert 'DOMAIN-SUFFIX,claude.ai,' not in mobile
    assert 'DOMAIN-SUFFIX,local.example,DIRECT' in mobile


def test_standard_template_custom_rules_export_to_both_clients(fixture):
    c = fixture['client']; c.login()
    spec = next(t['spec'] for t in c.json('/api/rule-templates')['templates'] if t['id'] == 'standard')
    spec['rules'] = 'DOMAIN-SUFFIX,example.org,PROXY\nIP-CIDR6,2001:db8::/32,STUN\n'
    tid = c.json('/api/rule-templates', 'POST', {'name': 'standard custom', 'spec': spec})['id']
    c.json('/api/rule-templates/' + tid + '/publish', 'POST', {'expected_revision': 1})
    c.json('/api/users/' + fixture['uid'] + '/rule-template', 'POST', {'template_id': tid})
    path = '/s/' + fixture['token']
    config = clash(c, path)
    assert 'DOMAIN-SUFFIX,example.org,PROXY' in config['rules']
    assert 'IP-CIDR6,2001:db8::/32,STUN,no-resolve' in config['rules']
    mobile = c.call(path + '/shadowrocket.conf')[2].decode()
    assert 'DOMAIN-SUFFIX,example.org,XCLI-PROXY' in mobile
    assert 'IP-CIDR,2001:db8::/32,XCLI-STUN,no-resolve' in mobile
    assert 'FINAL,XCLI-PROXY' in mobile


def test_keyword_geoip_port_and_resolution_export_to_both_clients(fixture):
    c = fixture['client']; c.login()
    spec = next(t['spec'] for t in c.json('/api/rule-templates')['templates'] if t['id'] == 'standard')
    spec['rules'] = ('# keep this comment\n'
                     'DOMAIN,media.example.com,DIRECT\n'
                     'DOMAIN-KEYWORD,media,PROXY\n'
                     'IP-CIDR,198.51.100.0/24,DIRECT,resolve\n'
                     'IP-CIDR6,2001:db8::/32,PROXY,no-resolve\n'
                     'GEOIP,US,PROXY,no-resolve\n'
                     'DST-PORT,8443,REJECT\n')
    tid = c.json('/api/rule-templates', 'POST', {'name': 'new types', 'spec': spec})['id']
    c.json('/api/rule-templates/' + tid + '/publish', 'POST', {'expected_revision': 1})
    c.json('/api/users/' + fixture['uid'] + '/rule-template', 'POST', {'template_id': tid})
    path = '/s/' + fixture['token']; config = clash(c, path); rules = config['rules']
    assert rules.index('DOMAIN,media.example.com,DIRECT') < rules.index('DOMAIN-KEYWORD,media,PROXY')
    assert 'IP-CIDR,198.51.100.0/24,DIRECT' in rules
    assert 'IP-CIDR6,2001:db8::/32,PROXY,no-resolve' in rules
    assert 'GEOIP,US,PROXY,no-resolve' in rules
    assert 'DST-PORT,8443,REJECT' in rules
    dns = config['dns']['nameserver-policy']; keys = list(dns)
    assert keys.index('+.todesk.com') < keys.index('rule-set:xcli-dns-1')
    assert keys.index('rule-set:xcli-dns-1') < keys.index('rule-set:xcli-dns-2') < keys.index('geosite:cn,private')
    assert config['rule-providers']['xcli-dns-1']['payload'] == ['DOMAIN,media.example.com']
    assert config['rule-providers']['xcli-dns-2']['payload'] == ['DOMAIN-KEYWORD,media']
    assert dns['rule-set:xcli-dns-1'][0].endswith('#DIRECT')
    assert dns['rule-set:xcli-dns-2'][0].endswith('#PROXY')
    mobile = c.call(path + '/shadowrocket.conf')[2].decode()
    assert 'DOMAIN-KEYWORD,media,XCLI-PROXY' in mobile
    assert 'IP-CIDR,198.51.100.0/24,DIRECT\n' in mobile
    assert 'IP-CIDR,2001:db8::/32,XCLI-PROXY,no-resolve' in mobile
    assert 'GEOIP,US,XCLI-PROXY,no-resolve' in mobile
    assert 'DST-PORT,8443,REJECT' in mobile


def test_explicit_no_resolve_is_kept_inside_ai_udp_guard(fixture):
    c = fixture['client']; c.login()
    spec = next(t['spec'] for t in c.json('/api/rule-templates')['templates'] if t['id'] == 'independent')
    spec['rules'] = ('DOMAIN-KEYWORD,media,独立 · AI\n'
                     'IP-CIDR,198.51.100.0/24,独立 · AI,no-resolve\n'
                     'GEOIP,US,独立 · AI,no-resolve\n')
    tid = c.json('/api/rule-templates', 'POST', {'name': 'AI guard', 'spec': spec})['id']
    c.json('/api/rule-templates/' + tid + '/publish', 'POST', {'expected_revision': 1})
    c.json('/api/users/' + fixture['uid'] + '/rule-template', 'POST', {'template_id': tid})
    path = '/s/' + fixture['token']; rules = clash(c, path)['rules']
    assert 'AND,((DOMAIN-KEYWORD,media),(NETWORK,UDP)),REJECT' in rules
    assert 'AND,((IP-CIDR,198.51.100.0/24,no-resolve),(NETWORK,UDP)),REJECT' in rules
    assert 'AND,((GEOIP,US,no-resolve),(NETWORK,UDP)),REJECT' in rules
    mobile = c.call(path + '/shadowrocket.conf')[2].decode()
    assert 'AND,((GEOIP,US,no-resolve),(PROTOCOL,UDP)),REJECT' in mobile


def test_rule_validation_reports_line_and_bounds(fixture):
    c = fixture['client']; c.login()
    standard = next(t['spec'] for t in c.json('/api/rule-templates')['templates'] if t['id'] == 'standard')
    for bad in ('DOMAIN-KEYWORD,foo bar,PROXY', 'GEOIP,china,DIRECT', 'DST-PORT,65536,DIRECT',
                'DOMAIN,example.com,DIRECT,resolve', 'IP-CIDR,192.0.2.0/24,DIRECT,unknown'):
        result = c.json('/api/rule-templates', 'POST',
                        {'name': 'invalid', 'spec': {**standard, 'rules': '# comment\n' + bad}}, expected=422)
        assert '第 2 行' in result['detail']
    rules = ''.join(f'DOMAIN,a{i}.co,DIRECT\n' for i in range(500))
    c.json('/api/rule-templates', 'POST', {'name': 'limit', 'spec': {**standard, 'rules': rules}})
    result = c.json('/api/rule-templates', 'POST',
                    {'name': 'too many', 'spec': {**standard, 'rules': rules + 'DOMAIN,extra.example.com,DIRECT\n'}}, expected=422)
    assert '500' in result['detail']
    c.json('/api/users', 'POST', {'name': 'x' * 17000}, expected=413)


def test_failed_publish_keeps_previous_release_and_rule_priority(fixture):
    c = fixture['client']; c.login()
    spec = next(t['spec'] for t in c.json('/api/rule-templates')['templates'] if t['id'] == 'independent')
    spec['rules'] = ('DOMAIN,office.example.com,DIRECT\n'
                     'DOMAIN-SUFFIX,example.com,独立 · AI\n'
                     'IP-CIDR6,2001:db8::/32,独立 · AI\n')
    tid = c.json('/api/rule-templates', 'POST', {'name': 'priority', 'spec': spec})['id']
    c.json('/api/rule-templates/' + tid + '/publish', 'POST', {'expected_revision': 1})
    c.json('/api/users/' + fixture['uid'] + '/rule-template', 'POST', {'template_id': tid})
    path = '/s/' + fixture['token']; before = clash(c, path)
    assert before['rules'].index('DOMAIN,office.example.com,DIRECT') < before['rules'].index('DOMAIN-SUFFIX,example.com,独立 · AI')
    assert before['dns']['nameserver-policy']['office.example.com'][0].endswith('#DIRECT')
    assert before['dns']['nameserver-policy']['+.example.com'][0].endswith('#独立 · AI')
    dns_keys = list(before['dns']['nameserver-policy'])
    assert dns_keys.index('+.example.com') < dns_keys.index('geosite:cn,private')
    mobile = c.call(path + '/shadowrocket.conf')[2].decode()
    assert 'AND,((IP-CIDR,2001:db8::/32),(PROTOCOL,UDP)),REJECT' in mobile
    changed = {**spec, 'ai_outbound': 'vmess'}  # fixture has no VMess entry
    c.json('/api/rule-templates/' + tid, 'PUT',
           {'name': 'priority', 'spec': changed, 'expected_revision': 1})
    c.json('/api/rule-templates/' + tid + '/publish', 'POST', {'expected_revision': 2}, expected=422)
    assert clash(c, path) == before


def test_validation_auth_and_stale_revision(fixture):
    c = fixture['client']
    c.json('/api/rule-templates', expected=401)
    c.login()
    standard = next(t['spec'] for t in c.json('/api/rule-templates')['templates'] if t['id'] == 'standard')
    c.json('/api/rule-templates', 'POST', {'name': 'bad', 'spec': standard},
           headers={'X-CSRF-Token': 'wrong'}, expected=403)
    for bad in ('DOMAIN-SUFFIX,example.com,独立 · AI',
                'DOMAIN,example.com\n[Proxy],DIRECT',
                'IP-CIDR,127.0.0.1/999,DIRECT',
                'DOMAIN-SUFFIX,UPPER.example,DIRECT',
                'PROCESS-NAME,curl,DIRECT'):
        c.json('/api/rule-templates', 'POST',
               {'name': 'bad', 'spec': {**standard, 'rules': bad}}, expected=422)
    tid = c.json('/api/rule-templates', 'POST', {'name': 'valid', 'spec': standard})['id']
    c.json('/api/rule-templates/' + tid, 'PUT',
           {'name': 'valid', 'spec': standard, 'expected_revision': 1})
    c.json('/api/rule-templates/' + tid, 'PUT',
           {'name': 'valid', 'spec': standard, 'expected_revision': 1}, expected=409)
    c.json('/api/users/' + fixture['uid'] + '/rule-template', 'POST', {'template_id': tid}, expected=409)


def test_transfer_validation_is_read_only_and_import_creates_unassigned_draft(fixture):
    c = fixture['client']
    candidate = {'name': '  可复用模板  ', 'spec': {'base': 'standard', 'ai_outbound': 'proxy',
                 'rules': '# 保留注释\nDOMAIN-SUFFIX,example.org,DIRECT\n'}}
    c.json('/api/rule-templates/validate', 'POST', candidate, expected=401)
    c.login()
    before = c.json('/api/rule-templates')
    path = '/s/' + fixture['token']
    subscription_before = c.call(path + '/clash.yaml')[2]
    c.json('/api/rule-templates/validate', 'POST', candidate,
           headers={'X-CSRF-Token': 'wrong'}, expected=403)
    for bad in ({**candidate, 'name': ''},
                {**candidate, 'spec': {**candidate['spec'], 'base': 'unknown'}},
                {**candidate, 'spec': {**candidate['spec'], 'ai_outbound': 'unknown'}},
                {**candidate, 'spec': {**candidate['spec'], 'rules': 'DOMAIN,invalid,DIRECT'}},
                {**candidate, 'spec': {**candidate['spec'], 'extra': True}},
                {**candidate, 'extra': True}):
        c.json('/api/rule-templates/validate', 'POST', bad, expected=422)
    valid = c.json('/api/rule-templates/validate', 'POST', candidate)
    assert valid == {'name': '可复用模板', 'spec': candidate['spec']}
    assert c.json('/api/rule-templates') == before
    assert c.call(path + '/clash.yaml')[2] == subscription_before

    tid = c.json('/api/rule-templates', 'POST', valid)['id']
    after = c.json('/api/rule-templates')
    imported = next(item for item in after['templates'] if item['id'] == tid)
    assert imported['name'] == valid['name'] and imported['spec'] == valid['spec']
    assert imported['published'] is False and after['users'] == before['users']
    assert c.call(path + '/clash.yaml')[2] == subscription_before


def test_template_state_restored_with_user_backup(fixture):
    c = fixture['client']; c.login()
    independent = next(t['spec'] for t in c.json('/api/rule-templates')['templates'] if t['id'] == 'independent')
    tid = c.json('/api/rule-templates', 'POST', {'name': 'saved', 'spec': independent})['id']
    c.json('/api/rule-templates/' + tid + '/publish', 'POST', {'expected_revision': 1})
    c.json('/api/users/' + fixture['uid'] + '/rule-template', 'POST', {'template_id': tid})
    backup = c.json('/api/backups', 'POST', {})
    c.json('/api/users/' + fixture['uid'] + '/rule-template', 'POST', {'template_id': 'standard'})
    assert '独立 · AI' not in group_names(clash(c, '/s/' + fixture['token']))
    c.json('/api/backups/restore', 'POST',
           {'id': backup['id'], 'confirm': backup['id'], 'current_password': PASSWORD})
    c.login()
    assert '独立 · AI' in group_names(clash(c, '/s/' + fixture['token']))
    users = c.json('/api/rule-templates')['users']
    assert next(u for u in users if u['id'] == fixture['uid'])['template_id'] == tid


@pytest.mark.parametrize('fixture', [POLICY], indirect=True)
@pytest.mark.parametrize('builtin_id', ['standard', 'independent'])
def test_builtin_draft_and_publish_affect_only_assigned_users(fixture, builtin_id):
    c = fixture['client']; c.login()
    assigned_id = c.json('/api/users', 'POST', {'name': 'builtin user'})['id']
    other_id = c.json('/api/users', 'POST', {'name': 'other builtin user'})['id']
    assigned_path, other_path = subscription(c, assigned_id), subscription(c, other_id)
    other_builtin = 'independent' if builtin_id == 'standard' else 'standard'
    c.json('/api/users/' + assigned_id + '/rule-template', 'POST', {'template_id': builtin_id})
    c.json('/api/users/' + other_id + '/rule-template', 'POST', {'template_id': other_builtin})
    legacy_path = '/s/' + fixture['token']
    before, other_before, legacy_before = (clash(c, p) for p in (assigned_path, other_path, legacy_path))
    old_mobile = c.call(assigned_path + '/shadowrocket.conf')
    generic_before = c.call(assigned_path)[2]

    builtin = next(t for t in c.json('/api/rule-templates')['templates'] if t['id'] == builtin_id)
    assert builtin['builtin'] and builtin['revision'] == builtin['published_revision'] == 1
    original = builtin['spec']
    edited = {**original, 'rules': original['rules'] + 'DOMAIN-SUFFIX,builtin-test.example,DIRECT\n'}
    result = c.json('/api/rule-templates/' + builtin_id, 'PUT',
                    {'name': builtin['name'], 'spec': edited, 'expected_revision': 1})
    assert result['revision'] == 2
    draft = next(t for t in c.json('/api/rule-templates')['templates'] if t['id'] == builtin_id)
    assert draft['spec'] == edited and draft['published_spec'] == draft['factory_spec'] == original
    assert draft['revision'] == 2 and draft['published_revision'] == 1
    assert clash(c, assigned_path) == before
    mobile_draft = c.call(assigned_path + '/shadowrocket.conf')
    assert (mobile_draft[0], mobile_draft[2]) == (old_mobile[0], old_mobile[2])
    c.json('/api/rule-templates/' + builtin_id, 'PUT',
           {'name': builtin['name'], 'spec': edited, 'expected_revision': 1}, expected=409)
    c.json('/api/rule-templates/' + builtin_id + '/publish', 'POST', {'expected_revision': 1}, expected=409)

    result = c.json('/api/rule-templates/' + builtin_id + '/publish', 'POST', {'expected_revision': 2})
    assert result == {'published_revision': 2, 'affected_users': 1}
    published = next(t for t in c.json('/api/rule-templates')['templates'] if t['id'] == builtin_id)
    assert published['published_spec'] == edited and published['published_revision'] == 2
    assert published['factory_spec'] == original
    updated = clash(c, assigned_path)
    assert 'DOMAIN-SUFFIX,builtin-test.example,DIRECT' in updated['rules']
    assert updated['dns']['nameserver-policy']['+.builtin-test.example'][0].endswith('#DIRECT')
    mobile = c.call(assigned_path + '/shadowrocket.conf')
    assert mobile[0] == 200 and b'DOMAIN-SUFFIX,builtin-test.example,DIRECT' in mobile[2]
    assert clash(c, other_path) == other_before
    assert clash(c, legacy_path) == legacy_before
    assert c.call(assigned_path)[2] == generic_before


def test_builtin_failed_publish_keeps_published_rules(fixture):
    c = fixture['client']; c.login()
    uid, path = fixture['uid'], '/s/' + fixture['token']
    c.json('/api/users/' + uid + '/rule-template', 'POST', {'template_id': 'independent'})
    before = clash(c, path)
    builtin = next(t for t in c.json('/api/rule-templates')['templates'] if t['id'] == 'independent')
    c.json('/api/rule-templates/independent', 'PUT',
           {'name': builtin['name'], 'spec': {**builtin['spec'], 'ai_outbound': 'vmess'}, 'expected_revision': 1})
    c.json('/api/rule-templates/independent/publish', 'POST', {'expected_revision': 2}, expected=422)
    after = next(t for t in c.json('/api/rule-templates')['templates'] if t['id'] == 'independent')
    assert after['revision'] == 2 and after['published_revision'] == 1
    assert after['published_spec'] == builtin['published_spec']
    assert clash(c, path) == before


def test_builtin_base_and_name_can_be_edited_without_reassigning(fixture):
    c = fixture['client']; c.login()
    uid, path = fixture['uid'], '/s/' + fixture['token']
    c.json('/api/users/' + uid + '/rule-template', 'POST', {'template_id': 'standard'})
    catalog = c.json('/api/rule-templates')['templates']
    standard = next(t for t in catalog if t['id'] == 'standard')
    independent = next(t['published_spec'] for t in catalog if t['id'] == 'independent')
    before = clash(c, path)
    c.json('/api/rule-templates/standard', 'PUT',
           {'name': '我的内置模板', 'spec': independent, 'expected_revision': 1})
    assert clash(c, path) == before
    result = c.json('/api/rule-templates/standard/publish', 'POST', {'expected_revision': 2})
    assert result['affected_users'] == 1
    assert '独立 · AI' in group_names(clash(c, path))
    catalog = c.json('/api/rule-templates')
    updated = next(t for t in catalog['templates'] if t['id'] == 'standard')
    assert updated['name'] == '我的内置模板' and updated['published_spec'] == independent
    assert updated['factory_spec'] == standard['factory_spec']
    assert next(u for u in catalog['users'] if u['id'] == uid)['template_id'] == 'standard'


def test_builtin_versions_are_restored_with_user_backup(fixture):
    c = fixture['client']; c.login()
    uid, path = fixture['uid'], '/s/' + fixture['token']
    c.json('/api/users/' + uid + '/rule-template', 'POST', {'template_id': 'standard'})
    builtin = next(t for t in c.json('/api/rule-templates')['templates'] if t['id'] == 'standard')
    first = {**builtin['spec'], 'rules': 'DOMAIN,first.example,DIRECT\n'}
    c.json('/api/rule-templates/standard', 'PUT', {'name': builtin['name'], 'spec': first, 'expected_revision': 1})
    c.json('/api/rule-templates/standard/publish', 'POST', {'expected_revision': 2})
    backup = c.json('/api/backups', 'POST', {})
    second = {**first, 'rules': 'DOMAIN,second.example,DIRECT\n'}
    c.json('/api/rule-templates/standard', 'PUT', {'name': builtin['name'], 'spec': second, 'expected_revision': 2})
    c.json('/api/rule-templates/standard/publish', 'POST', {'expected_revision': 3})
    assert 'DOMAIN,second.example,DIRECT' in clash(c, path)['rules']
    c.json('/api/backups/restore', 'POST',
           {'id': backup['id'], 'confirm': backup['id'], 'current_password': PASSWORD})
    c.login()
    restored = next(t for t in c.json('/api/rule-templates')['templates'] if t['id'] == 'standard')
    assert restored['revision'] == restored['published_revision'] == 2
    assert restored['published_spec'] == first
    rules = clash(c, path)['rules']
    assert 'DOMAIN,first.example,DIRECT' in rules and 'DOMAIN,second.example,DIRECT' not in rules


@pytest.mark.parametrize('fixture', [POLICY], indirect=True)
@pytest.mark.parametrize('builtin_id', ['standard', 'independent'])
def test_builtin_reset_and_undo_preserve_published_and_draft_versions(fixture, builtin_id):
    c = fixture['client']; c.login()
    uid = c.json('/api/users', 'POST', {'name': 'reset user'})['id']
    path, legacy = subscription(c, uid), '/s/' + fixture['token']
    c.json('/api/users/' + uid + '/rule-template', 'POST', {'template_id': builtin_id})
    original_clash, legacy_before = clash(c, path), clash(c, legacy)
    original_mobile = c.call(path + '/shadowrocket.conf')
    builtin = next(t for t in c.json('/api/rule-templates')['templates'] if t['id'] == builtin_id)
    factory = builtin['factory_spec']
    published = {**factory, 'rules': factory['rules'] + 'DOMAIN,reset-check.example,DIRECT\n'}
    c.json('/api/rule-templates/' + builtin_id, 'PUT',
           {'name': builtin['name'], 'spec': published, 'expected_revision': 1})
    c.json('/api/rule-templates/' + builtin_id + '/publish', 'POST', {'expected_revision': 2})
    published_clash = clash(c, path)
    draft = {**published, 'rules': published['rules'] + 'DOMAIN,draft-check.example,REJECT\n'}
    c.json('/api/rule-templates/' + builtin_id, 'PUT',
           {'name': '重置前名称', 'spec': draft, 'expected_revision': 2})
    c.json('/api/rule-templates/' + builtin_id + '/reset', 'POST', {'expected_revision': 2}, expected=409)
    c.json('/api/rule-templates/' + builtin_id + '/reset', 'POST', {'expected_revision': 3},
           headers={'X-CSRF-Token': 'wrong'}, expected=403)
    result = c.json('/api/rule-templates/' + builtin_id + '/reset', 'POST', {'expected_revision': 3})
    assert result == {'unchanged': False, 'revision': 4, 'affected_users': 1}
    reset = next(t for t in c.json('/api/rule-templates')['templates'] if t['id'] == builtin_id)
    assert reset['name'] == builtin['name'] and reset['spec'] == reset['published_spec'] == factory
    assert reset['revision'] == reset['published_revision'] == 4 and reset['can_undo_reset']
    assert clash(c, path) == original_clash and clash(c, legacy) == legacy_before
    mobile = c.call(path + '/shadowrocket.conf')
    assert (mobile[0], mobile[2]) == (original_mobile[0], original_mobile[2])
    again = c.json('/api/rule-templates/' + builtin_id + '/reset', 'POST', {'expected_revision': 4})
    assert again['unchanged'] and again['revision'] == 4
    c.json('/api/rule-templates/' + builtin_id, 'PUT',
           {'name': builtin['name'], 'spec': factory, 'expected_revision': 4})
    c.json('/api/rule-templates/' + builtin_id + '/reset', 'POST', {'expected_revision': 5})
    c.json('/api/rule-templates/' + builtin_id + '/undo-reset', 'POST', {'expected_revision': 5}, expected=409)
    result = c.json('/api/rule-templates/' + builtin_id + '/undo-reset', 'POST', {'expected_revision': 6})
    assert result == {'revision': 7, 'affected_users': 1}
    restored = next(t for t in c.json('/api/rule-templates')['templates'] if t['id'] == builtin_id)
    assert restored['name'] == '重置前名称' and restored['spec'] == draft and restored['published_spec'] == published
    assert restored['revision'] == 7 and restored['published_revision'] == 6 and not restored['can_undo_reset']
    assert clash(c, path) == published_clash and clash(c, legacy) == legacy_before
    c.json('/api/rule-templates/' + builtin_id + '/undo-reset', 'POST', {'expected_revision': 7}, expected=409)


def test_reset_is_limited_to_builtins(fixture):
    c = fixture['client']; c.login()
    spec = next(t['spec'] for t in c.json('/api/rule-templates')['templates'] if t['id'] == 'standard')
    tid = c.json('/api/rule-templates', 'POST', {'name': 'custom', 'spec': spec})['id']
    c.json('/api/rule-templates/' + tid + '/reset', 'POST', {'expected_revision': 1}, expected=404)
    c.json('/api/rule-templates/' + tid + '/undo-reset', 'POST', {'expected_revision': 1}, expected=404)
