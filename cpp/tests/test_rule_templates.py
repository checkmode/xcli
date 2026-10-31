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
