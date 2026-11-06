import assert from 'node:assert/strict';
import { test } from 'node:test';
import { changeSelectedRules, filterRuleLines, filterSystemRules, parseRuleLines, selectVisibleRules } from '../ui/src/rule-list.ts';

const fixture = [
  '# AI rules',
  'DOMAIN-SUFFIX,openai.com,独立 · AI',
  'DOMAIN,ai.google.dev,独立 · AI',
  '',
  'DOMAIN-SUFFIX,google.com,独立 · Google',
  'IP-CIDR,192.0.2.0/24,DIRECT,no-resolve',
  'IP-CIDR6,2001:db8::/32,DIRECT',
  '# Google comment',
  'malformed line',
].join('\n');
const defaults = { query: '', target: '', kind: '', resolution: '', selectedOnly: false };
const contents = lines => lines.map(line => line.text);

test('filters combine group, type, search, IP resolution and selection without changing order', () => {
  const lines = parseRuleLines(fixture);
  assert.deepEqual(contents(filterRuleLines(lines, { ...defaults, target: '独立 · AI', query: 'GOOGLE', kind: 'DOMAIN' }, new Set())),
    ['DOMAIN,ai.google.dev,独立 · AI']);
  assert.deepEqual(contents(filterRuleLines(lines, { ...defaults, target: 'DIRECT', resolution: 'default' }, new Set())),
    ['IP-CIDR6,2001:db8::/32,DIRECT']);
  assert.deepEqual(contents(filterRuleLines(lines, { ...defaults, resolution: 'no-resolve', selectedOnly: true }, new Set([1, 5]))),
    ['IP-CIDR,192.0.2.0/24,DIRECT,no-resolve']);
  assert.deepEqual(contents(filterRuleLines(lines, { ...defaults, query: 'google' }, new Set())),
    ['DOMAIN,ai.google.dev,独立 · AI', 'DOMAIN-SUFFIX,google.com,独立 · Google', '# Google comment']);
  assert.deepEqual(contents(parseRuleLines(fixture)), contents(lines));
});

test('select all applies only to visible rules and retains selections outside the filter', () => {
  const lines = parseRuleLines(fixture);
  const ai = filterRuleLines(lines, { ...defaults, target: '独立 · AI' }, new Set());
  assert.deepEqual(selectVisibleRules([4], ai, true), [1, 2, 4]);
  assert.deepEqual(selectVisibleRules([1, 2, 4], ai, false), [4]);
  assert.deepEqual(selectVisibleRules([], lines, true), [1, 2, 4, 5, 6]);
});

test('bulk changes preserve unrelated rules, comments, line endings and non-rule text', () => {
  const source = '# note\r\nDOMAIN,a.example, 独立 · AI \r\ninvalid\r\nIP-CIDR,192.0.2.0/24,DIRECT,no-resolve\r\n';
  const changed = changeSelectedRules(source, new Set([0, 1, 2]), { type: 'target', target: '独立 · Google' });
  assert.equal(changed, '# note\r\nDOMAIN,a.example, 独立 · Google \r\ninvalid\r\nIP-CIDR,192.0.2.0/24,DIRECT,no-resolve\r\n');
  const deleted = changeSelectedRules(source, new Set([0, 1, 2]), { type: 'delete' });
  assert.equal(deleted, '# note\r\ninvalid\r\nIP-CIDR,192.0.2.0/24,DIRECT,no-resolve\r\n');
});

test('system rules follow the group and other filters but are never selected for bulk edits', () => {
  const system = [
    { kind: 'DOMAIN-SUFFIX', value: 'google.com', target: '独立 · Google', option: '', provider: 'category-Google' },
    { kind: 'DOMAIN-SUFFIX', value: 'oraclecloud.com', target: 'oracle-cloud', option: '', provider: 'xcli-oracle-cloud' },
    { kind: 'IP-CIDR', value: '10.0.0.0/8', target: 'DIRECT', option: 'no-resolve', provider: '' },
  ];
  assert.deepEqual(filterSystemRules(system, { ...defaults, target: '独立 · Google', query: 'GOOGLE' }), [system[0]]);
  assert.deepEqual(filterSystemRules(system, { ...defaults, target: 'oracle-cloud', kind: 'DOMAIN-SUFFIX' }), [system[1]]);
  assert.deepEqual(filterSystemRules(system, { ...defaults, resolution: 'no-resolve' }), [system[2]]);
  assert.deepEqual(filterSystemRules(system, { ...defaults, selectedOnly: true }), []);
  assert.deepEqual(selectVisibleRules([], parseRuleLines(fixture), true), [1, 2, 4, 5, 6]);
});
