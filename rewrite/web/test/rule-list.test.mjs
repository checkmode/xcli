import assert from 'node:assert/strict';
import { test } from 'node:test';
import { changeSelectedRules, countRulesByTarget, filterRuleLines, filterSystemRules, moveRule, movedRuleIndex, parseRuleLines, selectVisibleRules } from '../ui/src/rule-list.ts';

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

test('moving a template rule changes precedence and preserves comments, selections and line endings', () => {
  const source = '# first\r\nDOMAIN,a.example,PROXY\r\n# other\r\nDOMAIN,b.example,DIRECT';
  const result = moveRule(source, 3, 1, false);
  assert.equal(result.text, '# first\r\nDOMAIN,b.example,DIRECT\r\nDOMAIN,a.example,PROXY\r\n# other');
  assert.equal(movedRuleIndex(3, result), 1);
  assert.equal(movedRuleIndex(1, result), 2);
  assert.equal(movedRuleIndex(2, result), 3);
  assert.equal(moveRule(source, 0, 1, false), null);
  assert.equal(moveRule(source, 1, 3, false)?.text, '# first\r\n# other\r\nDOMAIN,a.example,PROXY\r\nDOMAIN,b.example,DIRECT');
});

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

test('global filter counts cover every group while the selected group narrows the results', () => {
  const lines = parseRuleLines(fixture);
  const system = [
    { kind: 'DOMAIN-SUFFIX', value: 'googleapis.com', target: '独立 · Google', option: '', provider: 'category-Google' },
    { kind: 'DOMAIN-SUFFIX', value: 'oraclecloud.com', target: 'oracle-cloud', option: '', provider: 'xcli-oracle-cloud' },
  ];
  const google = { ...defaults, target: '独立 · Google', query: 'google', kind: 'DOMAIN-SUFFIX' };
  const summary = countRulesByTarget(lines, system, google, new Set());
  assert.equal(summary.total, 2);
  assert.equal(summary.counts.get('独立 · Google'), 2);
  assert.equal(summary.counts.get('独立 · AI') ?? 0, 0);
  assert.deepEqual(contents(filterRuleLines(lines, google, new Set())), ['DOMAIN-SUFFIX,google.com,独立 · Google']);
  assert.deepEqual(filterSystemRules(system, google), [system[0]]);
  const ai = { ...google, target: '独立 · AI', kind: '' };
  assert.equal(countRulesByTarget(lines, system, ai, new Set()).total, 3);
  assert.deepEqual(contents(filterRuleLines(lines, ai, new Set())), ['DOMAIN,ai.google.dev,独立 · AI']);
  assert.deepEqual(filterSystemRules(system, ai), []);
  const selectedOnly = countRulesByTarget(lines, system, { ...defaults, selectedOnly: true, target: 'DIRECT' }, new Set([1, 4]));
  assert.equal(selectedOnly.total, 2);
  assert.equal(selectedOnly.counts.get('独立 · AI'), 1);
  assert.equal(selectedOnly.counts.get('独立 · Google'), 1);
});
