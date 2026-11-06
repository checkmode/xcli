import assert from 'node:assert/strict';
import { test } from 'node:test';
import { inheritedGroupDefault, outboundLabel, validGroupOutbounds } from '../ui/src/group-defaults.ts';

test('old AI and custom group defaults remain visible when no override exists', () => {
  const descriptor = { default: 'selector:故障转移', options: [
    { value: 'selector:故障转移', label: '故障转移' },
    { value: 'node:residential-41', label: '住宅 41' },
    { value: 'selector:PROXY', label: '跟随 PROXY' },
  ] };
  assert.equal(inheritedGroupDefault('独立 · AI', 'residential-41', [], descriptor), 'node:residential-41');
  assert.equal(inheritedGroupDefault('独立 · AI', 'proxy', [], descriptor), 'selector:故障转移');
  assert.equal(inheritedGroupDefault('工作', 'proxy', [{ name: '工作', default: 'PROXY' }], descriptor), 'selector:PROXY');
  assert.equal(outboundLabel('node:residential-41', descriptor.options), '住宅 41');
  assert.match(outboundLabel('node:residential-99', descriptor.options), /当前不可用/);
});

test('catalog validation requires server-provided stable selectors and labels', () => {
  assert.equal(validGroupOutbounds({ PROXY: { default: 'node:reality', options: [{ value: 'node:reality', label: 'REALITY' }] } }), true);
  assert.equal(validGroupOutbounds({ PROXY: { default: 'node:reality', options: [{ value: 'node:reality' }] } }), false);
  assert.equal(validGroupOutbounds([]), false);
});
