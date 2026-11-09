import assert from 'node:assert/strict';
import { test } from 'node:test';
import { orderedGroups, validGroupOrderCatalog } from '../ui/src/group-order.ts';

const option = value => ({ value, label: value });
const independent = ['PROXY', '直连', '故障转移', '自动选择', 'EaseLian', '独立 · AI',
  '独立 · Telegram', '独立 · Google', '其他流量', '#node:residential-42', '__custom__', 'oracle-cloud'].map(option);
const names = values => values.map(item => item.value);

test('the catalog keeps visible helper and dynamic groups and expands custom groups', () => {
  assert.equal(validGroupOrderCatalog(independent), true);
  assert.equal(validGroupOrderCatalog([...independent, option('PROXY')]), false);
  assert.equal(validGroupOrderCatalog([{ value: 'PROXY' }]), false);
  assert.deepEqual(names(orderedGroups(independent, ['工作'], [])),
    names(independent).map(name => name === '__custom__' ? '工作' : name));
});

test('an old order preserves unsorted helper positions until the user moves them', () => {
  const old = ['PROXY', 'DIRECT', 'REJECT', '独立 · AI', '独立 · Google', '工作', '其他流量', 'EaseLian', 'oracle-cloud'];
  const visible = names(orderedGroups(independent, ['工作'], old));
  assert.deepEqual(visible.slice(0, 4), ['PROXY', '直连', '故障转移', '自动选择']);
  assert.ok(visible.indexOf('独立 · AI') < visible.indexOf('独立 · Google'));
  assert.equal(visible[9], '#node:residential-42');
  const userOrder = ['自动选择', '独立 · Google', '故障转移', '#node:residential-42',
    '直连', 'PROXY', '独立 · AI', '独立 · Telegram', '工作', '其他流量', 'EaseLian', 'oracle-cloud'];
  assert.deepEqual(names(orderedGroups(independent, ['工作'], userOrder)), userOrder);
});

test('standard template country selectors use their stable IDs when sorting', () => {
  const standard = [option('PROXY'), { value: '#country:SG', label: '住宅分组 · 新加坡' }, option('STUN'),
    option('__custom__'), option('oracle-cloud')];
  assert.deepEqual(names(orderedGroups(standard, ['工作'], ['#country:SG', '工作', 'PROXY', 'STUN', 'oracle-cloud'])),
    ['#country:SG', '工作', 'PROXY', 'STUN', 'oracle-cloud']);
});
