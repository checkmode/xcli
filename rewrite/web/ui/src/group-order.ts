export type GroupOrderOption = { value: string; label: string };

const legacyOrder = ['PROXY', 'STUN', 'EaseLian', '独立 · AI', '独立 · Google', '独立 · Telegram',
  '独立 · YouTube', '独立 · Netflix', '独立 · 国外媒体', '独立 · STUN', '其他流量', 'oracle-cloud'];

export function validGroupOrderCatalog(value: unknown): value is GroupOrderOption[] {
  return Array.isArray(value) && value.every(item => item && typeof item === 'object' &&
    typeof item.value === 'string' && typeof item.label === 'string') &&
    new Set(value.map(item => item.value)).size === value.length;
}

/** Mirror the client's ordering while preserving positions of older helper groups. */
export function orderedGroups(catalog: GroupOrderOption[], custom: string[], order: string[]): GroupOrderOption[] {
  const values = catalog.flatMap(item => item.value === '__custom__'
    ? custom.map(name => ({ value: name, label: name })) : [item]);
  if (!order.length) return values;
  const ranks = new Map(order.map((name, index) => [name, index]));
  let next = order.length;
  for (const name of [...legacyOrder, ...custom]) {
    if (!ranks.has(name)) ranks.set(name, next++);
  }
  const selected = values.filter(item => ranks.has(item.value))
    .sort((a, b) => ranks.get(a.value)! - ranks.get(b.value)!);
  let index = 0;
  return values.map(item => ranks.has(item.value) ? selected[index++]! : item);
}
