export type OutboundOption = { value: string; label: string };
export type GroupOutbound = { default: string | null; options: OutboundOption[] };
export type GroupOutbounds = Record<string, GroupOutbound>;
export type CustomGroup = { name: string; default: string };

export function validGroupOutbounds(value: unknown): value is GroupOutbounds {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  return Object.values(value).every(item => {
    if (!item || typeof item !== 'object' || !('default' in item) || !('options' in item)) return false;
    return (item.default === null || typeof item.default === 'string') && Array.isArray(item.options) &&
      item.options.every((option: unknown) => option && typeof option === 'object' && 'value' in option && typeof option.value === 'string' && 'label' in option && typeof option.label === 'string');
  });
}

/** Existing AI and custom-group defaults remain authoritative until changed. */
export function inheritedGroupDefault(group: string, legacyAi: string, customGroups: CustomGroup[], descriptor: GroupOutbound): string | null {
  const custom = customGroups.find(item => item.name === group);
  if (custom) return `selector:${custom.default}`;
  if (group === '独立 · AI' && legacyAi !== 'proxy') return `node:${legacyAi}`;
  return descriptor.default;
}

export function outboundLabel(value: string | null, options: OutboundOption[]): string {
  if (!value) return '系统默认';
  return options.find(option => option.value === value)?.label ?? `${value.replace(/^node:/, '')}（当前不可用）`;
}
