export type RuleLine = { index: number; text: string; fields: string[] | null };
export type RuleFilters = { query: string; target: string; kind: string; resolution: string; selectedOnly: boolean };
export type SystemRule = { id?: string; kind: string; value: string; target: string; option: string; provider: string; after_template?: boolean; disabled?: boolean; modified?: boolean };
export type SystemRuleOverride = { kind: string; value: string; target: string; option: string } | null;

export const ruleKinds = ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'IP-CIDR', 'IP-CIDR6', 'GEOIP', 'DST-PORT'];
export const resolutionKinds = ['IP-CIDR', 'IP-CIDR6', 'GEOIP'];

export function parseRuleLines(text: string): RuleLine[] {
  return text.split('\n').map((line, index) => {
    const trimmed = line.trim();
    const fields = trimmed.split(',').map(value => value.trim());
    return { index, text: line, fields: !trimmed || trimmed.startsWith('#') || fields.length < 3 || fields.length > 4 ? null : fields };
  }).filter(line => line.text.trim() !== '');
}

export function filterRuleLines(lines: RuleLine[], filters: RuleFilters, selected: ReadonlySet<number>, names: Record<string, string> = {}): RuleLine[] {
  const query = filters.query.trim().toLowerCase();
  return lines.filter(line => {
    if (query && !line.text.toLowerCase().includes(query) && !(line.fields?.[2] && names[line.fields[2]]?.toLowerCase().includes(query))) return false;
    if (filters.selectedOnly && (!line.fields || !selected.has(line.index))) return false;
    if (filters.target && (!line.fields || line.fields[2] !== filters.target)) return false;
    if (filters.kind && (!line.fields || line.fields[0] !== filters.kind)) return false;
    if (filters.resolution && (!line.fields || !resolutionKinds.includes(line.fields[0] ?? '') ||
        (line.fields[3] || 'default') !== filters.resolution)) return false;
    return true;
  });
}

export function filterSystemRules(lines: SystemRule[], filters: RuleFilters, names: Record<string, string> = {}): SystemRule[] {
  if (filters.selectedOnly) return [];
  const query = filters.query.trim().toLowerCase();
  return lines.filter(line => {
    if (query && ![line.kind, line.value, line.target, names[line.target] ?? '', line.option, line.provider].some(value => value.toLowerCase().includes(query))) return false;
    if (filters.target && line.target !== filters.target) return false;
    if (filters.kind && line.kind !== filters.kind) return false;
    if (filters.resolution && (!resolutionKinds.includes(line.kind) || (line.option || 'default') !== filters.resolution)) return false;
    return true;
  });
}

/** Group counts reflect the global filters, irrespective of the selected group. */
export function countRulesByTarget(lines: RuleLine[], system: SystemRule[], filters: RuleFilters, selected: ReadonlySet<number>, names: Record<string, string> = {}): { counts: Map<string, number>; total: number } {
  const global = { ...filters, target: '' };
  const counts = new Map<string, number>();
  for (const line of filterRuleLines(lines, global, selected, names)) {
    const target = line.fields?.[2];
    if (target) counts.set(target, (counts.get(target) ?? 0) + 1);
  }
  for (const line of filterSystemRules(system, global, names)) if (!line.disabled) counts.set(line.target, (counts.get(line.target) ?? 0) + 1);
  return { counts, total: [...counts.values()].reduce((sum, value) => sum + value, 0) };
}

/** Translate only rule targets; comments, values and original whitespace remain untouched. */
export function remapRuleTargets(text: string, names: Record<string, string>): string {
  const valid = new Set(parseRuleLines(text).filter(line => line.fields).map(line => line.index));
  return text.split('\n').map((line, index) => {
    if (!valid.has(index)) return line;
    const parts = line.split(',');
    const field = parts[2] ?? '';
    const whitespace = /^(\s*)(.*?)(\s*)$/.exec(field);
    const name = whitespace?.[2] ? names[whitespace[2]] : undefined;
    if (name !== undefined) parts[2] = `${whitespace?.[1] ?? ''}${name}${whitespace?.[3] ?? ''}`;
    return parts.join(',');
  }).join('\n');
}

export function selectVisibleRules(selected: number[], visible: RuleLine[], checked: boolean): number[] {
  const result = new Set(selected);
  for (const line of visible) {
    if (!line.fields) continue;
    if (checked) result.add(line.index); else result.delete(line.index);
  }
  return [...result].sort((a, b) => a - b);
}

export type RuleMove = { text: string; from: number; to: number };

/** Move one template rule while keeping comments, other rows and line endings. */
export function moveRule(text: string, from: number, target: number, after: boolean): RuleMove | null {
  const valid = new Set(parseRuleLines(text).filter(line => line.fields).map(line => line.index));
  if (!valid.has(from) || !valid.has(target) || from === target) return null;
  const boundary = target + (after ? 1 : 0);
  const to = boundary - (from < boundary ? 1 : 0);
  if (to === from) return null;
  const rows = text.split('\n');
  const endings = rows.map((row, index) => index === rows.length - 1 ? '' : (row.endsWith('\r') ? '\r\n' : '\n'));
  const content = rows.map((row, index) => endings[index] === '\r\n' ? row.slice(0, -1) : row);
  const [moved] = content.splice(from, 1);
  if (moved === undefined) return null;
  content.splice(to, 0, moved);
  return { text: content.map((row, index) => row + endings[index]).join(''), from, to };
}

export function movedRuleIndex(index: number, move: RuleMove): number {
  if (index === move.from) return move.to;
  if (move.from < move.to && index > move.from && index <= move.to) return index - 1;
  if (move.to < move.from && index >= move.to && index < move.from) return index + 1;
  return index;
}

export function changeSelectedRules(text: string, selected: ReadonlySet<number>, action: { type: 'delete' } | { type: 'target'; target: string }): string {
  const valid = new Set(parseRuleLines(text).filter(line => line.fields).map(line => line.index));
  return text.split('\n').flatMap((line, index) => {
    if (!selected.has(index) || !valid.has(index)) return [line];
    if (action.type === 'delete') return [];
    const parts = line.split(',');
    const previous = parts[2] ?? '';
    const whitespace = /^(\s*)(.*?)(\s*)$/.exec(previous);
    parts[2] = `${whitespace?.[1] ?? ''}${action.target}${whitespace?.[3] ?? ''}`;
    return [parts.join(',')];
  }).join('\n');
}
