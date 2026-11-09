<script setup lang="ts">
import { computed, nextTick, reactive, ref, watch } from 'vue';
import { changeSelectedRules, countRulesByTarget, filterRuleLines, filterSystemRules, moveRule, movedRuleIndex, parseRuleLines, remapRuleTargets, resolutionKinds, ruleKinds, selectVisibleRules, type RuleLine, type SystemRule, type SystemRuleOverride } from './rule-list';
import { inheritedGroupDefault, outboundLabel, type CustomGroup, type GroupOutbounds } from './group-defaults';

const props = defineProps<{ rules: string; targets: string[]; systemRules: SystemRule[]; systemRulesAvailable: boolean;
  systemOverrides: Record<string, SystemRuleOverride>; groupOutbounds: GroupOutbounds; groupOutboundsAvailable: boolean; groupDefaults: Record<string, string>; groupOrder: string[]; groupNames: Record<string, string>; customGroups: CustomGroup[]; legacyAi: string; busy: boolean }>();
const emit = defineEmits<{ 'update:rules': [value: string]; 'update:system-overrides': [value: Record<string, SystemRuleOverride>]; 'update:group-defaults': [value: Record<string, string>]; 'update:group-order': [value: string[]]; 'rename-group': [original: string, name: string] }>();
const filters = reactive({ query: '', kind: '', resolution: '', selectedOnly: false });
const selectedTarget = ref('');
const groupPickerOpen = ref(false);
const selectedLines = ref<number[]>([]);
const editLine = ref<number | null>(null);
const editSystem = ref<string | null>(null);
const ruleEditor = ref<HTMLElement | null>(null);
const ruleHeading = ref<HTMLElement | null>(null);
const groupPicker = ref<HTMLElement | null>(null);
const lineForm = reactive({ kind: 'DOMAIN-SUFFIX', value: '', target: 'PROXY', option: '', position: 'end' });
type RuleValues = { kind: string; value: string; target: string; option: string };
const editSnapshot = ref<RuleValues | null>(null);
type SystemOverrides = Record<string, SystemRuleOverride>;
type Change = { type: 'rules'; before: string; after: string } | { type: 'system'; before: SystemOverrides; after: SystemOverrides };
const lastChange = ref<Change | null>(null);
const notice = ref('');
const bulkTarget = ref('');
const error = ref('');
const editingGroupName = ref(false); const groupNameDraft = ref(''); const groupNameError = ref('');
let expectedRules: string | undefined;
type Drag = { kind: 'rule' | 'group'; source: string; target: string; after: boolean; pointer: number; startY: number; active: boolean };
const drag = ref<Drag | null>(null);

const lines = computed(() => parseRuleLines(props.rules));
const effectiveSystemRules = computed(() => props.systemRules.map(rule => {
  if (!rule.id || !(rule.id in props.systemOverrides)) return rule;
  const override = props.systemOverrides[rule.id];
  return override === null ? { ...rule, disabled: true, modified: true } : { ...rule, ...override, modified: true };
}));
const selectedSet = computed(() => new Set(selectedLines.value));
const effectiveFilters = computed(() => ({ ...filters, target: selectedTarget.value }));
const visibleLines = computed(() => filterRuleLines(lines.value, effectiveFilters.value, selectedSet.value, props.groupNames));
const visibleSystemRules = computed(() => filterSystemRules(effectiveSystemRules.value, effectiveFilters.value, props.groupNames));
const visibleRules = computed(() => visibleLines.value.filter(line => line.fields));
type DisplayRow = { type: 'heading'; key: string; label: string } | { type: 'system'; key: string; rule: SystemRule } | { type: 'template'; key: string; line: RuleLine };
const displayRows = computed<DisplayRow[]>(() => {
  const before = visibleSystemRules.value.filter(rule => !rule.after_template);
  const after = visibleSystemRules.value.filter(rule => rule.after_template);
  const rows: DisplayRow[] = [];
  if (before.length) rows.push({ type: 'heading', key: 'system-before', label: '系统基础规则' });
  rows.push(...before.map(rule => ({ type: 'system' as const, key: `system-${rule.id ?? effectiveSystemRules.value.indexOf(rule)}`, rule })));
  rows.push(...visibleLines.value.map(line => ({ type: 'template' as const, key: `template-${line.index}`, line })));
  if (after.length) rows.push({ type: 'heading', key: 'system-after', label: before.length ? '系统基础规则（续）' : '系统基础规则' });
  rows.push(...after.map(rule => ({ type: 'system' as const, key: `system-${rule.id ?? effectiveSystemRules.value.indexOf(rule)}`, rule })));
  return rows;
});
const visibleSelected = computed(() => visibleRules.value.filter(line => selectedSet.value.has(line.index)).length);
const hiddenSelected = computed(() => selectedLines.value.length - visibleSelected.value);
const editVisible = computed(() => editSystem.value ? visibleSystemRules.value.some(rule => rule.id === editSystem.value) : editLine.value === null || visibleRules.value.some(line => line.index === editLine.value));
const editingExisting = computed(() => editLine.value !== null || editSystem.value !== null);
const editingSystemOriginal = computed(() => props.systemRules.find(rule => rule.id === editSystem.value));
const systemTargets = computed(() => [...new Set([...props.targets, 'oracle-cloud'])]);
const allChecked = computed(() => visibleRules.value.length > 0 && visibleSelected.value === visibleRules.value.length);
const someChecked = computed(() => visibleSelected.value > 0 && !allChecked.value);
const globalFiltersActive = computed(() => Boolean(filters.query.trim() || filters.kind || filters.resolution || filters.selectedOnly));
const filterActive = computed(() => Boolean(globalFiltersActive.value || selectedTarget.value));
const filterTargets = computed(() => {
  const values = [...new Set([...props.targets, ...Object.keys(props.groupDefaults), ...effectiveSystemRules.value.map(rule => rule.target), ...lines.value.flatMap(line => line.fields?.[2] ? [line.fields[2]] : [])])];
  const ordered = props.groupOrder.filter(name => values.includes(name));
  return [...ordered, ...values.filter(name => !ordered.includes(name))];
});
const filterKinds = computed(() => [...new Set([...ruleKinds, ...effectiveSystemRules.value.map(rule => rule.kind)])]);
const groupCounts = computed(() => countRulesByTarget(lines.value, effectiveSystemRules.value, effectiveFilters.value, selectedSet.value, props.groupNames));
const groupDescriptor = computed(() => props.groupOutbounds[selectedTarget.value] ??
  (props.customGroups.some(group => group.name === selectedTarget.value) ? props.groupOutbounds.__custom__ : undefined));
const inheritedDefault = computed(() => groupDescriptor.value ? inheritedGroupDefault(selectedTarget.value, props.legacyAi, props.customGroups, groupDescriptor.value) : null);
const selectedDefault = computed(() => props.groupDefaults[selectedTarget.value] ?? '');
const defaultUnavailable = computed(() => Boolean(selectedDefault.value && groupDescriptor.value && !groupDescriptor.value.options.some(option => option.value === selectedDefault.value)));
const orphanedDefaults = computed(() => props.groupOutboundsAvailable ? Object.keys(props.groupDefaults).filter(group =>
  !props.groupOutbounds[group] && !props.customGroups.some(item => item.name === group)) : []);
const orphanedSystem = computed(() => props.systemRulesAvailable ? Object.keys(props.systemOverrides).filter(id =>
  !props.systemRules.some(rule => rule.id === id)) : []);
function currentValues(): RuleValues {
  return { kind: lineForm.kind, value: lineForm.value, target: lineForm.target, option: lineForm.option };
}
const rulePending = computed(() => !editingExisting.value ? Boolean(lineForm.value.trim()) :
  JSON.stringify(currentValues()) !== JSON.stringify(editSnapshot.value));
const hasPending = computed(() => rulePending.value || editingGroupName.value);
const displayRules = computed(() => remapRuleTargets(props.rules, props.groupNames));
const reverseNames = computed(() => Object.fromEntries(Object.entries(props.groupNames).map(([original, display]) => [display, original])));
const reservedNames = new Set(['DIRECT', 'REJECT', 'PROXY', 'STUN', '直连', '故障转移', '自动选择', '住宅节点', 'EaseLian', '独立 · AI', '独立 · Google', '独立 · Telegram', '独立 · YouTube', '独立 · Netflix', '独立 · 国外媒体', '独立 · STUN', '其他流量', 'oracle-cloud']);
function displayTarget(target: string) { return props.groupNames[target] ?? target; }
function targetLabel(target: string) { return target === 'DIRECT' ? 'DIRECT · 直连' : target === 'REJECT' ? 'REJECT · 拒绝' : displayTarget(target); }
function beginGroupName() {
  if (rulePending.value) { error.value = '请先完成正在编辑的规则。'; return; }
  groupNameDraft.value = displayTarget(selectedTarget.value); groupNameError.value = ''; editingGroupName.value = true;
}
function cancelGroupName() { editingGroupName.value = false; groupNameError.value = ''; groupNameDraft.value = ''; }
function saveGroupName() {
  const original = selectedTarget.value; const name = groupNameDraft.value.trim();
  if (!original || ['DIRECT', 'REJECT'].includes(original)) return;
  const used = [...filterTargets.value.filter(item => item !== original).map(displayTarget),
    ...Object.entries(props.groupNames).filter(([key]) => key !== original).map(([, value]) => value)];
  if (!name || new TextEncoder().encode(name).length > 64 || /[\x00-\x1f\x7f,=#]/.test(name) ||
      (name !== original && (reservedNames.has(name) || used.includes(name)))) {
    groupNameError.value = '名称为空、过长、重复或与内置名称冲突。'; return;
  }
  const custom = props.customGroups.some(group => group.name === original);
  emit('rename-group', original, name);
  if (custom) selectedTarget.value = name;
  cancelGroupName();
}
defineExpose({ hasPending });

watch(() => props.rules, value => {
  if (value === expectedRules) { expectedRules = undefined; return; }
  expectedRules = undefined; selectedLines.value = []; lastChange.value = null; notice.value = ''; cancelLine();
});
watch(filterTargets, targets => { if (selectedTarget.value && !targets.includes(selectedTarget.value)) selectedTarget.value = ''; });
watch(() => props.targets, targets => {
  if (!editingExisting.value && !hasPending.value && !targets.includes(lineForm.target)) lineForm.target = targets[0] ?? 'PROXY';
  if (!targets.includes(bulkTarget.value)) bulkTarget.value = '';
});
watch(selectedTarget, target => {
  if (!editingExisting.value && !hasPending.value && target && props.targets.includes(target)) lineForm.target = target;
});

function clearFilters() {
  Object.assign(filters, { query: '', kind: '', resolution: '', selectedOnly: false });
}
function chooseGroup(target: string) {
  if (editingGroupName.value && target !== selectedTarget.value) {
    if (!window.confirm('分组名称尚未保存，切换后会丢失，继续？')) return;
    cancelGroupName();
  }
  selectedTarget.value = target;
  if (window.matchMedia('(max-width: 1000px), (max-width: 1100px) and (max-height: 500px)').matches) {
    groupPickerOpen.value = false;
    void nextTick(() => ruleHeading.value?.scrollIntoView({ block: 'start' }));
  }
}
function openGroups() {
  groupPickerOpen.value = true;
  void nextTick(() => groupPicker.value?.scrollIntoView({ block: 'start' }));
}
function reorderGroup(source: string, target: string, after: boolean) {
  if (props.busy) return;
  const values = [...filterTargets.value];
  const from = values.indexOf(source); const position = values.indexOf(target);
  if (from < 0 || position < 0 || from === position) return;
  const boundary = position + (after ? 1 : 0);
  const to = boundary - (from < boundary ? 1 : 0);
  if (to === from) return;
  const [item] = values.splice(from, 1); if (item === undefined) return;
  values.splice(to, 0, item);
  const inactive = props.groupOrder.filter(name => !values.includes(name));
  emit('update:group-order', [...values, ...inactive]);
}
function reorderRule(from: number, target: number, after: boolean) {
  if (hasPending.value || props.busy) return;
  const move = moveRule(props.rules, from, target, after); if (!move) return;
  writeRules(move.text, '已调整规则的匹配顺序。');
  selectedLines.value = selectedLines.value.map(index => movedRuleIndex(index, move));
  if (editLine.value !== null) editLine.value = movedRuleIndex(editLine.value, move);
}
function moveAdjacent(kind: 'rule' | 'group', source: string, direction: -1 | 1) {
  const values = kind === 'rule' ? visibleRules.value.map(line => String(line.index)) : filterTargets.value;
  const index = values.indexOf(source); const target = values[index + direction];
  if (index < 0 || target === undefined) return;
  if (kind === 'rule') reorderRule(Number(source), Number(target), direction > 0);
  else reorderGroup(source, target, direction > 0);
}
function startDrag(event: PointerEvent, kind: 'rule' | 'group', source: string) {
  if (props.busy || (kind === 'rule' && hasPending.value) || event.button !== 0) return;
  event.preventDefault(); event.stopPropagation();
  (event.currentTarget as HTMLElement).setPointerCapture(event.pointerId);
  drag.value = { kind, source, target: source, after: false, pointer: event.pointerId, startY: event.clientY, active: false };
}
function updateDrag(event: PointerEvent) {
  const current = drag.value; if (!current || current.pointer !== event.pointerId) return;
  if (!current.active && Math.abs(event.clientY - current.startY) < 5) return;
  current.active = true;
  const selector = current.kind === 'rule' ? '[data-rule-index]' : '[data-group-name]';
  const item = document.elementFromPoint(event.clientX, event.clientY)?.closest<HTMLElement>(selector);
  const target = current.kind === 'rule' ? item?.dataset.ruleIndex : item?.dataset.groupName;
  if (!item || target === undefined) return;
  current.target = target; current.after = event.clientY >= item.getBoundingClientRect().top + item.getBoundingClientRect().height / 2;
  const list = current.kind === 'rule' ? item.closest<HTMLElement>('.rules-table') : item.closest<HTMLElement>('.group-picker-items');
  if (list) {
    const rect = list.getBoundingClientRect();
    if (event.clientY < rect.top + 30) list.scrollBy(0, -12);
    else if (event.clientY > rect.bottom - 30) list.scrollBy(0, 12);
  }
}
function endDrag(event: PointerEvent, cancel = false) {
  const current = drag.value; if (!current || current.pointer !== event.pointerId) return;
  drag.value = null;
  if (cancel || !current.active) return;
  if (current.kind === 'rule') reorderRule(Number(current.source), Number(current.target), current.after);
  else reorderGroup(current.source, current.target, current.after);
}
function setGroupDefault(value: string) {
  const defaults = { ...props.groupDefaults };
  if (value) defaults[selectedTarget.value] = value; else delete defaults[selectedTarget.value];
  emit('update:group-defaults', defaults);
}
function cancelLine() {
  editLine.value = null; editSystem.value = null; editSnapshot.value = null; lineForm.value = ''; lineForm.option = ''; error.value = '';
  lineForm.target = props.targets.includes(selectedTarget.value) ? selectedTarget.value : 'PROXY';
}
function showEditorOnCompactScreen() {
  if (window.matchMedia('(max-width: 1000px), (max-width: 1100px) and (max-height: 500px)').matches) {
    void nextTick(() => ruleEditor.value?.scrollIntoView({ block: 'start' }));
  }
}
function startLine(line: RuleLine) {
  if (editingGroupName.value) { groupNameError.value = '请先确定或取消分组名称。'; return; }
  if (!line.fields) return;
  if (editLine.value === line.index) { showEditorOnCompactScreen(); return; }
  if (hasPending.value && !window.confirm('当前规则尚未添加或更新，切换后会丢失，继续？')) return;
  editSystem.value = null;
  const [kind, value, target, option] = line.fields;
  lineForm.kind = kind ?? 'DOMAIN-SUFFIX'; lineForm.value = value ?? '';
  lineForm.target = target ?? 'PROXY'; lineForm.option = option ?? '';
  editLine.value = line.index; editSnapshot.value = currentValues(); error.value = '';
  showEditorOnCompactScreen();
}
function startSystem(rule: SystemRule) {
  if (editingGroupName.value) { groupNameError.value = '请先确定或取消分组名称。'; return; }
  if (!rule.id) return;
  if (editSystem.value === rule.id) { showEditorOnCompactScreen(); return; }
  if (hasPending.value && !window.confirm('当前规则尚未添加或更新，切换后会丢失，继续？')) return;
  editLine.value = null; editSystem.value = rule.id;
  lineForm.kind = rule.kind; lineForm.value = rule.value; lineForm.target = rule.target; lineForm.option = rule.option;
  editSnapshot.value = currentValues(); error.value = ''; showEditorOnCompactScreen();
}
function writeRules(value: string, message: string) {
  if (value === props.rules) { lastChange.value = null; notice.value = '规则内容没有变化。'; return; }
  lastChange.value = { type: 'rules', before: props.rules, after: value };
  notice.value = message; expectedRules = value; emit('update:rules', value);
}
function copySystem(values: SystemOverrides): SystemOverrides {
  return Object.fromEntries(Object.entries(values).map(([id, value]) => [id, value ? { ...value } : null]));
}
function writeSystem(values: SystemOverrides, message: string) {
  const before = copySystem(props.systemOverrides); const after = copySystem(values);
  if (JSON.stringify(before) === JSON.stringify(after)) { lastChange.value = null; notice.value = '规则内容没有变化。'; return; }
  lastChange.value = { type: 'system', before, after };
  notice.value = message; emit('update:system-overrides', after);
}
function setSystemRule(id: string, value: SystemRuleOverride | undefined, message: string) {
  const original = props.systemRules.find(rule => rule.id === id);
  if (!original) return;
  const next = copySystem(props.systemOverrides);
  if (value === undefined || value !== null && value.kind === original.kind && value.value === original.value && value.target === original.target && value.option === original.option) delete next[id];
  else next[id] = value;
  writeSystem(next, message);
}
function changeSystemTarget(rule: SystemRule, event: Event) {
  const input = event.target as HTMLSelectElement;
  if (!rule.id || input.value === rule.target) return;
  if (hasPending.value || !systemTargets.value.includes(input.value)) { input.value = rule.target; return; }
  const value = { kind: rule.kind, value: rule.value, target: input.value, option: rule.option };
  setSystemRule(rule.id, value, `已更改系统规则 ${rule.value} 的分流去向。`);
  if (editSystem.value === rule.id && editSnapshot.value) {
    lineForm.target = input.value; editSnapshot.value = { ...editSnapshot.value, target: input.value };
  }
}
function restoreSystem(id?: string) {
  if (hasPending.value) { error.value = '请先完成正在编辑的规则。'; return; }
  if (id) setSystemRule(id, undefined, '已恢复该系统规则的默认内容。');
  else writeSystem({}, '已恢复全部系统规则的默认内容。');
  cancelLine();
}
function disableSystem(rule: SystemRule) {
  if (!rule.id || rule.kind === 'MATCH' || hasPending.value) return;
  setSystemRule(rule.id, null, `已停用系统规则 ${rule.value}。`); cancelLine();
}
function undoChange() {
  const change = lastChange.value;
  if (!change || hasPending.value) return;
  if (change.type === 'rules') {
    if (props.rules !== change.after) return;
    expectedRules = change.before; emit('update:rules', change.before);
  } else {
    if (JSON.stringify(copySystem(props.systemOverrides)) !== JSON.stringify(change.after)) return;
    emit('update:system-overrides', copySystem(change.before));
  }
  lastChange.value = null; notice.value = '已撤销上一步修改。'; selectedLines.value = []; bulkTarget.value = ''; cancelLine();
}
function changeLineTarget(line: RuleLine, event: Event) {
  const input = event.target as HTMLSelectElement;
  const previous = line.fields?.[2];
  if (!previous || input.value === previous) return;
  if (hasPending.value || !props.targets.includes(input.value)) { input.value = previous; return; }
  const target = input.value;
  writeRules(changeSelectedRules(props.rules, new Set([line.index]), { type: 'target', target }),
    `已更改 ${line.fields?.[1]} 的分流去向。`);
  if (editLine.value === line.index && editSnapshot.value) {
    lineForm.target = target; editSnapshot.value = { ...editSnapshot.value, target };
  }
}
function saveLine() {
  const value = lineForm.value.trim();
  if (!value || /[\r\n]/.test(value) || (value.includes(',') && !(editSystem.value && lineForm.kind === 'AND'))) { error.value = '请填写有效的规则内容，不能包含换行。'; return; }
  if (editSystem.value) {
    if (![...ruleKinds, 'GEOSITE', 'MATCH', 'AND'].includes(lineForm.kind) || !systemTargets.value.includes(lineForm.target)) { error.value = '请选择当前模板支持的规则类型和分流去向。'; return; }
    if (!resolutionKinds.includes(lineForm.kind)) lineForm.option = '';
    setSystemRule(editSystem.value, { kind: lineForm.kind, value, target: lineForm.target, option: lineForm.option }, `已更新系统规则 ${value}。`);
    lineForm.value = value; editSnapshot.value = currentValues(); error.value = ''; return;
  }
  if (!ruleKinds.includes(lineForm.kind) || !props.targets.includes(lineForm.target)) { error.value = '请选择当前模板支持的规则类型和目标分组。'; return; }
  const parts = [lineForm.kind, value, lineForm.target];
  if (lineForm.option && resolutionKinds.includes(lineForm.kind)) parts.push(lineForm.option);
  let next: string;
  if (editLine.value !== null) {
    const rows = props.rules.split('\n');
    if (editLine.value >= rows.length) { error.value = '规则已变化，请重新选择。'; return; }
    rows[editLine.value] = parts.join(',') + (rows[editLine.value]?.endsWith('\r') ? '\r' : '');
    next = rows.join('\n');
  } else {
    const newline = props.rules.includes('\r\n') ? '\r\n' : '\n';
    next = lineForm.position === 'start' ? parts.join(',') + newline + props.rules :
      props.rules + (props.rules && !props.rules.endsWith('\n') ? newline : '') + parts.join(',') + newline;
  }
  const editing = editLine.value !== null;
  writeRules(next, editing ? `已更新规则 ${value}。` : `已添加规则 ${value}。`);
  if (editing) {
    lineForm.value = value;
    if (!resolutionKinds.includes(lineForm.kind)) lineForm.option = '';
    editSnapshot.value = currentValues(); error.value = '';
  } else cancelLine();
}
function toggleVisible(event: Event) {
  selectedLines.value = selectVisibleRules(selectedLines.value, visibleLines.value, (event.target as HTMLInputElement).checked);
}
function bulk(action: 'delete' | 'target') {
  if (!selectedLines.value.length) return;
  if (hasPending.value) { error.value = '请先添加、更新或取消正在编辑的规则。'; return; }
  if (action === 'target' && !props.targets.includes(bulkTarget.value)) { error.value = '请选择当前模板支持的目标分组。'; return; }
  const count = selectedLines.value.length;
  const target = bulkTarget.value;
  writeRules(changeSelectedRules(props.rules, selectedSet.value,
    action === 'delete' ? { type: 'delete' } : { type: 'target', target }),
    action === 'delete' ? `已删除 ${count} 条规则。` : `已将 ${count} 条规则的去向改为 ${target}。`);
  selectedLines.value = []; bulkTarget.value = ''; cancelLine();
}
function updateRaw(event: Event) {
  expectedRules = remapRuleTargets((event.target as HTMLTextAreaElement).value, reverseNames.value);
  emit('update:rules', expectedRules);
  lastChange.value = null; notice.value = '';
  selectedLines.value = []; cancelLine();
}
function openRaw(event: MouseEvent) {
  const details = (event.currentTarget as HTMLElement).parentElement;
  if (details?.hasAttribute('open') || !hasPending.value) return;
  if (!window.confirm('当前规则尚未添加或更新，打开文本编辑会丢失这些输入，继续？')) { event.preventDefault(); return; }
  cancelLine();
}
</script>

<template>
  <div class="rule-workspace">
    <div class="rule-global-filters" role="search" aria-label="规则全局筛选">
      <div class="rule-filters-heading"><div><h4>全局筛选</h4><p>筛选条件与所选分组同时生效。</p></div><button type="button" :disabled="!globalFiltersActive" @click="clearFilters">清除筛选</button></div>
      <div class="rule-filters">
        <label class="rule-search">搜索<input v-model="filters.query" type="search" placeholder="搜索内容、类型或目标"></label>
        <label>规则类型<select v-model="filters.kind"><option value="">全部类型</option><option v-for="kind in filterKinds" :key="kind">{{ kind }}</option></select></label>
        <label>IP 解析<select v-model="filters.resolution"><option value="">全部</option><option value="default">默认</option><option value="resolve">resolve</option><option value="no-resolve">no-resolve</option></select></label>
        <label class="checkbox filter-selected"><input v-model="filters.selectedOnly" type="checkbox">只看已选</label>
      </div>
    </div>
    <nav ref="groupPicker" class="group-picker" aria-label="查看分组规则">
      <div class="group-picker-heading"><h4>查看分组</h4><span>匹配数量</span></div>
      <button class="mobile-group-picker-toggle" type="button" :aria-expanded="groupPickerOpen" aria-controls="rule-groups" @click="groupPickerOpen = !groupPickerOpen"><span>查看分组</span><strong>{{ selectedTarget ? displayTarget(selectedTarget) : '全部分组' }}</strong><span aria-hidden="true">{{ groupPickerOpen ? '▴' : '▾' }}</span></button>
      <div id="rule-groups" class="group-picker-items" :class="{ 'is-open': groupPickerOpen }">
        <button type="button" :class="{ active: !selectedTarget }" :aria-pressed="!selectedTarget" @click="chooseGroup('')"><span>全部分组</span><span>{{ groupCounts.total }}</span></button>
        <div v-for="target in filterTargets" :key="target" class="group-picker-item" :data-group-name="target" :class="{ 'drag-before': drag?.kind === 'group' && drag.active && drag.target === target && !drag.after, 'drag-after': drag?.kind === 'group' && drag.active && drag.target === target && drag.after }">
          <button class="drag-handle" type="button" :disabled="busy" :aria-label="'调整分组顺序 ' + displayTarget(target)" title="拖动调整顺序；也可使用上下方向键" @pointerdown="startDrag($event, 'group', target)" @pointermove="updateDrag" @pointerup="endDrag($event)" @pointercancel="endDrag($event, true)" @keydown.up.prevent="moveAdjacent('group', target, -1)" @keydown.down.prevent="moveAdjacent('group', target, 1)"><span aria-hidden="true">⋮⋮</span></button>
          <button type="button" :class="{ active: selectedTarget === target }" :aria-pressed="selectedTarget === target" @click="chooseGroup(target)"><span>{{ displayTarget(target) }}</span><span>{{ groupCounts.counts.get(target) ?? 0 }}</span></button>
        </div>
      </div>
      <p v-if="orphanedDefaults.length" class="group-default-warning">{{ orphanedDefaults.length }} 个分组不属于当前基础模板，请选择后移除其默认出口。</p>
    </nav>
    <div class="rule-list-pane">
      <div ref="ruleHeading" class="subheading rule-list-heading">
        <div><h4>{{ selectedTarget ? displayTarget(selectedTarget) : '全部分组' }} · 规则列表</h4><p>模板规则 {{ visibleRules.length }} 条<template v-if="systemRulesAvailable"> · 系统规则 {{ visibleSystemRules.length }} 条</template> · 点击规则编辑，去向可直接修改</p></div>
        <button class="mobile-group-return" type="button" @click="openGroups">切换分组</button>
      </div>
      <div class="rule-filter-footer">
        <span v-if="systemRulesAvailable">模板规则可拖动调整顺序；系统规则保持原顺序，可编辑或恢复默认。</span>
        <span v-else class="system-warning">系统规则暂不可用，请刷新页面或检查面板版本。</span>
        <span v-if="filterActive">筛选时拖动会跨过隐藏的模板规则。</span>
        <button v-if="Object.keys(systemOverrides).length" type="button" :disabled="busy || hasPending" @click="restoreSystem()">恢复全部系统规则默认</button>
      </div>
      <p v-if="orphanedSystem.length" class="group-default-warning">{{ orphanedSystem.length }} 条系统规则修改不属于当前基础模板，请恢复系统规则默认后重新编辑。</p>
      <div class="bulk-actions">
        <label class="checkbox"><input type="checkbox" :checked="allChecked" :indeterminate.prop="someChecked" :disabled="busy || !visibleRules.length" @change="toggleVisible">全选当前结果</label>
        <template v-if="selectedLines.length">
          <span>已选择 {{ selectedLines.length }} 条<template v-if="hiddenSelected">（{{ hiddenSelected }} 条在筛选结果外）</template></span>
          <button type="button" :disabled="busy" @click="selectedLines = []; bulkTarget = ''">取消选择</button>
          <label class="bulk-target">更改去向<select v-model="bulkTarget" aria-label="批量更改分流去向" :disabled="busy || hasPending"><option value="" disabled>选择去向</option><option v-for="target in targets" :key="target" :value="target">{{ targetLabel(target) }}</option></select></label>
          <button type="button" :disabled="busy || hasPending || !bulkTarget" @click="bulk('target')">应用</button>
          <button type="button" :disabled="busy || hasPending" @click="bulk('delete')">删除已选</button>
        </template>
      </div>
      <div v-if="notice" class="rule-change-notice" role="status"><span>{{ notice }}</span><button v-if="lastChange" type="button" :disabled="busy || hasPending" @click="undoChange">撤销</button></div>
      <div class="rules-table" tabindex="0" role="region" aria-label="规则列表">
        <table><thead><tr><th></th><th>类型</th><th>内容</th><th>分流去向</th><th>解析</th></tr></thead><tbody>
          <template v-for="row in displayRows" :key="row.key">
          <tr v-if="row.type === 'heading'" class="system-rules-heading"><td colspan="5">{{ row.label }} · 顺序固定</td></tr>
          <tr v-else-if="row.type === 'system'" class="system-rule" :class="{ 'editing-rule': editSystem === row.rule.id, 'system-disabled': row.rule.disabled, 'editable-rule': row.rule.id }" @click="!busy && startSystem(row.rule)">
            <td aria-hidden="true">—</td><td class="rule-type">{{ row.rule.kind }}</td>
            <td class="rule-content"><button v-if="row.rule.id" class="rule-open" type="button" :disabled="busy" :aria-label="'编辑系统规则 ' + row.rule.value" :aria-current="editSystem === row.rule.id ? 'true' : undefined" @click.stop="startSystem(row.rule)">{{ row.rule.value }}<span class="mobile-rule-details">{{ row.rule.kind }}<template v-if="row.rule.option"> · {{ row.rule.option }}</template></span></button><template v-else>{{ row.rule.value }}</template></td>
            <td class="rule-target"><select v-if="row.rule.id && !row.rule.disabled" :value="row.rule.target" :disabled="busy || hasPending" :aria-label="'更改系统规则 ' + row.rule.value + ' 的分流去向'" @click.stop @change="changeSystemTarget(row.rule, $event)"><option v-if="!systemTargets.includes(row.rule.target)" :value="row.rule.target" disabled>{{ displayTarget(row.rule.target) }}（不可用）</option><option v-for="target in systemTargets" :key="target" :value="target">{{ targetLabel(target) }}</option></select><span v-else>{{ displayTarget(row.rule.target) }}</span> <span class="system-rule-tag">{{ row.rule.disabled ? '已停用' : row.rule.modified ? '已修改' : '系统' }}</span></td><td class="rule-resolution">{{ row.rule.option || '默认' }}</td>
          </tr>
          <template v-else>
          <tr v-for="line in [row.line]" :key="line.index" :data-rule-index="line.fields ? String(line.index) : undefined" :class="{ 'editing-rule': editLine === line.index, 'editable-rule': line.fields, 'drag-before': drag?.kind === 'rule' && drag.active && drag.target === String(line.index) && !drag.after, 'drag-after': drag?.kind === 'rule' && drag.active && drag.target === String(line.index) && drag.after }" @click="line.fields && !busy && startLine(line)">
            <td class="rule-select"><div v-if="line.fields" class="rule-select-controls"><button class="drag-handle" type="button" :disabled="busy || hasPending" :aria-label="'调整规则顺序 ' + line.fields[1]" title="拖动调整匹配顺序；也可使用上下方向键" @click.stop @pointerdown="startDrag($event, 'rule', String(line.index))" @pointermove="updateDrag" @pointerup="endDrag($event)" @pointercancel="endDrag($event, true)" @keydown.up.prevent="moveAdjacent('rule', String(line.index), -1)" @keydown.down.prevent="moveAdjacent('rule', String(line.index), 1)"><span aria-hidden="true">⋮⋮</span></button><input v-model="selectedLines" type="checkbox" :value="line.index" :disabled="busy" :aria-label="'批量选择 ' + line.fields[1]" @click.stop></div></td>
            <template v-if="line.fields">
              <td class="rule-type">{{ line.fields[0] }}</td>
              <td class="rule-content"><button class="rule-open" type="button" :disabled="busy" :aria-label="'编辑规则 ' + line.fields[1]" :aria-current="editLine === line.index ? 'true' : undefined" @click.stop="startLine(line)">{{ line.fields[1] }}<span class="mobile-rule-details">{{ line.fields[0] }}<template v-if="line.fields[3]"> · {{ line.fields[3] }}</template></span></button></td>
              <td class="rule-target"><select :value="line.fields[2]" :disabled="busy || hasPending" :title="hasPending ? '请先完成正在编辑的规则' : '直接更改分流去向'" :aria-label="'更改 ' + line.fields[1] + ' 的分流去向'" @click.stop @change="changeLineTarget(line, $event)"><option v-if="!targets.includes(line.fields[2] ?? '')" :value="line.fields[2]" disabled>{{ displayTarget(line.fields[2] ?? '') }}（不可用）</option><option v-for="target in targets" :key="target" :value="target">{{ targetLabel(target) }}</option></select></td>
              <td class="rule-resolution">{{ line.fields[3] ?? '默认' }}</td>
            </template>
            <td v-else colspan="4" class="rule-comment">{{ line.text }}</td>
          </tr>
          </template>
          </template>
          <tr v-if="!visibleLines.length && !visibleSystemRules.length"><td colspan="5" class="rule-empty">{{ filterActive ? '没有匹配的规则，请调整全局筛选或切换分组。' : '暂无规则，可在编辑区添加。' }}</td></tr>
        </tbody></table>
      </div>
      <details class="raw-rules"><summary @click="openRaw">编辑规则文本</summary><textarea :value="displayRules" rows="8" spellcheck="false" aria-label="规则文本" :disabled="busy || hasPending" @input="updateRaw"></textarea><p v-if="hasPending">请先完成或取消当前规则编辑。</p></details>
    </div>
    <aside class="rule-side" aria-label="分组与规则编辑">
    <div v-if="selectedTarget" class="group-settings-pane">
      <h4>分组设置</h4><p class="group-settings-name">{{ displayTarget(selectedTarget) }}</p>
      <div v-if="!['DIRECT', 'REJECT'].includes(selectedTarget)" class="group-name-editor">
        <template v-if="editingGroupName"><label>分组名称<input v-model="groupNameDraft" maxlength="64" :disabled="busy" @keydown.enter.prevent="saveGroupName" @keydown.esc.prevent="cancelGroupName"></label><div class="group-name-actions"><button type="button" :disabled="busy" @click="saveGroupName">确定名称</button><button type="button" :disabled="busy" @click="cancelGroupName">取消</button></div><p v-if="groupNameError" class="message" role="alert">{{ groupNameError }}</p></template>
        <template v-else><button type="button" :disabled="busy || rulePending" @click="beginGroupName">修改名称</button><button v-if="groupNames[selectedTarget]" type="button" :disabled="busy || rulePending" @click="$emit('rename-group', selectedTarget, selectedTarget)">恢复默认名称</button></template>
      </div>
      <template v-if="groupDescriptor">
        <label>默认出口<select :value="selectedDefault" :disabled="busy || !groupOutboundsAvailable" @change="setGroupDefault(($event.target as HTMLSelectElement).value)">
          <option value="">沿用原有默认：{{ outboundLabel(inheritedDefault, groupDescriptor.options) }}</option>
          <option v-if="defaultUnavailable" :value="selectedDefault" disabled>{{ outboundLabel(selectedDefault, groupDescriptor.options) }}</option>
          <option v-for="option in groupDescriptor.options.filter(option => !option.label.endsWith('（旧默认）') || option.value === selectedDefault)" :key="option.value" :value="option.value">{{ option.label }}</option>
        </select></label>
        <p>保存并发布后生效；客户端可能保留手动选择。节点按用户授权校验。</p>
      </template>
      <p v-else-if="!groupOutboundsAvailable">当前无法获取可用出口，请稍后刷新。</p>
      <template v-else-if="selectedDefault"><p>此分组不属于当前基础模板。</p><button type="button" :disabled="busy" @click="setGroupDefault('')">移除默认出口设置</button></template>
      <p v-else-if="selectedTarget === 'oracle-cloud'">系统分组固定直连。</p>
      <p v-else>这是规则动作，没有默认出口。</p>
    </div>
    <div ref="ruleEditor" class="rule-editor-pane" aria-label="规则编辑">
      <div><h4>{{ editSystem ? '编辑系统规则' : editLine === null ? '添加规则' : '编辑规则' }}</h4><p v-if="editingExisting">{{ editSnapshot?.value }}<template v-if="!editVisible"> · 不在当前筛选结果中</template></p><p v-else-if="selectedTarget && !targets.includes(selectedTarget)">此分组由系统维护，新增规则请选择可编辑目标。</p><p v-else>选择类型和去向后添加，或点击列表中的规则编辑。</p></div>
      <label>规则类型<select v-model="lineForm.kind" :disabled="busy || editingGroupName || Boolean(editSystem && ['AND', 'MATCH'].includes(editingSystemOriginal?.kind ?? ''))"><option v-for="kind in editSystem ? [...ruleKinds, 'GEOSITE', 'MATCH', 'AND'] : ruleKinds" :key="kind">{{ kind }}</option></select></label>
      <label>匹配内容<input v-model="lineForm.value" placeholder="域名、网段或端口" :disabled="busy || editingGroupName || Boolean(editSystem && ['AND', 'MATCH'].includes(lineForm.kind))"></label>
      <p v-if="editSystem && lineForm.kind === 'GEOSITE'" class="system-rule-hint">小火箭通过地域规则集转换，规则数据可能与 Clash 略有差异。</p>
      <label>分流去向<select v-model="lineForm.target" :disabled="busy || editingGroupName">
        <option v-if="!(editSystem ? systemTargets : targets).includes(lineForm.target)" :value="lineForm.target" disabled>{{ displayTarget(lineForm.target) }}（当前模板不可用）</option>
        <option v-for="target in editSystem ? systemTargets : targets" :key="target" :value="target">{{ targetLabel(target) }}</option>
      </select></label>
      <label v-if="resolutionKinds.includes(lineForm.kind)">IP 解析<select v-model="lineForm.option" :disabled="busy"><option value="">默认</option><option value="resolve">resolve</option><option value="no-resolve">no-resolve</option></select></label>
      <label v-if="!editingExisting">添加位置<select v-model="lineForm.position" :disabled="busy"><option value="end">模板末尾</option><option value="start">模板最前（优先匹配）</option></select></label>
      <p v-if="error" class="message" role="alert">{{ error }}</p>
      <div class="rule-editor-actions"><button class="primary" type="button" :disabled="busy || editingGroupName || (editingExisting && !rulePending)" @click="saveLine">{{ editingExisting ? '更新规则' : '添加规则' }}</button><button v-if="editingExisting || rulePending" type="button" :disabled="busy || editingGroupName" @click="cancelLine">{{ rulePending ? '取消修改' : '添加新规则' }}</button><button v-if="editSystem && editSystem in systemOverrides" type="button" :disabled="busy || hasPending" @click="restoreSystem(editSystem)">恢复此规则默认</button><button v-if="editSystem && editingSystemOriginal?.kind !== 'MATCH' && systemOverrides[editSystem] !== null" type="button" :disabled="busy || hasPending" @click="disableSystem(editingSystemOriginal!)">停用规则</button></div>
    </div>
    </aside>
  </div>
</template>
