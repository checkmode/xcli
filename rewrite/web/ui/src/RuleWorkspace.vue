<script setup lang="ts">
import { computed, nextTick, reactive, ref, watch } from 'vue';
import { changeSelectedRules, countRulesByTarget, filterRuleLines, filterSystemRules, parseRuleLines, resolutionKinds, ruleKinds, selectVisibleRules, type RuleLine, type SystemRule } from './rule-list';
import { inheritedGroupDefault, outboundLabel, type CustomGroup, type GroupOutbounds } from './group-defaults';

const props = defineProps<{ rules: string; targets: string[]; systemRules: SystemRule[]; systemRulesAvailable: boolean;
  groupOutbounds: GroupOutbounds; groupOutboundsAvailable: boolean; groupDefaults: Record<string, string>; customGroups: CustomGroup[]; legacyAi: string; busy: boolean }>();
const emit = defineEmits<{ 'update:rules': [value: string]; 'update:group-defaults': [value: Record<string, string>] }>();
const filters = reactive({ query: '', kind: '', resolution: '', selectedOnly: false });
const selectedTarget = ref('');
const groupPickerOpen = ref(false);
const selectedLines = ref<number[]>([]);
const editLine = ref<number | null>(null);
const ruleEditor = ref<HTMLElement | null>(null);
const ruleHeading = ref<HTMLElement | null>(null);
const groupPicker = ref<HTMLElement | null>(null);
const lineForm = reactive({ kind: 'DOMAIN-SUFFIX', value: '', target: 'PROXY', option: '', position: 'end' });
type RuleValues = { kind: string; value: string; target: string; option: string };
const editSnapshot = ref<RuleValues | null>(null);
const lastChange = ref<{ before: string; after: string } | null>(null);
const notice = ref('');
const bulkTarget = ref('');
const error = ref('');
let expectedRules: string | undefined;

const lines = computed(() => parseRuleLines(props.rules));
const selectedSet = computed(() => new Set(selectedLines.value));
const effectiveFilters = computed(() => ({ ...filters, target: selectedTarget.value }));
const visibleLines = computed(() => filterRuleLines(lines.value, effectiveFilters.value, selectedSet.value));
const visibleSystemRules = computed(() => filterSystemRules(props.systemRules, effectiveFilters.value));
const visibleRules = computed(() => visibleLines.value.filter(line => line.fields));
const visibleSelected = computed(() => visibleRules.value.filter(line => selectedSet.value.has(line.index)).length);
const hiddenSelected = computed(() => selectedLines.value.length - visibleSelected.value);
const editVisible = computed(() => editLine.value === null || visibleRules.value.some(line => line.index === editLine.value));
const allChecked = computed(() => visibleRules.value.length > 0 && visibleSelected.value === visibleRules.value.length);
const someChecked = computed(() => visibleSelected.value > 0 && !allChecked.value);
const globalFiltersActive = computed(() => Boolean(filters.query.trim() || filters.kind || filters.resolution || filters.selectedOnly));
const filterActive = computed(() => Boolean(globalFiltersActive.value || selectedTarget.value));
const filterTargets = computed(() => [...new Set([...props.targets, ...Object.keys(props.groupDefaults), ...props.systemRules.map(rule => rule.target), ...lines.value.flatMap(line => line.fields?.[2] ? [line.fields[2]] : [])])]);
const filterKinds = computed(() => [...new Set([...ruleKinds, ...props.systemRules.map(rule => rule.kind)])]);
const groupCounts = computed(() => countRulesByTarget(lines.value, props.systemRules, effectiveFilters.value, selectedSet.value));
const groupDescriptor = computed(() => props.groupOutbounds[selectedTarget.value] ??
  (props.customGroups.some(group => group.name === selectedTarget.value) ? props.groupOutbounds.__custom__ : undefined));
const inheritedDefault = computed(() => groupDescriptor.value ? inheritedGroupDefault(selectedTarget.value, props.legacyAi, props.customGroups, groupDescriptor.value) : null);
const selectedDefault = computed(() => props.groupDefaults[selectedTarget.value] ?? '');
const defaultUnavailable = computed(() => Boolean(selectedDefault.value && groupDescriptor.value && !groupDescriptor.value.options.some(option => option.value === selectedDefault.value)));
const orphanedDefaults = computed(() => props.groupOutboundsAvailable ? Object.keys(props.groupDefaults).filter(group =>
  !props.groupOutbounds[group] && !props.customGroups.some(item => item.name === group)) : []);
function currentValues(): RuleValues {
  return { kind: lineForm.kind, value: lineForm.value, target: lineForm.target, option: lineForm.option };
}
const hasPending = computed(() => editLine.value === null ? Boolean(lineForm.value.trim()) :
  JSON.stringify(currentValues()) !== JSON.stringify(editSnapshot.value));
defineExpose({ hasPending });

watch(() => props.rules, value => {
  if (value === expectedRules) { expectedRules = undefined; return; }
  expectedRules = undefined; selectedLines.value = []; lastChange.value = null; notice.value = ''; cancelLine();
});
watch(filterTargets, targets => { if (selectedTarget.value && !targets.includes(selectedTarget.value)) selectedTarget.value = ''; });
watch(() => props.targets, targets => {
  if (editLine.value === null && !hasPending.value && !targets.includes(lineForm.target)) lineForm.target = targets[0] ?? 'PROXY';
  if (!targets.includes(bulkTarget.value)) bulkTarget.value = '';
});
watch(selectedTarget, target => {
  if (editLine.value === null && !hasPending.value && target && props.targets.includes(target)) lineForm.target = target;
});

function clearFilters() {
  Object.assign(filters, { query: '', kind: '', resolution: '', selectedOnly: false });
}
function chooseGroup(target: string) {
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
function setGroupDefault(value: string) {
  const defaults = { ...props.groupDefaults };
  if (value) defaults[selectedTarget.value] = value; else delete defaults[selectedTarget.value];
  emit('update:group-defaults', defaults);
}
function cancelLine() {
  editLine.value = null; editSnapshot.value = null; lineForm.value = ''; lineForm.option = ''; error.value = '';
  lineForm.target = props.targets.includes(selectedTarget.value) ? selectedTarget.value : 'PROXY';
}
function showEditorOnCompactScreen() {
  if (window.matchMedia('(max-width: 1000px), (max-width: 1100px) and (max-height: 500px)').matches) {
    void nextTick(() => ruleEditor.value?.scrollIntoView({ block: 'start' }));
  }
}
function startLine(line: RuleLine) {
  if (!line.fields) return;
  if (editLine.value === line.index) { showEditorOnCompactScreen(); return; }
  if (hasPending.value && !window.confirm('当前规则尚未添加或更新，切换后会丢失，继续？')) return;
  const [kind, value, target, option] = line.fields;
  lineForm.kind = kind ?? 'DOMAIN-SUFFIX'; lineForm.value = value ?? '';
  lineForm.target = target ?? 'PROXY'; lineForm.option = option ?? '';
  editLine.value = line.index; editSnapshot.value = currentValues(); error.value = '';
  showEditorOnCompactScreen();
}
function writeRules(value: string, message: string) {
  if (value === props.rules) { lastChange.value = null; notice.value = '规则内容没有变化。'; return; }
  lastChange.value = { before: props.rules, after: value };
  notice.value = message; expectedRules = value; emit('update:rules', value);
}
function undoChange() {
  const change = lastChange.value;
  if (!change || props.rules !== change.after || hasPending.value) return;
  expectedRules = change.before; emit('update:rules', change.before);
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
  if (!value || value.includes(',') || /[\r\n]/.test(value)) { error.value = '请填写一条规则内容，不能包含逗号或换行。'; return; }
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
  expectedRules = (event.target as HTMLTextAreaElement).value;
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
      <button class="mobile-group-picker-toggle" type="button" :aria-expanded="groupPickerOpen" aria-controls="rule-groups" @click="groupPickerOpen = !groupPickerOpen"><span>查看分组</span><strong>{{ selectedTarget || '全部分组' }}</strong><span aria-hidden="true">{{ groupPickerOpen ? '▴' : '▾' }}</span></button>
      <div id="rule-groups" class="group-picker-items" :class="{ 'is-open': groupPickerOpen }">
        <button type="button" :class="{ active: !selectedTarget }" :aria-pressed="!selectedTarget" @click="chooseGroup('')"><span>全部分组</span><span>{{ groupCounts.total }}</span></button>
        <button v-for="target in filterTargets" :key="target" type="button" :class="{ active: selectedTarget === target }" :aria-pressed="selectedTarget === target" @click="chooseGroup(target)"><span>{{ target }}</span><span>{{ groupCounts.counts.get(target) ?? 0 }}</span></button>
      </div>
      <p v-if="orphanedDefaults.length" class="group-default-warning">{{ orphanedDefaults.length }} 个分组不属于当前基础模板，请选择后移除其默认出口。</p>
    </nav>
    <div class="rule-list-pane">
      <div ref="ruleHeading" class="subheading rule-list-heading">
        <div><h4>{{ selectedTarget || '全部分组' }} · 规则列表</h4><p>模板规则 {{ visibleRules.length }} 条<template v-if="systemRulesAvailable"> · 系统规则 {{ visibleSystemRules.length }} 条</template> · 点击规则编辑，去向可直接修改</p></div>
        <button class="mobile-group-return" type="button" @click="openGroups">切换分组</button>
      </div>
      <div class="rule-filter-footer">
        <span v-if="systemRulesAvailable">系统规则只读，实际匹配顺序和用户设置以客户端配置为准。</span>
        <span v-else class="system-warning">系统规则暂不可用，请刷新页面或检查面板版本。</span>
      </div>
      <div class="bulk-actions">
        <label class="checkbox"><input type="checkbox" :checked="allChecked" :indeterminate.prop="someChecked" :disabled="busy || !visibleRules.length" @change="toggleVisible">全选当前结果</label>
        <template v-if="selectedLines.length">
          <span>已选择 {{ selectedLines.length }} 条<template v-if="hiddenSelected">（{{ hiddenSelected }} 条在筛选结果外）</template></span>
          <button type="button" :disabled="busy" @click="selectedLines = []; bulkTarget = ''">取消选择</button>
          <label class="bulk-target">更改去向<select v-model="bulkTarget" aria-label="批量更改分流去向" :disabled="busy || hasPending"><option value="" disabled>选择去向</option><option v-for="target in targets" :key="target" :value="target">{{ target === 'DIRECT' ? 'DIRECT · 直连' : target === 'REJECT' ? 'REJECT · 拒绝' : target }}</option></select></label>
          <button type="button" :disabled="busy || hasPending || !bulkTarget" @click="bulk('target')">应用</button>
          <button type="button" :disabled="busy || hasPending" @click="bulk('delete')">删除已选</button>
        </template>
      </div>
      <div v-if="notice" class="rule-change-notice" role="status"><span>{{ notice }}</span><button v-if="lastChange" type="button" :disabled="busy || hasPending" @click="undoChange">撤销</button></div>
      <div class="rules-table" tabindex="0" role="region" aria-label="规则列表">
        <table><thead><tr><th></th><th>类型</th><th>内容</th><th>分流去向</th><th>解析</th></tr></thead><tbody>
          <tr v-for="line in visibleLines" :key="line.index" :class="{ 'editing-rule': editLine === line.index, 'editable-rule': line.fields }" @click="line.fields && !busy && startLine(line)">
            <td class="rule-select"><input v-if="line.fields" v-model="selectedLines" type="checkbox" :value="line.index" :disabled="busy" :aria-label="'批量选择 ' + line.fields[1]" @click.stop></td>
            <template v-if="line.fields">
              <td class="rule-type">{{ line.fields[0] }}</td>
              <td class="rule-content"><button class="rule-open" type="button" :disabled="busy" :aria-label="'编辑规则 ' + line.fields[1]" :aria-current="editLine === line.index ? 'true' : undefined" @click.stop="startLine(line)">{{ line.fields[1] }}<span class="mobile-rule-details">{{ line.fields[0] }}<template v-if="line.fields[3]"> · {{ line.fields[3] }}</template></span></button></td>
              <td class="rule-target"><select :value="line.fields[2]" :disabled="busy || hasPending" :title="hasPending ? '请先完成正在编辑的规则' : '直接更改分流去向'" :aria-label="'更改 ' + line.fields[1] + ' 的分流去向'" @click.stop @change="changeLineTarget(line, $event)"><option v-if="!targets.includes(line.fields[2] ?? '')" :value="line.fields[2]" disabled>{{ line.fields[2] }}（不可用）</option><option v-for="target in targets" :key="target" :value="target">{{ target === 'DIRECT' ? 'DIRECT · 直连' : target === 'REJECT' ? 'REJECT · 拒绝' : target }}</option></select></td>
              <td class="rule-resolution">{{ line.fields[3] ?? '默认' }}</td>
            </template>
            <td v-else colspan="4" class="rule-comment">{{ line.text }}</td>
          </tr>
          <tr v-if="visibleSystemRules.length" class="system-rules-heading"><td colspan="5">系统基础规则 · 只读</td></tr>
          <tr v-for="(line, index) in visibleSystemRules" :key="`system-${index}`" class="system-rule">
            <td aria-hidden="true">—</td><td class="rule-type">{{ line.kind }}</td>
            <td class="rule-content">{{ line.value }}<span class="mobile-rule-details">{{ line.kind }}<template v-if="line.option"> · {{ line.option }}</template></span></td>
            <td class="rule-target">{{ line.target }} <span class="system-rule-tag">系统</span></td><td class="rule-resolution">{{ line.option || '默认' }}</td>
          </tr>
          <tr v-if="!visibleLines.length && !visibleSystemRules.length"><td colspan="5" class="rule-empty">{{ filterActive ? '没有匹配的规则，请调整全局筛选或切换分组。' : '暂无规则，可在编辑区添加。' }}</td></tr>
        </tbody></table>
      </div>
      <details class="raw-rules"><summary @click="openRaw">编辑规则文本</summary><textarea :value="rules" rows="8" spellcheck="false" aria-label="规则文本" :disabled="busy || hasPending" @input="updateRaw"></textarea><p v-if="hasPending">请先完成或取消当前规则编辑。</p></details>
    </div>
    <aside class="rule-side" aria-label="分组与规则编辑">
    <div v-if="selectedTarget" class="group-settings-pane">
      <h4>分组设置</h4><p class="group-settings-name">{{ selectedTarget }}</p>
      <template v-if="groupDescriptor">
        <label>默认出口<select :value="selectedDefault" :disabled="busy || !groupOutboundsAvailable" @change="setGroupDefault(($event.target as HTMLSelectElement).value)">
          <option value="">沿用原有默认：{{ outboundLabel(inheritedDefault, groupDescriptor.options) }}</option>
          <option v-if="defaultUnavailable" :value="selectedDefault" disabled>{{ outboundLabel(selectedDefault, groupDescriptor.options) }}</option>
          <option v-for="option in groupDescriptor.options" :key="option.value" :value="option.value">{{ option.label }}</option>
        </select></label>
        <p>保存并发布后生效；客户端可能保留手动选择。节点按用户授权校验。</p>
      </template>
      <p v-else-if="!groupOutboundsAvailable">当前无法获取可用出口，请稍后刷新。</p>
      <template v-else-if="selectedDefault"><p>此分组不属于当前基础模板。</p><button type="button" :disabled="busy" @click="setGroupDefault('')">移除默认出口设置</button></template>
      <p v-else-if="selectedTarget === 'oracle-cloud'">系统分组固定直连。</p>
      <p v-else>这是规则动作，没有默认出口。</p>
    </div>
    <div ref="ruleEditor" class="rule-editor-pane" aria-label="规则编辑">
      <div><h4>{{ editLine === null ? '添加规则' : '编辑规则' }}</h4><p v-if="editLine !== null">{{ editSnapshot?.value }}<template v-if="!editVisible"> · 不在当前筛选结果中</template></p><p v-else-if="selectedTarget && !targets.includes(selectedTarget)">此分组由系统维护，新增规则请选择可编辑目标。</p><p v-else>选择类型和去向后添加，或点击列表中的规则编辑。</p></div>
      <label>规则类型<select v-model="lineForm.kind" :disabled="busy"><option v-for="kind in ruleKinds" :key="kind">{{ kind }}</option></select></label>
      <label>匹配内容<input v-model="lineForm.value" placeholder="域名、网段或端口" :disabled="busy"></label>
      <label>分流去向<select v-model="lineForm.target" :disabled="busy">
        <option v-if="!targets.includes(lineForm.target)" :value="lineForm.target" disabled>{{ lineForm.target }}（当前模板不可用）</option>
        <option v-for="target in targets" :key="target">{{ target }}</option>
      </select></label>
      <label v-if="resolutionKinds.includes(lineForm.kind)">IP 解析<select v-model="lineForm.option" :disabled="busy"><option value="">默认</option><option value="resolve">resolve</option><option value="no-resolve">no-resolve</option></select></label>
      <label v-if="editLine === null">添加位置<select v-model="lineForm.position" :disabled="busy"><option value="end">模板末尾</option><option value="start">模板最前（优先匹配）</option></select></label>
      <p v-if="error" class="message" role="alert">{{ error }}</p>
      <div class="rule-editor-actions"><button class="primary" type="button" :disabled="busy || (editLine !== null && !hasPending)" @click="saveLine">{{ editLine === null ? '添加规则' : '更新规则' }}</button><button v-if="editLine !== null || hasPending" type="button" :disabled="busy" @click="cancelLine">{{ hasPending ? '取消修改' : '添加新规则' }}</button></div>
    </div>
    </aside>
  </div>
</template>
