<script setup lang="ts">
import { computed, nextTick, reactive, ref, watch } from 'vue';
import { changeSelectedRules, filterRuleLines, filterSystemRules, parseRuleLines, resolutionKinds, ruleKinds, selectVisibleRules, type RuleLine, type SystemRule } from './rule-list';

const props = defineProps<{ rules: string; targets: string[]; systemRules: SystemRule[]; systemRulesAvailable: boolean; busy: boolean }>();
const emit = defineEmits<{ 'update:rules': [value: string] }>();
const filters = reactive({ query: '', target: '', kind: '', resolution: '', selectedOnly: false });
const selectedLines = ref<number[]>([]);
const editLine = ref<number | null>(null);
const ruleInput = ref<HTMLInputElement | null>(null);
const ruleHeading = ref<HTMLElement | null>(null);
const groupPicker = ref<HTMLElement | null>(null);
const lineForm = reactive({ kind: 'DOMAIN-SUFFIX', value: '', target: 'PROXY', option: '', position: 'end' });
const bulkTarget = ref('PROXY');
const error = ref('');

const lines = computed(() => parseRuleLines(props.rules));
const selectedSet = computed(() => new Set(selectedLines.value));
const visibleLines = computed(() => filterRuleLines(lines.value, filters, selectedSet.value));
const visibleSystemRules = computed(() => filterSystemRules(props.systemRules, filters));
const totalRules = computed(() => lines.value.filter(line => line.fields).length);
const visibleRules = computed(() => visibleLines.value.filter(line => line.fields));
const visibleSelected = computed(() => visibleRules.value.filter(line => selectedSet.value.has(line.index)).length);
const hiddenSelected = computed(() => selectedLines.value.length - visibleSelected.value);
const allChecked = computed(() => visibleRules.value.length > 0 && visibleSelected.value === visibleRules.value.length);
const someChecked = computed(() => visibleSelected.value > 0 && !allChecked.value);
const filterActive = computed(() => Boolean(filters.query.trim() || filters.target || filters.kind || filters.resolution || filters.selectedOnly));
const filterTargets = computed(() => [...new Set([...props.targets, ...props.systemRules.map(rule => rule.target), ...lines.value.flatMap(line => line.fields?.[2] ? [line.fields[2]] : [])])]);
const filterKinds = computed(() => [...new Set([...ruleKinds, ...props.systemRules.map(rule => rule.kind)])]);
const targetCounts = computed(() => {
  const counts = new Map<string, number>();
  for (const line of lines.value) {
    const target = line.fields?.[2];
    if (target) counts.set(target, (counts.get(target) ?? 0) + 1);
  }
  for (const rule of props.systemRules) counts.set(rule.target, (counts.get(rule.target) ?? 0) + 1);
  return counts;
});
const hasPending = computed(() => editLine.value !== null || Boolean(lineForm.value.trim()));
defineExpose({ hasPending });

watch(() => props.rules, () => { selectedLines.value = []; cancelLine(); });
watch(filterTargets, targets => { if (filters.target && !targets.includes(filters.target)) filters.target = ''; });
watch(() => props.targets, targets => {
  if (!hasPending.value && !targets.includes(lineForm.target)) lineForm.target = targets[0] ?? 'PROXY';
  if (!targets.includes(bulkTarget.value)) bulkTarget.value = targets[0] ?? 'PROXY';
});
watch(() => filters.target, target => {
  if (!hasPending.value && target && props.targets.includes(target)) lineForm.target = target;
});

function clearFilters() {
  Object.assign(filters, { query: '', target: '', kind: '', resolution: '', selectedOnly: false });
}
function chooseGroup(target: string) {
  Object.assign(filters, { query: '', target, kind: '', resolution: '', selectedOnly: false });
  if (window.matchMedia('(max-width: 800px)').matches) {
    void nextTick(() => ruleHeading.value?.scrollIntoView({ block: 'start' }));
  }
}
function cancelLine() {
  editLine.value = null; lineForm.value = ''; lineForm.option = ''; error.value = '';
}
function startLine(line: RuleLine) {
  if (!line.fields) return;
  if (hasPending.value && !window.confirm('当前规则尚未添加或更新，切换后会丢失，继续？')) return;
  const [kind, value, target, option] = line.fields;
  lineForm.kind = kind ?? 'DOMAIN-SUFFIX'; lineForm.value = value ?? '';
  lineForm.target = target ?? 'PROXY'; lineForm.option = option ?? '';
  editLine.value = line.index; error.value = '';
  void nextTick(() => ruleInput.value?.focus());
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
  emit('update:rules', next);
  cancelLine();
}
function toggleVisible(event: Event) {
  selectedLines.value = selectVisibleRules(selectedLines.value, visibleLines.value, (event.target as HTMLInputElement).checked);
}
function bulk(action: 'delete' | 'target') {
  if (!selectedLines.value.length) return;
  if (hasPending.value) { error.value = '请先添加、更新或取消正在编辑的规则。'; return; }
  if (action === 'target' && !props.targets.includes(bulkTarget.value)) { error.value = '请选择当前模板支持的目标分组。'; return; }
  emit('update:rules', changeSelectedRules(props.rules, selectedSet.value,
    action === 'delete' ? { type: 'delete' } : { type: 'target', target: bulkTarget.value }));
  selectedLines.value = []; cancelLine();
}
function updateRaw(event: Event) {
  emit('update:rules', (event.target as HTMLTextAreaElement).value);
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
    <div class="rule-list-pane">
      <div ref="groupPicker" class="group-picker" role="group" aria-label="查看分组规则">
        <div class="group-picker-heading"><h4>查看分组</h4><span>点选分组查看规则，数量包含系统规则</span></div>
        <div class="group-picker-items">
          <button type="button" :class="{ active: !filters.target }" :aria-pressed="!filters.target" @click="chooseGroup('')"><span>全部分组</span><span>{{ totalRules + systemRules.length }}</span></button>
          <button v-for="target in filterTargets" :key="target" type="button" :class="{ active: filters.target === target }" :aria-pressed="filters.target === target" @click="chooseGroup(target)"><span>{{ target }}</span><span>{{ targetCounts.get(target) ?? 0 }}</span></button>
        </div>
      </div>
      <div ref="ruleHeading" class="subheading rule-list-heading">
        <div><h4>{{ filters.target || '全部分组' }} · 规则列表</h4><p>模板规则 {{ visibleRules.length }} 条<template v-if="systemRulesAvailable"> · 系统规则 {{ visibleSystemRules.length }} 条</template></p></div>
        <div class="rule-heading-actions"><button v-if="filters.target" type="button" @click="groupPicker?.scrollIntoView({ block: 'start' })">切换分组</button><button v-if="filterActive" type="button" @click="clearFilters">清除筛选</button></div>
      </div>
      <div class="rule-filters">
        <label class="rule-search">搜索<input v-model="filters.query" type="search" placeholder="搜索内容、类型或目标"></label>
        <label>规则类型<select v-model="filters.kind"><option value="">全部类型</option><option v-for="kind in filterKinds" :key="kind">{{ kind }}</option></select></label>
        <label>IP 解析<select v-model="filters.resolution"><option value="">全部</option><option value="default">默认</option><option value="resolve">resolve</option><option value="no-resolve">no-resolve</option></select></label>
      </div>
      <div class="rule-filter-footer">
        <label class="checkbox"><input v-model="filters.selectedOnly" type="checkbox">只看已选</label>
        <span v-if="systemRulesAvailable">系统规则只读，实际匹配顺序和用户设置以客户端配置为准。</span>
        <span v-else class="system-warning">系统规则暂不可用，请刷新页面或检查面板版本。</span>
      </div>
      <div class="bulk-actions">
        <label class="checkbox"><input type="checkbox" :checked="allChecked" :indeterminate.prop="someChecked" :disabled="busy || !visibleRules.length" @change="toggleVisible">全选当前结果</label>
        <span>已选 {{ selectedLines.length }}<template v-if="hiddenSelected">（{{ hiddenSelected }} 条在筛选结果外）</template></span>
        <button v-if="selectedLines.length" type="button" :disabled="busy" @click="selectedLines = []">清空选择</button>
        <select v-model="bulkTarget" aria-label="批量修改目标" :disabled="busy"><option v-for="target in targets" :key="target">{{ target }}</option></select>
        <button type="button" :disabled="busy || !selectedLines.length" @click="bulk('target')">修改已选目标</button>
        <button type="button" :disabled="busy || !selectedLines.length" @click="bulk('delete')">删除已选</button>
      </div>
      <div class="rules-table" tabindex="0" role="region" aria-label="规则列表">
        <table><thead><tr><th></th><th>类型</th><th>内容</th><th>目标</th><th>解析</th><th></th></tr></thead><tbody>
          <tr v-for="line in visibleLines" :key="line.index" :class="{ 'editing-rule': editLine === line.index }">
            <td><input v-if="line.fields" v-model="selectedLines" type="checkbox" :value="line.index" :disabled="busy" :aria-label="'选择第 ' + (line.index + 1) + ' 行'"></td>
            <template v-if="line.fields">
              <td class="rule-type">{{ line.fields[0] }}</td>
              <td class="rule-content">{{ line.fields[1] }}<span class="mobile-rule-details">{{ line.fields[0] }} · {{ line.fields[2] }}<template v-if="line.fields[3]"> · {{ line.fields[3] }}</template></span></td>
              <td class="rule-target">{{ line.fields[2] }}</td><td class="rule-resolution">{{ line.fields[3] ?? '默认' }}</td>
              <td><button type="button" :disabled="busy" @click="startLine(line)">编辑</button></td>
            </template>
            <td v-else colspan="5" class="rule-comment">{{ line.text }}</td>
          </tr>
          <tr v-if="visibleSystemRules.length" class="system-rules-heading"><td colspan="6">系统基础规则 · 只读</td></tr>
          <tr v-for="(line, index) in visibleSystemRules" :key="`system-${index}`" class="system-rule">
            <td aria-hidden="true">—</td><td class="rule-type">{{ line.kind }}</td>
            <td class="rule-content">{{ line.value }}<span class="mobile-rule-details">{{ line.kind }} · {{ line.target }}<template v-if="line.option"> · {{ line.option }}</template></span></td>
            <td class="rule-target">{{ line.target }}</td><td class="rule-resolution">{{ line.option || '默认' }}</td><td><span class="system-rule-tag">系统</span></td>
          </tr>
          <tr v-if="!visibleLines.length && !visibleSystemRules.length"><td colspan="6" class="rule-empty">{{ filterActive ? '没有匹配的规则，请调整筛选条件。' : '暂无规则，可在编辑区添加。' }}</td></tr>
        </tbody></table>
      </div>
      <details class="raw-rules"><summary @click="openRaw">编辑规则文本</summary><textarea :value="rules" rows="8" spellcheck="false" aria-label="规则文本" :disabled="busy || hasPending" @input="updateRaw"></textarea><p v-if="hasPending">请先完成或取消当前规则编辑。</p></details>
    </div>
    <aside class="rule-editor-pane" aria-label="规则编辑">
      <div><h4>{{ editLine === null ? '添加规则' : '编辑规则' }}</h4><p v-if="editLine !== null">正在修改第 {{ editLine + 1 }} 行</p><p v-else-if="filters.target && !targets.includes(filters.target)">此分组由系统维护，新增规则请选择可编辑目标。</p><p v-else>选择类型和目标后添加。</p></div>
      <label>规则类型<select v-model="lineForm.kind" :disabled="busy"><option v-for="kind in ruleKinds" :key="kind">{{ kind }}</option></select></label>
      <label>匹配内容<input ref="ruleInput" v-model="lineForm.value" placeholder="域名、网段或端口" :disabled="busy"></label>
      <label>目标分组<select v-model="lineForm.target" :disabled="busy">
        <option v-if="!targets.includes(lineForm.target)" :value="lineForm.target" disabled>{{ lineForm.target }}（当前模板不可用）</option>
        <option v-for="target in targets" :key="target">{{ target }}</option>
      </select></label>
      <label v-if="resolutionKinds.includes(lineForm.kind)">IP 解析<select v-model="lineForm.option" :disabled="busy"><option value="">默认</option><option value="resolve">resolve</option><option value="no-resolve">no-resolve</option></select></label>
      <label v-if="editLine === null">添加位置<select v-model="lineForm.position" :disabled="busy"><option value="end">模板末尾</option><option value="start">模板最前（优先匹配）</option></select></label>
      <p v-if="error" class="message" role="alert">{{ error }}</p>
      <div class="rule-editor-actions"><button class="primary" type="button" :disabled="busy" @click="saveLine">{{ editLine === null ? '添加规则' : '更新规则' }}</button><button v-if="hasPending" type="button" :disabled="busy" @click="cancelLine">取消</button></div>
    </aside>
  </div>
</template>
