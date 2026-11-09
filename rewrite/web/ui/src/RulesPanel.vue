<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import RuleWorkspace from './RuleWorkspace.vue';
import { changeSelectedRules, parseRuleLines, type SystemRule, type SystemRuleOverride } from './rule-list';
import { validGroupOutbounds, type GroupOutbounds } from './group-defaults';
import { validGroupOrderCatalog, type GroupOrderOption } from './group-order';

type Group = { name: string; default: string };
type Spec = { base: 'standard' | 'independent'; ai_outbound: string; rules: string; groups?: Group[]; group_defaults?: Record<string, string>; group_order?: string[]; group_names?: Record<string, string>; system_overrides?: Record<string, SystemRuleOverride> };
type Template = { id: string; name: string; builtin: boolean; spec: Spec; revision: number; published: boolean;
  published_spec: Spec | null; published_revision: number; can_undo_reset?: boolean; factory_spec?: Spec };
type User = { id: string; name: string; template_id: string; legacy_independent: boolean };
const props = defineProps<{ csrf: string }>();
const emit = defineEmits<{ expired: []; policyChanged: [] }>();
const templates = ref<Template[]>([]); const users = ref<User[]>([]); const selectedId = ref('');
const systemRules = ref<Record<Spec['base'], SystemRule[]>>({ standard: [], independent: [] });
const systemRulesAvailable = ref(false);
const groupOutbounds = ref<Record<Spec['base'], GroupOutbounds>>({ standard: {}, independent: {} });
const groupOutboundsAvailable = ref(false);
const groupOrderCatalog = ref<Record<Spec['base'], GroupOrderOption[]>>({ standard: [], independent: [] });
const groupOrderCatalogAvailable = ref(false);
const loading = ref(true); const busy = ref(false); const message = ref(''); const notice = ref('');
const groupMessage = ref('');
const creating = ref(false); const editingGroup = ref<number | null>(null);
const importInput = ref<HTMLInputElement | null>(null);
const ruleWorkspace = ref<InstanceType<typeof RuleWorkspace> | null>(null);
const form = reactive({ name: '', base: 'standard' as Spec['base'], ai: 'proxy', rules: '', groups: [] as Group[], groupDefaults: {} as Record<string, string>, groupOrder: [] as string[], groupNames: {} as Record<string, string>, systemOverrides: {} as Record<string, SystemRuleOverride> });
const groupForm = reactive({ name: '' });
const selected = computed(() => templates.value.find(item => item.id === selectedId.value) ?? null);
const targets = computed(() => ['PROXY', 'DIRECT', 'REJECT', ...(form.base === 'standard' ? ['STUN'] :
  ['EaseLian', '独立 · AI', '独立 · Google', '独立 · Telegram', '独立 · YouTube', '独立 · Netflix', '独立 · 国外媒体', '独立 · STUN', '其他流量']),
  ...form.groups.map(group => group.name)]);
const dirty = computed(() => !selected.value || creating.value || JSON.stringify({ name: form.name, spec: currentSpec() }) !==
  JSON.stringify({ name: selected.value.name, spec: selected.value.spec }));
const pendingEditors = computed(() => Boolean(editingGroup.value !== null || groupForm.name.trim() || ruleWorkspace.value?.hasPending));
const hasUnsaved = computed(() => pendingEditors.value || (creating.value ? Boolean(form.name || form.rules || form.groups.length || form.groupOrder.length || Object.keys(form.groupNames).length || Object.keys(form.groupDefaults).length || Object.keys(form.systemOverrides).length) : Boolean(selected.value && dirty.value)));
const assignedCount = computed(() => users.value.filter(user => user.template_id === selectedId.value).length);
function copyOverrides(value: Record<string, SystemRuleOverride>): Record<string, SystemRuleOverride> {
  return Object.fromEntries(Object.entries(value).map(([id, entry]) => [id, entry ? { ...entry } : null]));
}

function currentSpec(): Spec {
  const result: Spec = { base: form.base, ai_outbound: form.ai, rules: form.rules };
  if (form.groups.length) result.groups = form.groups.map(group => ({ name: group.name, default: group.default }));
  if (Object.keys(form.groupDefaults).length) result.group_defaults = { ...form.groupDefaults };
  if (form.groupOrder.length) result.group_order = [...form.groupOrder];
  if (Object.keys(form.groupNames).length) result.group_names = { ...form.groupNames };
  if (Object.keys(form.systemOverrides).length) result.system_overrides = copyOverrides(form.systemOverrides);
  return result;
}
function updateRules(value: string) { form.rules = value; message.value = ''; notice.value = ''; }
function updateGroupDefaults(value: Record<string, string>) { form.groupDefaults = value; message.value = ''; notice.value = ''; }
function updateGroupOrder(value: string[]) { form.groupOrder = value; message.value = ''; notice.value = ''; }
function updateSystemOverrides(value: Record<string, SystemRuleOverride>) { form.systemOverrides = value; message.value = ''; notice.value = ''; }
function validSpec(value: unknown): value is Spec {
  if (!value || typeof value !== 'object') return false;
  const item = value as Partial<Spec>;
  const keys = Object.keys(value);
  return keys.every(key => ['ai_outbound', 'base', 'rules', 'groups', 'group_defaults', 'group_order', 'group_names', 'system_overrides'].includes(key)) &&
    (item.base === 'standard' || item.base === 'independent') && typeof item.ai_outbound === 'string' && typeof item.rules === 'string' &&
    (item.groups === undefined || Array.isArray(item.groups) && item.groups.every(group => group && typeof group.name === 'string' && typeof group.default === 'string')) &&
    (item.group_defaults === undefined || Boolean(item.group_defaults && typeof item.group_defaults === 'object' && !Array.isArray(item.group_defaults) && Object.values(item.group_defaults).every(value => typeof value === 'string'))) &&
    (item.group_order === undefined || Array.isArray(item.group_order) && item.group_order.every(value => typeof value === 'string')) &&
    (item.group_names === undefined || Boolean(item.group_names && typeof item.group_names === 'object' && !Array.isArray(item.group_names) && Object.values(item.group_names).every(value => typeof value === 'string'))) &&
    (item.system_overrides === undefined || Boolean(item.system_overrides && typeof item.system_overrides === 'object' && !Array.isArray(item.system_overrides) && Object.values(item.system_overrides).every(value => value === null || value && typeof value === 'object' && ['kind', 'value', 'target', 'option'].every(key => typeof (value as Record<string, unknown>)[key] === 'string'))));
}
function validSystemRule(value: unknown): value is SystemRule {
  return Boolean(value && typeof value === 'object' &&
    ['kind', 'value', 'target', 'option', 'provider'].every(key => typeof (value as Record<string, unknown>)[key] === 'string'));
}
function open(item: Template) {
  selectedId.value = item.id; creating.value = false;
  form.name = item.name; form.base = item.spec.base; form.ai = item.spec.ai_outbound; form.rules = item.spec.rules;
  form.groups = (item.spec.groups ?? []).map(group => ({ ...group })); form.groupDefaults = { ...item.spec.group_defaults }; form.groupOrder = [...(item.spec.group_order ?? [])]; form.groupNames = { ...item.spec.group_names }; form.systemOverrides = copyOverrides(item.spec.system_overrides ?? {}); cancelGroup(); message.value = ''; notice.value = '';
}
function startNew() {
  if (hasUnsaved.value && !window.confirm('当前修改尚未保存，继续新建？')) return;
  selectedId.value = ''; creating.value = true; form.name = ''; form.base = 'standard'; form.ai = 'proxy'; form.rules = '';
  form.groups = []; form.groupDefaults = {}; form.groupOrder = []; form.groupNames = {}; form.systemOverrides = {}; cancelGroup(); message.value = ''; notice.value = '';
}
function selectItem(item: Template) {
  if (selectedId.value === item.id && !creating.value) return;
  if (hasUnsaved.value && !window.confirm('当前修改尚未保存，切换模板？')) return;
  open(item);
}
async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const response = await fetch(path, { ...init, credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(15000) });
  if (response.status === 401) emit('expired'); return response;
}
async function detail(response: Response): Promise<string> {
  try { const body: unknown = await response.json(); if (body && typeof body === 'object' && 'detail' in body && typeof body.detail === 'string') return body.detail; }
  catch { /* The server may return a non-JSON error. */ }
  return '操作失败，请稍后重试。';
}
async function refresh(id?: string): Promise<boolean> {
  if (!templates.value.length) loading.value = true;
  try {
    const response = await request('/api/rule-templates'); if (!response.ok) throw new Error(await detail(response));
    const body: unknown = await response.json();
    if (!body || typeof body !== 'object' || !('templates' in body) || !Array.isArray(body.templates) || !('users' in body) || !Array.isArray(body.users)) throw new Error('规则模板数据不可用。');
    const next = body.templates as Template[]; const nextUsers = body.users as User[];
    if (!next.length || next.some(item => typeof item.id !== 'string' || typeof item.name !== 'string' || !validSpec(item.spec) || !Number.isSafeInteger(item.revision))) throw new Error('规则模板数据不可用。');
    if (nextUsers.some(user => typeof user.id !== 'string' || typeof user.name !== 'string' || typeof user.template_id !== 'string')) throw new Error('用户分配数据不可用。');
    const generated = 'system_rules' in body && body.system_rules && typeof body.system_rules === 'object' ? body.system_rules as Record<string, unknown> : null;
    systemRulesAvailable.value = Boolean(generated && Array.isArray(generated.standard) && Array.isArray(generated.independent) &&
      generated.standard.every(validSystemRule) && generated.independent.every(validSystemRule));
    systemRules.value = systemRulesAvailable.value ? { standard: generated!.standard as SystemRule[], independent: generated!.independent as SystemRule[] } : { standard: [], independent: [] };
    const outbounds = 'group_outbounds' in body && body.group_outbounds && typeof body.group_outbounds === 'object' ? body.group_outbounds as Record<string, unknown> : null;
    groupOutboundsAvailable.value = Boolean(outbounds && validGroupOutbounds(outbounds.standard) && validGroupOutbounds(outbounds.independent));
    groupOutbounds.value = groupOutboundsAvailable.value ? { standard: outbounds!.standard as GroupOutbounds, independent: outbounds!.independent as GroupOutbounds } : { standard: {}, independent: {} };
    const ordering = 'group_order_catalog' in body && body.group_order_catalog && typeof body.group_order_catalog === 'object' ? body.group_order_catalog as Record<string, unknown> : null;
    groupOrderCatalogAvailable.value = Boolean(ordering && validGroupOrderCatalog(ordering.standard) && validGroupOrderCatalog(ordering.independent));
    groupOrderCatalog.value = groupOrderCatalogAvailable.value ? { standard: ordering!.standard as GroupOrderOption[], independent: ordering!.independent as GroupOrderOption[] } : { standard: [], independent: [] };
    templates.value = next; users.value = nextUsers;
    const item = next.find(template => template.id === (id ?? selectedId.value)) ?? next[0];
    if (item) open(item);
    return true;
  } catch (error) { message.value = error instanceof Error ? error.message : '无法加载规则模板。'; return false; }
  finally { loading.value = false; }
}
async function refreshUsers() {
  try {
    const response = await request('/api/rule-templates'); if (!response.ok) throw new Error(await detail(response));
    const body: unknown = await response.json();
    if (!body || typeof body !== 'object' || !('users' in body) || !Array.isArray(body.users) ||
        body.users.some((user: User) => typeof user.id !== 'string' || typeof user.name !== 'string' || typeof user.template_id !== 'string')) throw new Error('用户分配数据不可用。');
    users.value = body.users as User[];
  } catch (error) { message.value = error instanceof Error ? error.message : '无法刷新用户分配。'; }
}
defineExpose({ refreshUsers });
async function write(path: string, method: string, body: unknown): Promise<unknown> {
  const response = await request(path, { method, headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': props.csrf }, body: JSON.stringify(body) });
  if (!response.ok) throw new Error(await detail(response)); return response.json();
}
async function save() {
  if (pendingEditors.value) { message.value = '请先添加、更新或取消正在编辑的规则和分组。'; return; }
  if (busy.value) return; busy.value = true; message.value = ''; notice.value = '';
  try {
    const isNew = creating.value; const item = selected.value;
    if (!isNew && !item) throw new Error('请选择模板。');
    const body = isNew ? { name: form.name, spec: currentSpec() } : { name: form.name, spec: currentSpec(), expected_revision: item!.revision };
    const result = await write(isNew ? '/api/rule-templates' : `/api/rule-templates/${encodeURIComponent(item!.id)}`, isNew ? 'POST' : 'PUT', body) as { id?: unknown };
    const id = isNew && typeof result.id === 'string' ? result.id : item!.id;
    notice.value = await refresh(id) ? '草稿已保存。' : '草稿已保存，但刷新失败，请重新加载页面后继续。';
  } catch (error) { message.value = error instanceof Error ? error.message : '保存失败。'; }
  finally { busy.value = false; }
}
async function templateAction(action: 'publish' | 'reset' | 'undo-reset') {
  const item = selected.value; if (!item || busy.value) return;
  if (pendingEditors.value) { message.value = '请先添加、更新或取消正在编辑的规则和分组。'; return; }
  if (action === 'publish' && dirty.value) { message.value = '请先保存草稿，再发布。'; return; }
  const question = action === 'publish' ? `发布此模板将影响 ${assignedCount.value} 位已分配用户，继续？` :
    action === 'reset' ? `恢复出厂模板并发布，将影响 ${assignedCount.value} 位已分配用户，继续？` : `撤销恢复将影响 ${assignedCount.value} 位已分配用户，继续？`;
  if (!window.confirm(question)) return;
  busy.value = true; message.value = ''; notice.value = '';
  try { await write(`/api/rule-templates/${encodeURIComponent(item.id)}/${action}`, 'POST', { expected_revision: item.revision });
    const refreshed = await refresh(item.id); emit('policyChanged');
    notice.value = refreshed ? (action === 'publish' ? '模板已发布。' : action === 'reset' ? '已恢复出厂模板。' : '已撤销恢复。') : '操作已完成，但刷新失败，请重新加载页面后继续。';
  } catch (error) { message.value = error instanceof Error ? error.message : '操作失败。'; }
  finally { busy.value = false; }
}
async function assign(user: User, event: Event) {
  const choice = (event.target as HTMLSelectElement).value; if (busy.value || choice === user.template_id) return;
  busy.value = true; message.value = ''; notice.value = '';
  try { await write(`/api/users/${encodeURIComponent(user.id)}/rule-template`, 'POST', { template_id: choice });
    user.template_id = choice; emit('policyChanged'); notice.value = `已更新 ${user.name} 的模板。`;
  } catch (error) { (event.target as HTMLSelectElement).value = user.template_id; message.value = error instanceof Error ? error.message : '分配失败。'; }
  finally { busy.value = false; }
}
const reservedGroups = new Set(['DIRECT', 'REJECT', 'PROXY', 'STUN', '直连', '故障转移', '自动选择', '住宅节点',
  'EaseLian', '独立 · AI', '独立 · Google', '独立 · Telegram', '独立 · YouTube', '独立 · Netflix',
  '独立 · 国外媒体', '独立 · STUN', '其他流量', 'oracle-cloud']);
function cancelGroup() { editingGroup.value = null; groupForm.name = ''; groupMessage.value = ''; }
function editGroup(index: number) {
  const group = form.groups[index]; if (!group) return;
  if ((editingGroup.value !== null || groupForm.name.trim()) && !window.confirm('当前分组尚未添加或更新，切换后会丢失，继续？')) return;
  editingGroup.value = index; groupForm.name = group.name; groupMessage.value = '';
}
function addGroup() {
  const name = groupForm.name.trim();
  if (!name || new TextEncoder().encode(name).length > 64 || /[\x00-\x1f\x7f,=#]/.test(name) ||
      reservedGroups.has(name) || Object.values(form.groupNames).includes(name) || form.groups.some((group, index) => group.name === name && index !== editingGroup.value)) {
    groupMessage.value = '分组名称为空、过长、重复或与内置名称冲突。'; return;
  }
  if (editingGroup.value !== null) {
    const group = form.groups[editingGroup.value]; if (!group) { groupMessage.value = '分组已变化，请重新选择。'; return; }
    if (group.name !== name) {
      if (ruleWorkspace.value?.hasPending) { groupMessage.value = '请先完成正在编辑的规则，再修改分组名称。'; return; }
      const references = parseRuleLines(form.rules).filter(line => line.fields?.[2] === group.name).map(line => line.index);
      form.rules = changeSelectedRules(form.rules, new Set(references), { type: 'target', target: name });
      if (group.name in form.groupDefaults) {
        const defaults = { ...form.groupDefaults, [name]: form.groupDefaults[group.name]! };
        delete defaults[group.name]; form.groupDefaults = defaults;
      }
      form.groupOrder = form.groupOrder.map(item => item === group.name ? name : item);
      form.systemOverrides = Object.fromEntries(Object.entries(form.systemOverrides).map(([id, value]) => [id, value && value.target === group.name ? { ...value, target: name } : value]));
    }
    form.groups[editingGroup.value] = { ...group, name };
  } else {
    if (form.groups.length >= 16) { groupMessage.value = '最多添加 16 个分组。'; return; }
    form.groups.push({ name, default: 'PROXY' });
  }
  cancelGroup(); message.value = ''; notice.value = '';
}
function renameSelectedGroup(original: string, name: string) {
  const index = form.groups.findIndex(group => group.name === original);
  if (index >= 0) {
    const references = parseRuleLines(form.rules).filter(line => line.fields?.[2] === original).map(line => line.index);
    form.rules = changeSelectedRules(form.rules, new Set(references), { type: 'target', target: name });
    if (original in form.groupDefaults) {
      const defaults = { ...form.groupDefaults, [name]: form.groupDefaults[original]! };
      delete defaults[original]; form.groupDefaults = defaults;
    }
    form.groupOrder = form.groupOrder.map(item => item === original ? name : item);
    form.systemOverrides = Object.fromEntries(Object.entries(form.systemOverrides).map(([id, value]) => [id, value && value.target === original ? { ...value, target: name } : value]));
    form.groups[index] = { ...form.groups[index]!, name };
  } else {
    const names = { ...form.groupNames };
    if (name === original) delete names[original]; else names[original] = name;
    form.groupNames = names;
  }
  message.value = ''; notice.value = '分组名称已修改，请保存草稿并发布。';
}
function removeGroup(index: number) {
  const group = form.groups[index]; if (!group) return;
  if (parseRuleLines(form.rules).some(line => line.fields?.[2] === group.name) || Object.values(form.systemOverrides).some(value => value?.target === group.name)) {
    groupMessage.value = '请先修改或删除引用此分组的规则。'; return;
  }
  if (editingGroup.value === index) cancelGroup();
  else if (editingGroup.value !== null && editingGroup.value > index) editingGroup.value--;
  form.groups.splice(index, 1);
  const defaults = { ...form.groupDefaults }; delete defaults[group.name]; form.groupDefaults = defaults;
  form.groupOrder = form.groupOrder.filter(item => item !== group.name);
  groupMessage.value = '';
}
async function validateTransfer(name: string, spec: Spec): Promise<{ name: string; spec: Spec }> {
  const input = { name, spec };
  if (new TextEncoder().encode(JSON.stringify(input)).length > 64 * 1024) throw new Error('模板内容超过请求大小限制，请减少规则或注释。');
  const result = await write('/api/rule-templates/validate', 'POST', input);
  if (!result || typeof result !== 'object' || !('name' in result) || typeof result.name !== 'string' || !('spec' in result) || !validSpec(result.spec)) throw new Error('模板校验结果不可用。');
  return { name: result.name, spec: result.spec };
}
async function exportTemplate() {
  if (pendingEditors.value) { message.value = '请先添加、更新或取消正在编辑的规则和分组。'; return; }
  if (busy.value) return; busy.value = true; message.value = '';
  try {
    const item = await validateTransfer(form.name, currentSpec());
    const text = JSON.stringify({ format: 'xdistribute-rule-template', version: 1, template: item }, null, 2) + '\n';
    const blob = new Blob([text], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url;
    const filename = item.name.replace(/[\\/:*?"<>|\u0000-\u001f]/g, '_').replace(/[. ]+$/, '').trim().slice(0, 80) || '规则模板';
    link.download = `Xdistribute-${filename}.json`; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) { message.value = error instanceof Error ? error.message : '导出失败。'; }
  finally { busy.value = false; }
}
async function importTemplate(event: Event) {
  const input = event.target as HTMLInputElement; const file = input.files?.[0]; input.value = ''; if (!file) return;
  try {
    if (file.size > 128 * 1024) throw new Error('模板文件不能超过 128 KB。');
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer()));
    if (!value || typeof value !== 'object' || !('format' in value) || value.format !== 'xdistribute-rule-template' ||
        !('version' in value) || value.version !== 1 || !('template' in value) || !value.template || typeof value.template !== 'object' ||
        Object.keys(value.template).sort().join(',') !== 'name,spec' || !('name' in value.template) || typeof value.template.name !== 'string' ||
        !('spec' in value.template) || !validSpec(value.template.spec)) throw new Error('文件格式或版本不受支持，请选择 Xdistribute 导出的规则模板。');
    const validated = await validateTransfer(value.template.name, value.template.spec);
    if (hasUnsaved.value && !window.confirm('导入会替换当前未保存的内容，继续？')) return;
    form.name = validated.name; form.base = validated.spec.base; form.ai = validated.spec.ai_outbound; form.rules = validated.spec.rules;
    form.groups = (validated.spec.groups ?? []).map(group => ({ ...group })); form.groupDefaults = { ...validated.spec.group_defaults }; form.groupOrder = [...(validated.spec.group_order ?? [])]; form.groupNames = { ...validated.spec.group_names }; form.systemOverrides = copyOverrides(validated.spec.system_overrides ?? {}); cancelGroup(); notice.value = '模板已导入，请检查后保存。';
  } catch (error) { message.value = error instanceof Error ? error.message : '导入失败。'; }
}
onMounted(() => { void refresh(); });
</script>

<template>
  <section class="rules-panel" aria-labelledby="rules-heading">
    <div class="users-heading"><div><h2 id="rules-heading">规则模板</h2><p>编辑分组和规则，保存草稿并发布给已分配用户。</p></div>
      <div class="heading-actions"><button type="button" :disabled="busy" @click="importInput?.click()">导入</button><button class="primary" type="button" :disabled="busy" @click="startNew">新建模板</button></div>
    </div>
    <input ref="importInput" class="visually-hidden" type="file" accept="application/json,.json" :disabled="busy" @change="importTemplate">
    <p v-if="message" class="message" role="alert">{{ message }}</p><p v-if="notice" class="notice" role="status">{{ notice }}</p>
    <p v-if="loading" class="table-message">正在加载规则模板…</p>
    <div v-else class="rules-layout">
      <nav class="template-list" aria-label="模板列表">
        <button v-for="item in templates" :key="item.id" type="button" :disabled="busy" :class="{ active: selectedId === item.id && !creating }" @click="selectItem(item)">
          <strong>{{ item.name }}</strong><span>{{ item.builtin ? '内置' : '自定义' }} · {{ item.published ? `已发布 v${item.published_revision}` : '未发布' }}</span>
        </button>
      </nav>
      <div v-if="selected || creating" class="template-editor">
        <div class="users-heading"><div><h3>{{ creating ? '新建模板' : '编辑模板' }}</h3><p v-if="selected && !creating">草稿 v{{ selected.revision }} · 已分配 {{ assignedCount }} 位用户</p></div><button type="button" :disabled="busy" @click="exportTemplate">导出</button></div>
        <div class="template-meta">
          <label>模板名称<input v-model="form.name" maxlength="60" required :disabled="busy"></label>
          <label>基础模板<select v-model="form.base" :disabled="busy"><option value="standard">标准分流</option><option value="independent">独立服务分组</option></select></label>
        </div>
        <details class="group-management">
          <summary><strong>添加分组</strong><span>{{ form.groups.length }} / 16</span></summary>
          <p>添加或管理自定义分组；选择分组后可设置默认出口。</p>
          <div v-for="(group, index) in form.groups" :key="index" class="group-line">
            <span>{{ group.name }}</span>
            <div><button type="button" :disabled="busy" @click="editGroup(index)">编辑</button><button type="button" :disabled="busy" @click="removeGroup(index)">移除</button></div>
          </div>
          <div class="group-editor"><input v-model="groupForm.name" aria-label="分组名称" placeholder="分组名称" maxlength="64" :disabled="busy">
            <button type="button" :disabled="busy || (editingGroup === null && form.groups.length >= 16)" @click="addGroup">{{ editingGroup === null ? '添加分组' : '更新分组' }}</button>
            <button v-if="editingGroup !== null || groupForm.name.trim()" type="button" :disabled="busy" @click="cancelGroup">取消</button>
          </div>
          <p v-if="groupMessage" class="message" role="alert">{{ groupMessage }}</p>
        </details>
        <RuleWorkspace :key="creating ? 'new' : selectedId" ref="ruleWorkspace" :rules="form.rules" :targets="targets" :system-rules="systemRules[form.base]" :system-rules-available="systemRulesAvailable" :system-overrides="form.systemOverrides" :group-outbounds="groupOutbounds[form.base]" :group-outbounds-available="groupOutboundsAvailable" :group-order-catalog="groupOrderCatalog[form.base]" :group-order-catalog-available="groupOrderCatalogAvailable" :group-defaults="form.groupDefaults" :group-order="form.groupOrder" :group-names="form.groupNames" :custom-groups="form.groups" :legacy-ai="form.ai" :busy="busy" @update:rules="updateRules" @update:system-overrides="updateSystemOverrides" @update:group-defaults="updateGroupDefaults" @update:group-order="updateGroupOrder" @rename-group="renameSelectedGroup" />
        <div class="editor-actions"><button v-if="selected?.builtin && !creating" type="button" :disabled="busy" @click="templateAction('reset')">恢复默认</button><button v-if="selected?.can_undo_reset && !creating" type="button" :disabled="busy" @click="templateAction('undo-reset')">撤销恢复</button><button type="button" :disabled="busy || !form.name.trim()" @click="save">保存草稿</button><button class="primary" type="button" :disabled="busy || creating || dirty" @click="templateAction('publish')">发布</button></div>
      </div>
    </div>
    <div v-if="users.length" class="template-users"><h3>用户模板分配</h3><div class="table-wrap"><table><thead><tr><th>用户</th><th>使用的模板</th></tr></thead><tbody>
      <tr v-for="user in users" :key="user.id"><td>{{ user.name }}</td><td><select :value="user.template_id" :disabled="busy" :aria-label="`${user.name} 的模板`" @change="assign(user, $event)"><option value="legacy">沿用原配置{{ user.legacy_independent ? ' · 独立服务' : '' }}</option><option v-for="item in templates.filter(t => t.published)" :key="item.id" :value="item.id">{{ item.name }}</option></select></td></tr>
    </tbody></table></div></div>
  </section>
</template>
