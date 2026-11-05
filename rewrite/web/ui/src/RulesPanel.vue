<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';

type Group = { name: string; default: string };
type Spec = { base: 'standard' | 'independent'; ai_outbound: string; rules: string; groups?: Group[] };
type Template = { id: string; name: string; builtin: boolean; spec: Spec; revision: number; published: boolean;
  published_spec: Spec | null; published_revision: number; can_undo_reset?: boolean; factory_spec?: Spec };
type User = { id: string; name: string; template_id: string; legacy_independent: boolean };
type Line = { index: number; text: string; fields: string[] | null };
const props = defineProps<{ csrf: string }>();
const emit = defineEmits<{ expired: []; policyChanged: [] }>();
const templates = ref<Template[]>([]); const users = ref<User[]>([]); const selectedId = ref('');
const loading = ref(true); const busy = ref(false); const message = ref(''); const notice = ref('');
const creating = ref(false); const selectedLines = ref<number[]>([]); const editLine = ref<number | null>(null);
const importInput = ref<HTMLInputElement | null>(null);
const form = reactive({ name: '', base: 'standard' as Spec['base'], ai: 'proxy', rules: '', groups: [] as Group[] });
const lineForm = reactive({ kind: 'DOMAIN-SUFFIX', value: '', target: 'PROXY', option: '' });
const groupForm = reactive({ name: '', default: 'PROXY' }); const bulkTarget = ref('PROXY');
const selected = computed(() => templates.value.find(item => item.id === selectedId.value) ?? null);
const targets = computed(() => ['PROXY', 'DIRECT', 'REJECT', ...(form.base === 'standard' ? ['STUN'] :
  ['EaseLian', '独立 · AI', '独立 · Google', '独立 · Telegram', '独立 · YouTube', '独立 · Netflix', '独立 · 国外媒体', '独立 · STUN', '其他流量']),
  ...form.groups.map(group => group.name)]);
const groupChoices = computed(() => ['PROXY', 'DIRECT', ...(form.base === 'independent' ? ['故障转移', '自动选择'] : [])]);
const lines = computed<Line[]>(() => form.rules.split('\n').map((text, index) => {
  const fields = text.trim().split(',').map(value => value.trim());
  return { index, text, fields: !text.trim() || text.trimStart().startsWith('#') || fields.length < 3 || fields.length > 4 ? null : fields };
}).filter(line => line.text.trim() !== ''));
const dirty = computed(() => !selected.value || creating.value || JSON.stringify({ name: form.name, spec: currentSpec() }) !==
  JSON.stringify({ name: selected.value.name, spec: selected.value.spec }));
const hasUnsaved = computed(() => creating.value ? Boolean(form.name || form.rules || form.groups.length) : Boolean(selected.value && dirty.value));
const assignedCount = computed(() => users.value.filter(user => user.template_id === selectedId.value).length);
const allChecked = computed(() => lines.value.some(line => line.fields) && lines.value.filter(line => line.fields).every(line => selectedLines.value.includes(line.index)));

function currentSpec(): Spec {
  const result: Spec = { base: form.base, ai_outbound: form.ai, rules: form.rules };
  if (form.groups.length) result.groups = form.groups.map(group => ({ name: group.name, default: group.default }));
  return result;
}
function validSpec(value: unknown): value is Spec {
  if (!value || typeof value !== 'object') return false;
  const item = value as Partial<Spec>;
  const keys = Object.keys(value).sort().join(',');
  return (keys === 'ai_outbound,base,rules' || keys === 'ai_outbound,base,groups,rules') &&
    (item.base === 'standard' || item.base === 'independent') && typeof item.ai_outbound === 'string' && typeof item.rules === 'string' &&
    (item.groups === undefined || Array.isArray(item.groups) && item.groups.every(group => group && typeof group.name === 'string' && typeof group.default === 'string'));
}
function open(item: Template) {
  selectedId.value = item.id; creating.value = false;
  form.name = item.name; form.base = item.spec.base; form.ai = item.spec.ai_outbound; form.rules = item.spec.rules;
  form.groups = (item.spec.groups ?? []).map(group => ({ ...group })); selectedLines.value = []; editLine.value = null; message.value = ''; notice.value = '';
}
function startNew() {
  if (hasUnsaved.value && !window.confirm('当前修改尚未保存，继续新建？')) return;
  selectedId.value = ''; creating.value = true; form.name = ''; form.base = 'standard'; form.ai = 'proxy'; form.rules = '';
  form.groups = []; selectedLines.value = []; editLine.value = null; message.value = ''; notice.value = '';
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
async function refresh(id?: string) {
  loading.value = true;
  try {
    const response = await request('/api/rule-templates'); if (!response.ok) throw new Error(await detail(response));
    const body: unknown = await response.json();
    if (!body || typeof body !== 'object' || !('templates' in body) || !Array.isArray(body.templates) || !('users' in body) || !Array.isArray(body.users)) throw new Error('规则模板数据不可用。');
    const next = body.templates as Template[]; const nextUsers = body.users as User[];
    if (next.some(item => typeof item.id !== 'string' || typeof item.name !== 'string' || !validSpec(item.spec) || !Number.isSafeInteger(item.revision))) throw new Error('规则模板数据不可用。');
    if (nextUsers.some(user => typeof user.id !== 'string' || typeof user.name !== 'string' || typeof user.template_id !== 'string')) throw new Error('用户分配数据不可用。');
    templates.value = next; users.value = nextUsers;
    const item = next.find(template => template.id === (id ?? selectedId.value)) ?? next[0];
    if (item) open(item);
  } catch (error) { message.value = error instanceof Error ? error.message : '无法加载规则模板。'; }
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
  if (busy.value) return; busy.value = true; message.value = ''; notice.value = '';
  try {
    const isNew = creating.value; const item = selected.value;
    if (!isNew && !item) throw new Error('请选择模板。');
    const body = isNew ? { name: form.name, spec: currentSpec() } : { name: form.name, spec: currentSpec(), expected_revision: item!.revision };
    const result = await write(isNew ? '/api/rule-templates' : `/api/rule-templates/${encodeURIComponent(item!.id)}`, isNew ? 'POST' : 'PUT', body) as { id?: unknown };
    const id = isNew && typeof result.id === 'string' ? result.id : item!.id;
    await refresh(id); notice.value = '草稿已保存。';
  } catch (error) { message.value = error instanceof Error ? error.message : '保存失败。'; }
  finally { busy.value = false; }
}
async function templateAction(action: 'publish' | 'reset' | 'undo-reset') {
  const item = selected.value; if (!item || busy.value) return;
  if (action === 'publish' && dirty.value) { message.value = '请先保存草稿，再发布。'; return; }
  const question = action === 'publish' ? `发布此模板将影响 ${assignedCount.value} 位已分配用户，继续？` :
    action === 'reset' ? `恢复出厂模板并发布，将影响 ${assignedCount.value} 位已分配用户，继续？` : `撤销恢复将影响 ${assignedCount.value} 位已分配用户，继续？`;
  if (!window.confirm(question)) return;
  busy.value = true; message.value = ''; notice.value = '';
  try { await write(`/api/rule-templates/${encodeURIComponent(item.id)}/${action}`, 'POST', { expected_revision: item.revision });
    await refresh(item.id); emit('policyChanged'); notice.value = action === 'publish' ? '模板已发布。' : action === 'reset' ? '已恢复出厂模板。' : '已撤销恢复。';
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
function addGroup() {
  const name = groupForm.name.trim(); if (!name || form.groups.some(group => group.name === name)) { message.value = '请输入不重复的分组名称。'; return; }
  form.groups.push({ name, default: groupForm.default }); groupForm.name = ''; message.value = '';
}
function startLine(line: Line) {
  if (!line.fields) return; const [kind, value, target, option] = line.fields;
  lineForm.kind = kind ?? 'DOMAIN-SUFFIX'; lineForm.value = value ?? ''; lineForm.target = target ?? 'PROXY'; lineForm.option = option ?? '';
  editLine.value = line.index;
}
function saveLine() {
  if (!lineForm.value.trim() || !lineForm.target) { message.value = '请填写规则内容和目标分组。'; return; }
  const pieces = [lineForm.kind, lineForm.value.trim(), lineForm.target];
  if (lineForm.option && ['IP-CIDR', 'IP-CIDR6', 'GEOIP'].includes(lineForm.kind)) pieces.push(lineForm.option);
  const rows = form.rules.split('\n');
  if (editLine.value === null) { if (rows.at(-1) === '') rows.pop(); rows.push(pieces.join(',')); }
  else rows[editLine.value] = pieces.join(',');
  form.rules = rows.join('\n') + (rows.at(-1) === '' ? '' : '\n'); lineForm.value = ''; editLine.value = null; selectedLines.value = []; message.value = '';
}
function selectAll() { selectedLines.value = allChecked.value ? [] : lines.value.filter(line => line.fields).map(line => line.index); }
function bulk(action: 'delete' | 'target') {
  if (!selectedLines.value.length) return;
  const chosen = new Set(selectedLines.value);
  form.rules = form.rules.split('\n').flatMap((line, index) => {
    if (!chosen.has(index)) return [line]; if (action === 'delete') return [];
    const parts = line.split(','); if (parts.length < 3 || parts.length > 4) return [line]; parts[2] = bulkTarget.value; return [parts.join(',')];
  }).join('\n');
  selectedLines.value = []; editLine.value = null;
}
async function validateTransfer(name: string, spec: Spec): Promise<{ name: string; spec: Spec }> {
  const input = { name, spec };
  if (new TextEncoder().encode(JSON.stringify(input)).length > 16384) throw new Error('模板内容超过请求大小限制，请减少规则或注释。');
  const result = await write('/api/rule-templates/validate', 'POST', input);
  if (!result || typeof result !== 'object' || !('name' in result) || typeof result.name !== 'string' || !('spec' in result) || !validSpec(result.spec)) throw new Error('模板校验结果不可用。');
  return { name: result.name, spec: result.spec };
}
async function exportTemplate() {
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
    if (file.size > 64 * 1024) throw new Error('模板文件不能超过 64 KB。');
    const value: unknown = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer()));
    if (!value || typeof value !== 'object' || !('format' in value) || value.format !== 'xdistribute-rule-template' ||
        !('version' in value) || value.version !== 1 || !('template' in value) || !value.template || typeof value.template !== 'object' ||
        Object.keys(value.template).sort().join(',') !== 'name,spec' || !('name' in value.template) || typeof value.template.name !== 'string' ||
        !('spec' in value.template) || !validSpec(value.template.spec)) throw new Error('文件格式或版本不受支持，请选择 Xdistribute 导出的规则模板。');
    const validated = await validateTransfer(value.template.name, value.template.spec);
    if (hasUnsaved.value && !window.confirm('导入会替换当前未保存的内容，继续？')) return;
    form.name = validated.name; form.base = validated.spec.base; form.ai = validated.spec.ai_outbound; form.rules = validated.spec.rules;
    form.groups = (validated.spec.groups ?? []).map(group => ({ ...group })); selectedLines.value = []; editLine.value = null; notice.value = '模板已导入，请检查后保存。';
  } catch (error) { message.value = error instanceof Error ? error.message : '导入失败。'; }
}
onMounted(() => { void refresh(); });
</script>

<template>
  <section class="rules-panel" aria-labelledby="rules-heading">
    <div class="users-heading"><div><h2 id="rules-heading">规则模板</h2><p>编辑分组和规则，保存草稿并发布给已分配用户。</p></div>
      <div class="heading-actions"><button type="button" @click="importInput?.click()">导入</button><button class="primary" type="button" @click="startNew">新建模板</button></div>
    </div>
    <input ref="importInput" class="visually-hidden" type="file" accept="application/json,.json" @change="importTemplate">
    <p v-if="message" class="message" role="alert">{{ message }}</p><p v-if="notice" class="notice" role="status">{{ notice }}</p>
    <p v-if="loading" class="table-message">正在加载规则模板…</p>
    <div v-else class="rules-layout">
      <nav class="template-list" aria-label="模板列表">
        <button v-for="item in templates" :key="item.id" type="button" :class="{ active: selectedId === item.id && !creating }" @click="selectItem(item)">
          <strong>{{ item.name }}</strong><span>{{ item.builtin ? '内置' : '自定义' }} · {{ item.published ? `已发布 v${item.published_revision}` : '未发布' }}</span>
        </button>
      </nav>
      <div v-if="selected || creating" class="template-editor">
        <div class="users-heading"><div><h3>{{ creating ? '新建模板' : '编辑模板' }}</h3><p v-if="selected && !creating">草稿 v{{ selected.revision }} · 已分配 {{ assignedCount }} 位用户</p></div><button type="button" @click="exportTemplate">导出</button></div>
        <div class="template-meta">
          <label>模板名称<input v-model="form.name" maxlength="60" required></label>
          <label>基础模板<select v-model="form.base"><option value="standard">标准分流</option><option value="independent">独立服务分组</option></select></label>
          <label>AI 默认出口<select v-model="form.ai"><option value="proxy">自动选择</option><option value="reality">REALITY</option><option value="websocket">HTTPS</option><option value="hysteria2">Hysteria 2</option><option value="vmess">VMess</option><option v-for="n in 40" :key="n" :value="`residential-${String(n).padStart(2, '0')}`">住宅 {{ String(n).padStart(2, '0') }}</option></select></label>
        </div>
        <div class="subheading"><h4>自定义分组</h4><span>{{ form.groups.length }} / 16</span></div>
        <div v-for="(group, index) in form.groups" :key="index" class="group-line"><span>{{ group.name }}</span><span>默认：{{ group.default }}</span><button type="button" @click="form.groups.splice(index, 1)">移除</button></div>
        <div class="group-editor"><input v-model="groupForm.name" aria-label="分组名称" placeholder="分组名称" maxlength="64"><select v-model="groupForm.default" aria-label="分组默认出口"><option v-for="choice in groupChoices" :key="choice">{{ choice }}</option></select><button type="button" :disabled="form.groups.length >= 16" @click="addGroup">添加分组</button></div>
        <div class="subheading"><h4>规则</h4><span>{{ lines.length }} 条 / 注释</span></div>
        <div class="rule-builder"><select v-model="lineForm.kind" aria-label="规则类型"><option v-for="kind in ['DOMAIN','DOMAIN-SUFFIX','DOMAIN-KEYWORD','IP-CIDR','IP-CIDR6','GEOIP','DST-PORT']" :key="kind">{{ kind }}</option></select>
          <input v-model="lineForm.value" aria-label="规则内容" placeholder="域名、网段或端口"><select v-model="lineForm.target" aria-label="规则目标"><option v-for="target in targets" :key="target">{{ target }}</option></select>
          <select v-if="['IP-CIDR','IP-CIDR6','GEOIP'].includes(lineForm.kind)" v-model="lineForm.option" aria-label="解析选项"><option value="">默认解析</option><option value="resolve">resolve</option><option value="no-resolve">no-resolve</option></select>
          <button type="button" @click="saveLine">{{ editLine === null ? '添加规则' : '更新规则' }}</button><button v-if="editLine !== null" type="button" @click="editLine = null; lineForm.value = ''">取消</button>
        </div>
        <div class="bulk-actions"><label class="checkbox"><input type="checkbox" :checked="allChecked" @change="selectAll">全选</label><span>已选 {{ selectedLines.length }}</span>
          <select v-model="bulkTarget" aria-label="批量修改目标"><option v-for="target in targets" :key="target">{{ target }}</option></select><button type="button" :disabled="!selectedLines.length" @click="bulk('target')">修改目标</button><button type="button" :disabled="!selectedLines.length" @click="bulk('delete')">删除</button></div>
        <div class="rules-table"><table><thead><tr><th></th><th>类型</th><th>内容</th><th>目标</th><th>解析</th><th></th></tr></thead><tbody>
          <tr v-for="line in lines" :key="line.index"><td><input v-if="line.fields" v-model="selectedLines" type="checkbox" :value="line.index" :aria-label="`选择第 ${line.index + 1} 行`"></td>
            <template v-if="line.fields"><td>{{ line.fields[0] }}</td><td>{{ line.fields[1] }}</td><td>{{ line.fields[2] }}</td><td>{{ line.fields[3] ?? '默认' }}</td><td><button type="button" @click="startLine(line)">编辑</button></td></template>
            <td v-else colspan="5" class="rule-comment">{{ line.text }}</td></tr>
        </tbody></table></div>
        <details class="raw-rules"><summary>编辑规则文本</summary><textarea v-model="form.rules" rows="8" spellcheck="false" @input="selectedLines = []; editLine = null"></textarea></details>
        <div class="editor-actions"><button v-if="selected?.builtin && !creating" type="button" :disabled="busy" @click="templateAction('reset')">恢复默认</button><button v-if="selected?.can_undo_reset && !creating" type="button" :disabled="busy" @click="templateAction('undo-reset')">撤销恢复</button><button type="button" :disabled="busy || !form.name.trim()" @click="save">保存草稿</button><button class="primary" type="button" :disabled="busy || creating || dirty" @click="templateAction('publish')">发布</button></div>
      </div>
    </div>
    <div v-if="users.length" class="template-users"><h3>用户模板分配</h3><div class="table-wrap"><table><thead><tr><th>用户</th><th>使用的模板</th></tr></thead><tbody>
      <tr v-for="user in users" :key="user.id"><td>{{ user.name }}</td><td><select :value="user.template_id" :disabled="busy" :aria-label="`${user.name} 的模板`" @change="assign(user, $event)"><option value="legacy">沿用原配置{{ user.legacy_independent ? ' · 独立服务' : '' }}</option><option v-for="item in templates.filter(t => t.published)" :key="item.id" :value="item.id">{{ item.name }}</option></select></td></tr>
    </tbody></table></div></div>
  </section>
</template>
