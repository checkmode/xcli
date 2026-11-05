<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue';

type Choice = { id: string; name: string };
type Node = { id: string; name: string; enabled: boolean; users: string[]; last_seen: number;
  pending_revision: string; applied_revision: string; endpoint: { domain: string; public_ip: string; public_port: number } };
const props = defineProps<{ csrf: string }>();
const emit = defineEmits<{ expired: [] }>();
const nodes = ref<Node[]>([]); const choices = ref<Choice[]>([]);
const loading = ref(true); const busy = ref(false); const message = ref(''); const editor = ref(false);
const editing = ref<string | null>(null); const selected = ref<string[]>([]);
const form = reactive({ name: '', registration: '', enabled: true });

function parseNode(value: unknown): Node | null {
  if (typeof value !== 'object' || value === null) return null;
  const item = value as Partial<Node>; const ep = item.endpoint;
  if (typeof item.id !== 'string' || !/^[0-9a-f]{32}$/.test(item.id) || typeof item.name !== 'string' ||
      typeof item.enabled !== 'boolean' || !Array.isArray(item.users) || !item.users.every(id => typeof id === 'string' && /^[0-9a-f]{32}$/.test(id)) ||
      typeof item.last_seen !== 'number' || !Number.isSafeInteger(item.last_seen) || item.last_seen < 0 || item.last_seen > 4_102_444_800 ||
      typeof item.pending_revision !== 'string' || !/^(|[0-9a-f]{64})$/.test(item.pending_revision) ||
      typeof item.applied_revision !== 'string' || !/^(|[0-9a-f]{64})$/.test(item.applied_revision) ||
      typeof ep !== 'object' || ep === null || typeof ep.domain !== 'string' || typeof ep.public_ip !== 'string' ||
      !Number.isInteger(ep.public_port) || ep.public_port < 1 || ep.public_port > 65535) return null;
  return item as Node;
}
function parseChoice(value: unknown): Choice | null {
  if (typeof value !== 'object' || value === null || !('id' in value) || !('name' in value) ||
      typeof value.id !== 'string' || !/^[0-9a-f]{32}$/.test(value.id) || typeof value.name !== 'string') return null;
  return { id: value.id, name: value.name };
}
async function request(path: string, options: RequestInit = {}): Promise<Response> {
  const response = await fetch(path, { ...options, cache: 'no-store', credentials: 'same-origin', signal: AbortSignal.timeout(15000) });
  if (response.status === 401) emit('expired');
  return response;
}
async function refresh() {
  loading.value = true; message.value = '';
  try {
    const [nodeResponse, userResponse] = await Promise.all([request('/api/remote-nodes'), request('/api/users')]);
    if (!nodeResponse.ok || !userResponse.ok) throw new Error('request failed');
    const nodeBody: unknown = await nodeResponse.json(); const userBody: unknown = await userResponse.json();
    if (typeof nodeBody !== 'object' || nodeBody === null || !('nodes' in nodeBody) || !Array.isArray(nodeBody.nodes) ||
        typeof userBody !== 'object' || userBody === null || !('users' in userBody) || !Array.isArray(userBody.users)) throw new Error('invalid response');
    const parsedNodes = nodeBody.nodes.map(parseNode); const parsedUsers = userBody.users.map(parseChoice);
    if (parsedNodes.some(value => value === null) || parsedUsers.some(value => value === null)) throw new Error('invalid data');
    nodes.value = parsedNodes as Node[]; choices.value = parsedUsers as Choice[];
  } catch { message.value = '无法加载节点，请稍后重试。'; }
  finally { loading.value = false; }
}
function edit(node?: Node) {
  editing.value = node?.id ?? null; form.name = node?.name ?? ''; form.enabled = node?.enabled ?? true;
  form.registration = ''; selected.value = node ? [...node.users] : []; message.value = ''; editor.value = true;
}
function cancel() { form.registration = ''; editor.value = false; }
async function save() {
  if (busy.value) return;
  let registration: unknown;
  if (!editing.value) {
    try {
      registration = JSON.parse(form.registration) as unknown;
      if (typeof registration !== 'object' || registration === null || Array.isArray(registration)) throw new Error('invalid registration');
    } catch { message.value = '请粘贴节点安装时提供的注册信息。'; return; }
  }
  const payload = editing.value ? { name: form.name, users: selected.value, enabled: form.enabled }
    : { name: form.name, users: selected.value, registration };
  busy.value = true; message.value = '';
  try {
    const response = await request('/api/remote-nodes' + (editing.value ? '/' + encodeURIComponent(editing.value) : ''), {
      method: editing.value ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': props.csrf },
      body: JSON.stringify(payload),
    });
    if (response.status === 409) { message.value = '节点编号冲突或达到数量上限。'; return; }
    if (!response.ok) throw new Error('save failed');
    form.registration = ''; editor.value = false; await refresh();
  } catch { message.value = '保存失败，请检查节点信息和用户选择。'; }
  finally { busy.value = false; }
}
function revision(node: Node): string {
  if (!node.pending_revision) return '尚未同步';
  return node.pending_revision === node.applied_revision ? '配置已确认' : '等待节点确认';
}
onMounted(() => { void refresh(); });
</script>

<template>
  <section class="nodes" aria-labelledby="nodes-heading">
    <div class="users-heading"><div><h2 id="nodes-heading">独立节点</h2><p>添加节点，并选择可使用该节点的用户。</p></div>
      <div class="heading-actions"><button type="button" @click="refresh">刷新</button><button type="button" class="primary" @click="edit()">添加节点</button></div>
    </div>
    <form v-if="editor" class="user-editor" @submit.prevent="save">
      <h3>{{ editing ? '编辑节点' : '添加节点' }}</h3>
      <div class="node-form-grid">
        <label>节点名称<input v-model="form.name" maxlength="60" required></label>
        <label v-if="!editing">节点注册信息<textarea v-model="form.registration" maxlength="8000" rows="5" autocomplete="off" spellcheck="false" required></textarea><small>粘贴节点安装时生成的注册信息。</small></label>
        <label v-if="editing" class="checkbox"><input v-model="form.enabled" type="checkbox">启用节点</label>
        <fieldset><legend>可用用户</legend><p v-if="!choices.length">暂无用户，可稍后编辑节点。</p>
          <div v-else class="node-choices"><label v-for="user in choices" :key="user.id" class="checkbox"><input v-model="selected" type="checkbox" :value="user.id">{{ user.name }}</label></div>
        </fieldset>
      </div>
      <div class="editor-actions"><button type="button" @click="cancel">取消</button><button class="primary" type="submit" :disabled="busy">保存节点</button></div>
    </form>
    <p v-if="message" class="message" role="alert">{{ message }}</p>
    <p v-if="loading" class="table-message">正在加载节点…</p>
    <p v-else-if="!nodes.length" class="table-message">暂无独立节点。</p>
    <div v-else class="table-wrap"><table>
      <thead><tr><th>节点</th><th>地址</th><th>用户</th><th>配置状态</th><th>最后同步</th><th>操作</th></tr></thead>
      <tbody><tr v-for="node in nodes" :key="node.id"><td>{{ node.name }}{{ node.enabled ? '' : '（已停用）' }}</td>
        <td>{{ node.endpoint.domain }}:{{ node.endpoint.public_port }}</td><td>{{ node.users.length }}</td><td>{{ revision(node) }}</td>
        <td>{{ node.last_seen ? new Date(node.last_seen * 1000).toLocaleString() : '从未' }}</td>
        <td class="user-actions"><button type="button" @click="edit(node)">编辑</button></td></tr></tbody>
    </table></div>
  </section>
</template>
