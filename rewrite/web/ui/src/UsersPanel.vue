<script setup lang="ts">
import { onMounted, onUnmounted, reactive, ref } from 'vue';

type User = { id: string; name: string; enabled: boolean; quota: string; upload: string; download: string;
  expires: number; created: number; status: 'active' | 'disabled' | 'expired' | 'exhausted' };
type Pending = { action: 'delete' | 'rotate' | 'reset'; user: User };
type LinkItem = { label: string; value: string; kind: string };
type DiagnosticFormat = { status: 'ready' | 'inactive' | 'unavailable' | 'error'; node_count?: number;
  groups?: string[]; inherits_local_base?: boolean; sha256?: string };
type Diagnostic = { generated_at: number; origin: string; user_status: User['status'];
  template: { name: string; revision: number | null; published_at: number | null };
  formats: { nodes: DiagnosticFormat; clash: DiagnosticFormat; shadowrocket: DiagnosticFormat } };
const props = defineProps<{ csrf: string }>();
const emit = defineEmits<{ expired: []; changed: [] }>();
const users = ref<User[]>([]);
const loading = ref(true);
const busy = ref(false);
const message = ref('');
const coreSyncMessage = ref('');
type SyncTicket = { instance: string; revision: number };
let syncTicket: SyncTicket | null = null;
let syncTimer: ReturnType<typeof setTimeout> | undefined;
let syncRequest = 0;
let disposed = false;
const editor = ref(false);
const editing = ref<string | null>(null);
const originalDate = ref('');
const originalExpires = ref(0);
const pending = ref<Pending | null>(null);
const linksUser = ref<User | null>(null);
const links = ref<LinkItem[]>([]);
const linksLoading = ref(false);
const linksNotice = ref('');
let linksRequest = 0;
const diagnosticUser = ref<User | null>(null);
const diagnostic = ref<Diagnostic | null>(null);
const diagnosticLoading = ref(false);
const diagnosticNotice = ref('');
let diagnosticRequest = 0;
const form = reactive({ name: '', quota: '0', expires: '', enabled: true });
const statusLabel: Record<User['status'], string> = { active: '正常', disabled: '已停用', expired: '已到期', exhausted: '配额已用尽' };

function parseUser(value: unknown): User | null {
  if (typeof value !== 'object' || value === null) return null;
  const item = value as Partial<User>;
  if (typeof item.id !== 'string' || !/^[0-9a-f]{32}$/.test(item.id) || typeof item.name !== 'string' ||
      typeof item.enabled !== 'boolean' || ![item.quota, item.upload, item.download].every(v => typeof v === 'string' && /^(0|[1-9][0-9]*)$/.test(v)) ||
      typeof item.expires !== 'number' || !Number.isSafeInteger(item.expires) || item.expires < 0 || item.expires > 4_102_444_800 ||
      typeof item.created !== 'number' || !Number.isSafeInteger(item.created) || item.created < 0 || !item.status || !Object.hasOwn(statusLabel, item.status)) return null;
  return item as User;
}
function parseDiagnostic(value: unknown): Diagnostic | null {
  if (typeof value !== 'object' || value === null) return null;
  const item = value as Record<string, unknown>;
  if (typeof item.origin !== 'string' || item.origin.length > 2048 || typeof item.generated_at !== 'number' ||
      !Number.isSafeInteger(item.generated_at) || item.generated_at < 0 || typeof item.user_status !== 'string' ||
      !Object.hasOwn(statusLabel, item.user_status) || typeof item.template !== 'object' || item.template === null ||
      typeof item.formats !== 'object' || item.formats === null) return null;
  const template = item.template as Record<string, unknown>;
  if (typeof template.name !== 'string' || (template.revision !== null &&
      (typeof template.revision !== 'number' || !Number.isSafeInteger(template.revision)))) return null;
  const formats = item.formats as Record<string, unknown>;
  for (const key of ['nodes', 'clash', 'shadowrocket']) {
    if (typeof formats[key] !== 'object' || formats[key] === null) return null;
    const format = formats[key] as Record<string, unknown>;
    if (typeof format.status !== 'string' || !['ready', 'inactive', 'unavailable', 'error'].includes(format.status)) return null;
    if (format.status === 'ready' && (typeof format.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(format.sha256))) return null;
    if (format.node_count !== undefined && (typeof format.node_count !== 'number' || !Number.isSafeInteger(format.node_count) || format.node_count < 0)) return null;
    if (format.groups !== undefined && (!Array.isArray(format.groups) || !format.groups.every(name => typeof name === 'string'))) return null;
    if (format.inherits_local_base !== undefined && typeof format.inherits_local_base !== 'boolean') return null;
  }
  return value as Diagnostic;
}
function bytes(value: bigint): string {
  if (value < 1000n) return `${value} B`;
  const units = ['KB', 'MB', 'GB', 'TB', 'PB', 'EB'];
  let divisor = 1000n; let index = 0;
  while (value >= divisor * 1000n && index < units.length - 1) { divisor *= 1000n; index++; }
  const tenth = value * 10n / divisor;
  return `${tenth / 10n}.${tenth % 10n} ${units[index]}`;
}
function quotaInput(value: string): string {
  const number = BigInt(value); const whole = number / 1_000_000_000n;
  const remainder = (number % 1_000_000_000n).toString().padStart(9, '0').replace(/0+$/, '');
  return remainder ? `${whole}.${remainder}` : String(whole);
}
function quotaBytes(value: string): string | null {
  const match = /^(0|[1-9][0-9]*)(?:\.([0-9]{1,9}))?$/.exec(value.trim());
  if (!match) return null;
  const amount = BigInt(match[1]!) * 1_000_000_000n + BigInt((match[2] ?? '').padEnd(9, '0'));
  return amount <= 10_000_000_000_000_000n ? amount.toString() : null;
}
function localDate(timestamp: number): string {
  if (!timestamp) return '';
  const date = new Date(timestamp * 1000);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}
function displayDate(timestamp: number): string { return timestamp ? new Date(timestamp * 1000).toLocaleString() : '不限'; }
async function request(path: string, options: RequestInit = {}): Promise<Response> {
  const response = await fetch(path, { ...options, cache: 'no-store', credentials: 'same-origin', signal: AbortSignal.timeout(15000) });
  if (response.status === 401) emit('expired');
  return response;
}
function trackCoreSync(value: unknown) {
  if (disposed) return;
  if (syncTimer) clearTimeout(syncTimer);
  syncRequest++;
  const ticket = value && typeof value === 'object' && 'local_core_sync' in value ? value.local_core_sync : null;
  if (!ticket || typeof ticket !== 'object' || !('instance' in ticket) || !('revision' in ticket) ||
      typeof ticket.instance !== 'string' || !/^[0-9a-f]{32}$/.test(ticket.instance) ||
      typeof ticket.revision !== 'number' || !Number.isSafeInteger(ticket.revision) || ticket.revision < 1) {
    syncTicket = null;
    coreSyncMessage.value = '更改已保存，本地核心同步状态未知；独立节点状态需另行检查。';
    return;
  }
  syncTicket = { instance: ticket.instance, revision: ticket.revision };
  coreSyncMessage.value = '更改已保存，正在检查本地核心同步；独立节点状态需另行检查。';
  void refreshCoreSync(syncRequest);
}
async function refreshCoreSync(serial: number) {
  const ticket = syncTicket;
  if (disposed || !ticket || serial !== syncRequest) return;
  try {
    const response = await request('/api/core-sync');
    if (response.status === 401) return;
    if (!response.ok) throw new Error('sync unavailable');
    const value: unknown = await response.json();
    if (serial !== syncRequest || !syncTicket) return;
    if (!value || typeof value !== 'object' || !('instance' in value) || value.instance !== ticket.instance) {
      syncTicket = null;
      coreSyncMessage.value = '控制器已重启或状态不可用，请重新核对本地核心和独立节点。';
      return;
    }
    if (!('state' in value) || !('applied_revision' in value)) throw new Error('invalid sync state');
    if (value.state === 'ready' && typeof value.applied_revision === 'number' &&
        Number.isSafeInteger(value.applied_revision) && value.applied_revision >= ticket.revision) {
      syncTicket = null;
      coreSyncMessage.value = '本地核心最近一次核对已应用更改；独立节点状态需另行检查。';
      return;
    }
    coreSyncMessage.value = value.state === 'pending'
      ? '更改已保存，本地核心仍在同步；独立节点状态需另行检查。'
      : '本地核心同步暂不可确认，旧连接可能仍然有效；请检查核心和独立节点。';
  } catch {
    if (serial !== syncRequest) return;
    coreSyncMessage.value = '本地核心同步暂不可确认，旧连接可能仍然有效；请检查核心和独立节点。';
  }
  if (serial === syncRequest && syncTicket) syncTimer = setTimeout(() => { void refreshCoreSync(serial); }, 3000);
}
async function refresh() {
  loading.value = true; message.value = '';
  try {
    const response = await request('/api/users');
    if (!response.ok) throw new Error('request failed');
    const body: unknown = await response.json();
    if (typeof body !== 'object' || body === null || !('users' in body) || !Array.isArray(body.users)) throw new Error('invalid response');
    const parsed = body.users.map(parseUser);
    if (parsed.some(item => item === null)) throw new Error('invalid user');
    users.value = parsed as User[];
  } catch { message.value = '无法加载用户，请稍后重试。'; }
  finally { loading.value = false; }
}
function edit(user?: User) {
  closeLinks();
  closeDiagnostic();
  editing.value = user?.id ?? null;
  form.name = user?.name ?? ''; form.quota = user ? quotaInput(user.quota) : '0';
  form.expires = user ? localDate(user.expires) : ''; form.enabled = user?.enabled ?? true;
  originalDate.value = form.expires; originalExpires.value = user?.expires ?? 0;
  pending.value = null; message.value = ''; editor.value = true;
}
async function save() {
  if (busy.value) return;
  const quota = quotaBytes(form.quota);
  const expires = form.expires === originalDate.value ? originalExpires.value : form.expires ? Math.floor(new Date(form.expires).getTime() / 1000) : 0;
  if (quota === null || !Number.isSafeInteger(expires) || expires < 0 || expires > 4_102_444_800) {
    message.value = '请检查配额和到期时间。配额最多保留 9 位小数。'; return;
  }
  // Insert the validated decimal string directly so large byte values never
  // pass through an imprecise JavaScript Number.
  const body = `{"name":${JSON.stringify(form.name)},"enabled":${form.enabled},"quota":${quota},"expires":${expires}}`;
  busy.value = true; message.value = '';
  try {
    const response = await request('/api/users' + (editing.value ? '/' + encodeURIComponent(editing.value) : ''), {
      method: editing.value ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': props.csrf }, body,
    });
    if (!response.ok) throw new Error('save failed');
    const result: unknown = await response.json();
    editor.value = false; await refresh(); trackCoreSync(result); emit('changed');
  } catch { message.value = '保存结果暂不可确认，请刷新用户列表并在概览检查本地核心状态后再操作。'; }
  finally { busy.value = false; }
}
async function confirmAction() {
  if (!pending.value || busy.value) return;
  const { user, action } = pending.value;
  closeLinks();
  busy.value = true; message.value = '';
  try {
    const path = '/api/users/' + encodeURIComponent(user.id) + (action === 'rotate' ? '/rotate' : action === 'reset' ? '/reset-traffic' : '');
    const response = await request(path, { method: action === 'delete' ? 'DELETE' : 'POST', headers: { 'X-CSRF-Token': props.csrf } });
    if (action === 'reset' && response.status === 409) {
      message.value = '该用户曾使用独立节点，离线节点可能仍有未上报流量，无法安全清零。'; return;
    }
    if (action === 'reset' && response.status === 503) {
      message.value = '无法确认清零，请检查核心和管理服务后刷新用户用量。'; return;
    }
    if (!response.ok) throw new Error('action failed');
    const result: unknown = await response.json();
    pending.value = null; await refresh();
    if (action !== 'reset') trackCoreSync(result);
    emit('changed');
  } catch { message.value = '操作结果暂不可确认，请刷新用户列表并在概览检查本地核心状态后再操作。'; }
  finally { busy.value = false; }
}
function closeLinks() { linksRequest++; linksUser.value = null; links.value = []; linksNotice.value = ''; }
function closeDiagnostic() { diagnosticRequest++; diagnosticUser.value = null; diagnostic.value = null; diagnosticNotice.value = ''; }
function refreshLinks() { if (linksUser.value) void showLinks(linksUser.value); }
defineExpose({ refreshLinks, refresh, closeLinks });
async function showLinks(user: User) {
  closeDiagnostic();
  const serial = ++linksRequest;
  linksUser.value = user; links.value = []; linksNotice.value = ''; linksLoading.value = true;
  try {
    const base = '/api/users/' + encodeURIComponent(user.id);
    const responses = await Promise.all([request(base + '/links'), request(base + '/shadowrocket')]);
    if (serial !== linksRequest) return;
    if (responses.some(response => !response.ok)) throw new Error('links failed');
    const [node, client]: unknown[] = await Promise.all(responses.map(response => response.json()));
    if (serial !== linksRequest) return;
    if (!node || typeof node !== 'object' || !client || typeof client !== 'object') throw new Error('invalid links');
    const nodes = node as Record<string, unknown>; const clients = client as Record<string, unknown>;
    const result: LinkItem[] = [];
    const add = (source: Record<string, unknown>, key: string, label: string, kind = key) => {
      const value = source[key];
      if (typeof value === 'string' && value.length > 0 && value.length <= 8192) result.push({ label, value, kind });
    };
    add(nodes, 'subscription', '通用订阅');
    add(clients, 'clash', 'Clash 配置');
    add(clients, 'shadowrocket', '小火箭配置');
    add(clients, 'dns_install', '小火箭 DNS 模块', 'dns');
    for (const [key, label] of [['reality','REALITY'],['websocket','HTTPS'],['hysteria2','Hysteria 2'],['hysteria2-brutal','Hysteria 2 Brutal 40 Mbps'],['vmess','VMess']]) add(nodes, key!, label!);
    if (!result.length) throw new Error('empty links');
    links.value = result;
  } catch { if (serial === linksRequest) linksNotice.value = '无法读取客户端链接，请重试。'; }
  finally { if (serial === linksRequest) linksLoading.value = false; }
}
async function showDiagnostic(user: User) {
  closeLinks(); editor.value = false; pending.value = null;
  const serial = ++diagnosticRequest;
  diagnosticUser.value = user; diagnostic.value = null; diagnosticNotice.value = ''; diagnosticLoading.value = true;
  try {
    const response = await request('/api/users/' + encodeURIComponent(user.id) + '/subscription-diagnostics');
    if (!response.ok) throw new Error('diagnostic failed');
    const value: unknown = await response.json();
    if (serial !== diagnosticRequest) return;
    const parsed = parseDiagnostic(value);
    if (!parsed) throw new Error('invalid response');
    diagnostic.value = parsed;
  } catch { if (serial === diagnosticRequest) diagnosticNotice.value = '无法生成订阅诊断，请稍后重试。'; }
  finally { if (serial === diagnosticRequest) diagnosticLoading.value = false; }
}
const diagnosticFormats: Array<[keyof Diagnostic['formats'], string]> = [
  ['nodes', '节点订阅'], ['clash', 'Clash 配置'], ['shadowrocket', '小火箭远程配置'],
];
const diagnosticStatus: Record<DiagnosticFormat['status'], string> = {
  ready: '可生成', inactive: '用户不可用', unavailable: '未配置远程配置', error: '生成失败',
};
async function copyLink(item: LinkItem) {
  try { await navigator.clipboard.writeText(item.value); linksNotice.value = `已复制${item.label}。`; }
  catch { linksNotice.value = '复制失败，请选择链接手动复制。'; }
}
onMounted(() => { void refresh(); });
onUnmounted(() => { disposed = true; syncRequest++; if (syncTimer) clearTimeout(syncTimer); syncTicket = null; });
</script>

<template>
  <section class="users" aria-labelledby="users-heading">
    <div class="users-heading"><div><h2 id="users-heading">用户管理</h2><p>管理用户的状态、流量配额和到期时间。</p></div><button class="primary" type="button" @click="edit()">新建用户</button></div>
    <form v-if="editor" class="user-editor" @submit.prevent="save">
      <h3>{{ editing ? '编辑用户' : '新建用户' }}</h3>
      <div class="editor-grid">
        <label>用户名称<input v-model="form.name" maxlength="60" required></label>
        <label>流量配额（GB）<input v-model="form.quota" inputmode="decimal" maxlength="19" required><small>0 表示不限制</small></label>
        <label>到期时间<input v-model="form.expires" type="datetime-local"><small>留空表示不过期</small></label>
        <label class="checkbox"><input v-model="form.enabled" type="checkbox">允许连接</label>
      </div>
      <div class="editor-actions"><button type="button" @click="editor = false">取消</button><button class="primary" type="submit" :disabled="busy">保存用户</button></div>
    </form>
    <div v-if="pending" class="confirmation" role="alert">
      <p>{{ pending.action === 'delete' ? '确定删除' : pending.action === 'rotate' ? '确定重置凭据：' : '确定清零流量：' }}{{ pending.user.name }}？{{ pending.action === 'rotate' ? '订阅凭据会失效；核心同步完成前，旧连接可能仍可用。' : pending.action === 'reset' ? '已用尽配额的用户可能恢复连接。' : '订阅会失效；核心同步完成前，旧连接可能仍可用。' }}{{ pending.action !== 'reset' ? '独立节点需另行检查。' : '' }}</p>
      <div class="editor-actions"><button type="button" @click="pending = null">取消</button><button type="button" class="danger" :disabled="busy" @click="confirmAction">确认{{ pending.action === 'delete' ? '删除' : pending.action === 'reset' ? '清零' : '重置' }}</button></div>
    </div>
    <div v-if="linksUser" class="user-editor client-links">
      <div class="users-heading"><div><h3>{{ linksUser.name }} · 客户端链接</h3><p>链接包含个人凭据，请只分享给该用户。</p></div><button type="button" @click="closeLinks">关闭</button></div>
      <p v-if="linksLoading">正在读取链接…</p>
      <div v-for="item in links" :key="item.label" class="client-link">
        <label>{{ item.label }}<input :value="item.value" readonly @focus="($event.target as HTMLInputElement).select()"></label>
        <button type="button" @click="copyLink(item)">复制</button>
        <details><summary>二维码</summary><img :src="'/api/users/' + encodeURIComponent(linksUser.id) + '/qr/' + encodeURIComponent(item.kind)" :alt="item.label + '二维码'"></details>
      </div>
      <p v-if="linksNotice" class="notice" role="status">{{ linksNotice }}</p>
    </div>
    <div v-if="diagnosticUser" class="user-editor subscription-diagnostic">
      <div class="users-heading"><div><h3>{{ diagnosticUser.name }} · 订阅诊断</h3><p>查看本面板当前生成的配置。</p></div><button type="button" @click="closeDiagnostic">关闭</button></div>
      <p v-if="diagnosticLoading">正在检查…</p>
      <template v-if="diagnostic">
        <p>面板地址：{{ diagnostic.origin }}<br>用户状态：{{ statusLabel[diagnostic.user_status] || '未知' }}<br>
          规则模板：{{ diagnostic.template.name }}<template v-if="diagnostic.template.revision !== null"> · 已发布版本 {{ diagnostic.template.revision }}</template><br>
          生成检查：{{ displayDate(diagnostic.generated_at) }}</p>
        <p class="preview-note">最近获取时间和客户端是否已启用：未知。此检查不会读取客户端配置，也不会记录订阅请求。</p>
        <div v-for="[key, label] in diagnosticFormats" :key="key" class="diagnostic-format">
          <strong>{{ label }}</strong> · {{ diagnosticStatus[diagnostic.formats[key].status] || '未知' }}
          <template v-if="diagnostic.formats[key].status === 'ready'">
            <div v-if="diagnostic.formats[key].node_count !== undefined">节点数：{{ diagnostic.formats[key].node_count }}</div>
            <div v-if="diagnostic.formats[key].groups">策略组：{{ diagnostic.formats[key].groups?.join('、') || '无' }}</div>
            <div v-if="diagnostic.formats[key].inherits_local_base">另继承客户端 default.conf，以上仅列出服务端生成的分组。</div>
            <div>配置摘要：<code>{{ diagnostic.formats[key].sha256?.slice(0, 16) }}</code></div>
          </template>
        </div>
        <p class="preview-note">摘要用于比较同一格式的服务端生成内容；Clash 摘要基于结构化配置，其余格式基于生成文本。客户端可能仍使用旧地址或旧配置。</p>
      </template>
      <p v-if="diagnosticNotice" class="notice" role="status">{{ diagnosticNotice }}</p>
    </div>
    <p v-if="message" class="message" role="alert">{{ message }}</p>
    <p v-if="coreSyncMessage" class="sync-notice" role="status">{{ coreSyncMessage }}</p>
    <p v-if="loading" class="table-message">正在加载用户…</p>
    <p v-else-if="!users.length" class="table-message">暂无用户。</p>
    <div v-else class="table-wrap user-list"><table>
      <thead><tr><th>用户</th><th>状态</th><th>流量 / 配额</th><th>到期</th><th>操作</th></tr></thead>
      <tbody><tr v-for="user in users" :key="user.id">
        <td>{{ user.name }}</td><td><span class="mobile-user-label" aria-hidden="true">状态：</span>{{ statusLabel[user.status] }}</td>
        <td><span class="mobile-user-label" aria-hidden="true">流量 / 配额：</span>{{ bytes(BigInt(user.upload) + BigInt(user.download)) }} / {{ user.quota === '0' ? '不限' : bytes(BigInt(user.quota)) }}</td>
        <td><span class="mobile-user-label" aria-hidden="true">到期：</span>{{ displayDate(user.expires) }}</td>
        <td class="user-actions"><button type="button" @click="showLinks(user)">客户端</button><button type="button" @click="showDiagnostic(user)">订阅诊断</button><button type="button" @click="edit(user)">编辑</button><button type="button" @click="pending = { action: 'rotate', user }; editor = false; closeDiagnostic()">重置凭据</button><button type="button" @click="pending = { action: 'reset', user }; editor = false; closeDiagnostic()">清零流量</button><button type="button" @click="pending = { action: 'delete', user }; editor = false; closeDiagnostic()">删除</button></td>
      </tr></tbody>
    </table></div>
  </section>
</template>
