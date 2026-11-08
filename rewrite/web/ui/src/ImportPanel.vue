<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue';

type Row = { tag?: string; label?: string; exit_ip?: string; country?: string; port?: number; hysteria2?: boolean };
type ProxyItem = { tag: string; protocol: string; address: string; port: number; label: string; country: string; exit_ip: string; enabled: boolean; deleted_at: number;
  network?: string; security?: string; server_name?: string; host?: string; path?: string; alpn?: string; fingerprint?: string; tls?: boolean };
type Report = { status: string; id?: string; updated?: number; expires?: number; rows?: Row[]; reason?: string; apply_enabled?: boolean; items?: ProxyItem[] | null };
const props = defineProps<{ csrf: string }>();
const emit = defineEmits<{ expired: [] }>();
const report = ref<Report | null>(null); const loading = ref(true); const busy = ref(false);
const failure = ref(''); const pendingId = ref(''); const notice = ref('');
const managementDescription = ref('');
const form = reactive({ protocol: 'socks', label: '', text: '' });
const editing = ref<ProxyItem | null>(null);
const edit = reactive({ label:'', address:'', port:0, protocol:'socks', username:'', password:'', uuid:'', network:'tcp',
  security:'auto', tls:false, server_name:'', host:'', path:'', alpn:'', fingerprint:'' });
let timer: ReturnType<typeof setInterval> | undefined;
const waiting = computed(() => Boolean(pendingId.value && report.value?.id !== pendingId.value));
const blocked = computed(() => busy.value || waiting.value || !report.value ||
  ['unavailable', 'verifying', 'applying'].includes(report.value.status));

function parse(value: unknown): Report {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid report');
  const data = value as Partial<Report>;
  if (!['idle', 'verifying', 'ready', 'applying', 'complete', 'failed', 'expired', 'unavailable'].includes(data.status ?? '')) throw new Error('invalid status');
  if (data.apply_enabled !== undefined && typeof data.apply_enabled !== 'boolean') throw new Error('invalid capability');
  if (data.items !== undefined && data.items !== null && (!Array.isArray(data.items) || data.items.length > 40 ||
      !data.items.every(item => item && typeof item === 'object' &&
        ['tag', 'protocol', 'address', 'label', 'country', 'exit_ip'].every(key => typeof item[key as keyof ProxyItem] === 'string') &&
        ['network', 'security', 'server_name', 'host', 'path', 'alpn', 'fingerprint'].every(key => item[key as keyof ProxyItem] === undefined || typeof item[key as keyof ProxyItem] === 'string') &&
        (item.tls === undefined || typeof item.tls === 'boolean') &&
        Number.isSafeInteger(item.port) && item.port > 0 && item.port <= 65535 && typeof item.enabled === 'boolean' &&
        Number.isSafeInteger(item.deleted_at) && item.deleted_at >= 0))) throw new Error('invalid catalog');
  if (data.id !== undefined && (typeof data.id !== 'string' || !/^([0-9a-f]{32})?$/.test(data.id))) throw new Error('invalid id');
  if (data.reason !== undefined && (typeof data.reason !== 'string' || !['invalid', 'probe', 'conflict', 'expired', 'unavailable', 'apply_disabled', 'interrupted'].includes(data.reason))) throw new Error('invalid reason');
  if ([data.updated, data.expires].some(value => value !== undefined && (!Number.isSafeInteger(value) || value < 0))) throw new Error('invalid time');
  if (data.rows !== undefined && (!Array.isArray(data.rows) || data.rows.length > 40 || !data.rows.every(row => row && typeof row === 'object' && !Array.isArray(row) &&
    ['tag', 'label', 'exit_ip', 'country'].every(key => !(key in row) || typeof row[key as keyof Row] === 'string') &&
    (row.port === undefined || Number.isSafeInteger(row.port)) && (row.hysteria2 === undefined || typeof row.hysteria2 === 'boolean')))) throw new Error('invalid rows');
  return data as Report;
}
async function refresh() {
  try {
    const response = await fetch('/api/proxy-import', { credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(10000) });
    if (response.status === 401) { emit('expired'); return; }
    if (!response.ok) throw new Error('unavailable');
    const value = parse(await response.json());
    report.value = value; failure.value = '';
    if (pendingId.value && value.id === pendingId.value && ['ready', 'complete', 'failed', 'expired'].includes(value.status)) {
      pendingId.value = '';
      notice.value = value.status === 'complete' ? '代理配置已应用。' : value.status === 'ready' ? '检测完成，请核对结果。' : '';
      if (value.status !== 'ready') managementDescription.value = '';
    }
  } catch { failure.value = '暂时无法读取检测状态。'; }
  finally { loading.value = false; }
}
async function submit() {
  if (blocked.value || !form.label.trim() || !form.text.trim()) return;
  busy.value = true; failure.value = ''; notice.value = ''; managementDescription.value = '';
  try {
    const response = await fetch('/api/proxy-import', { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': props.csrf },
      body: JSON.stringify({ action: 'preview', ...form }), signal: AbortSignal.timeout(15000) });
    if (response.status === 401) { emit('expired'); return; }
    if (!response.ok) {
      const body: unknown = await response.json().catch(() => null);
      failure.value = body && typeof body === 'object' && 'detail' in body && typeof body.detail === 'string' ? body.detail : '检测请求未完成。';
      return;
    }
    const body: unknown = await response.json();
    if (!body || typeof body !== 'object' || !('id' in body) || typeof body.id !== 'string' || !/^[0-9a-f]{32}$/.test(body.id)) throw new Error('invalid response');
    pendingId.value = body.id; form.text = ''; notice.value = '检测请求已提交。';
    await refresh();
  } catch { failure.value = '提交结果暂时未知，请刷新状态后重试。'; }
  finally { busy.value = false; }
}
function clearEdit() { editing.value = null; edit.username = ''; edit.password = ''; edit.uuid = ''; edit.path = ''; edit.host = ''; edit.server_name = ''; }
function startEdit(item: ProxyItem) {
  editing.value = item;
  Object.assign(edit, { label:item.label, address:item.address, port:item.port, protocol:item.protocol, username:'', password:'', uuid:'',
    network:item.network || 'tcp', security:item.security || 'auto', tls:item.tls || false, server_name:item.server_name || '',
    host:item.host || '', path:item.path || '', alpn:item.alpn || '', fingerprint:item.fingerprint || '' });
}
async function manage(item: ProxyItem, operation: 'enable' | 'disable' | 'delete' | 'restore' | 'edit') {
  if (blocked.value || !report.value?.apply_enabled) return;
  const action = { enable: '启用', disable: '停用', delete: '移入回收站', restore: '从回收站找回', edit: '修改' }[operation];
  busy.value = true; failure.value = ''; notice.value = '';
  try {
    const changes = operation === 'edit' ? {
      label:edit.label, address:edit.address, port:edit.port, protocol:edit.protocol,
      ...(edit.protocol === 'vmess' ? { uuid:edit.uuid, network:edit.network, security:edit.security, tls:edit.tls,
        server_name:edit.tls ? edit.server_name : '', host:edit.host, path:edit.path,
        alpn:edit.tls ? edit.alpn : '', fingerprint:edit.tls ? edit.fingerprint : '' }
        : { username:edit.username, password:edit.password }),
    } : undefined;
    const response = await fetch('/api/proxy-import', { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': props.csrf },
      body: JSON.stringify({ action: 'manage', operation, tag: item.tag, ...(changes ? { changes } : {}) }), signal: AbortSignal.timeout(15000) });
    if (response.status === 401) { emit('expired'); return; }
    if (!response.ok) {
      const body: unknown = await response.json().catch(() => null);
      failure.value = body && typeof body === 'object' && 'detail' in body && typeof body.detail === 'string' ? body.detail : '操作未完成。';
      return;
    }
    const body: unknown = await response.json();
    if (!body || typeof body !== 'object' || !('id' in body) || typeof body.id !== 'string' || !/^[0-9a-f]{32}$/.test(body.id)) throw new Error('invalid response');
    managementDescription.value = `确认${action}「${item.label}」？`;
    clearEdit();
    pendingId.value = body.id; notice.value = '操作已提交，正在准备。';
    await refresh();
  } catch { failure.value = '操作结果暂时未知，请刷新状态后重试。'; }
  finally { busy.value = false; }
}
async function apply() {
  if (blocked.value || !report.value?.apply_enabled || report.value.status !== 'ready' || !report.value.id) return;
  busy.value = true; failure.value = ''; notice.value = '';
  try {
    const response = await fetch('/api/proxy-import', { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': props.csrf },
      body: JSON.stringify({ action: 'apply', preview_id: report.value.id }), signal: AbortSignal.timeout(15000) });
    if (response.status === 401) { emit('expired'); return; }
    if (!response.ok) {
      const body: unknown = await response.json().catch(() => null);
      failure.value = body && typeof body === 'object' && 'detail' in body && typeof body.detail === 'string' ? body.detail : '应用未完成。';
      return;
    }
    const body: unknown = await response.json();
    if (!body || typeof body !== 'object' || !('id' in body) || typeof body.id !== 'string' || !/^[0-9a-f]{32}$/.test(body.id)) throw new Error('invalid response');
    pendingId.value = body.id; notice.value = '应用请求已提交，正在等待结果。';
    await refresh();
  } catch { failure.value = '应用结果暂时未知，请刷新状态后重试。'; }
  finally { busy.value = false; }
}
function state(value: string): string {
  return ({ idle: '等待检测', verifying: '正在检测', ready: '检测完成', applying: '正在应用', complete: '已完成',
    failed: '操作失败', expired: '检测结果已过期', unavailable: '检测服务不可用' } as Record<string, string>)[value] ?? '未知';
}
function reason(value?: string): string {
  return ({ invalid: '输入或现有配置不符合要求。', probe: '代理连接或出口检测未通过。', conflict: '配置在检测期间发生变化，请重新检测。',
    expired: '检测结果已过期，请重新检测。', unavailable: '检测服务暂时不可用。', apply_disabled: '应用功能尚未启用。',
    interrupted: '检测过程已中断，请重新检测。' } as Record<string, string>)[value ?? ''] ?? '请检查输入和检测服务后重试。';
}
onMounted(() => { void refresh(); timer = setInterval(() => { void refresh(); }, 5000); });
onUnmounted(() => { if (timer) clearInterval(timer); form.text = ''; clearEdit(); });
</script>

<template>
  <section aria-labelledby="import-heading">
    <div class="users-heading"><div><h2 id="import-heading">固定代理</h2><p>检测 SOCKS5、HTTP 和 VMess 代理，查看可用出口。</p></div>
      <button type="button" @click="refresh">刷新</button></div>
    <p class="preview-note">{{ report?.apply_enabled ? '应用变更时，现有连接可能短暂中断。' : '当前服务只能检测，不能应用或修改现有配置。' }}</p>
    <p class="preview-note">支持双入口的固定代理在客户端中作为一个出口使用：默认优先 Hysteria 2，故障时切换至 HTTPS；也可在出口分组中手动选择协议。</p>
    <p v-if="loading" class="table-message">正在读取检测状态…</p>
    <template v-else-if="report">
      <div class="webshare-status" aria-live="polite"><strong>{{ waiting ? '等待工作进程处理' : state(report.status) }}</strong>
        <span v-if="report.status === 'ready' && !waiting">仅供预览，尚未应用。</span>
        <span v-if="report.status === 'failed' && !waiting">{{ reason(report.reason) }}</span></div>
      <div v-if="report.status === 'ready' && !waiting && report.rows?.length" class="table-wrap"><table>
        <thead><tr><th>名称</th><th>入口</th><th>出口</th><th>地区</th><th>端口</th></tr></thead>
        <tbody><tr v-for="(row, index) in report.rows" :key="row.tag || index"><td>{{ row.label || '—' }}</td><td>{{ row.tag || '—' }}</td>
          <td>{{ row.exit_ip || '—' }}</td><td>{{ row.country || '—' }}</td><td>{{ row.port ?? '—' }}</td></tr></tbody></table></div>
      <div v-if="report.status === 'ready' && !waiting && report.apply_enabled" class="form-actions">
        <p v-if="managementDescription">{{ managementDescription }}</p>
        <button type="button" class="primary" :disabled="blocked" @click="apply">确认应用</button>
      </div>
      <div v-if="report.items?.length" class="table-wrap"><table>
        <thead><tr><th>已导入代理</th><th>地址</th><th>状态</th><th>操作</th></tr></thead>
        <tbody><tr v-for="item in report.items" :key="item.tag"><td>{{ item.label }}<br><small>{{ item.tag }} · {{ item.country }}</small></td>
          <td>{{ item.address }}:{{ item.port }}<br><small>{{ item.protocol }}</small></td>
          <td>{{ item.deleted_at ? '回收站' : item.enabled ? '已启用' : '已停用' }}</td>
          <td v-if="report.apply_enabled">
            <button v-if="item.deleted_at" type="button" :disabled="blocked" @click="manage(item, 'restore')">找回</button>
            <template v-else><button type="button" :disabled="blocked" @click="startEdit(item)">编辑</button>
              <button type="button" :disabled="blocked" @click="manage(item, item.enabled ? 'disable' : 'enable')">{{ item.enabled ? '停用' : '启用' }}</button>
              <button type="button" :disabled="blocked" @click="manage(item, 'delete')">删除</button></template>
          </td><td v-else>—</td></tr></tbody></table></div>
      <form v-if="editing" class="import-form" @submit.prevent="manage(editing, 'edit')">
        <h3>编辑 {{ editing.label }}</h3>
        <div class="editor-grid"><label>名称<input v-model="edit.label" maxlength="60" required></label>
          <label>协议<select v-model="edit.protocol"><template v-if="editing.protocol === 'vmess'"><option value="vmess">VMess</option></template>
            <template v-else><option value="socks">SOCKS5</option><option value="http">HTTP</option></template></select></label></div>
        <div class="editor-grid"><label>代理地址<input v-model="edit.address" maxlength="253" required></label>
          <label>端口<input v-model.number="edit.port" type="number" min="1" max="65535" required></label></div>
        <template v-if="edit.protocol === 'vmess'">
          <label>新 UUID<input v-model="edit.uuid" type="password" autocomplete="new-password" placeholder="留空保留原值"></label>
          <div class="editor-grid"><label>传输<select v-model="edit.network"><option value="tcp">TCP</option><option value="ws">WebSocket</option><option value="grpc">gRPC</option></select></label>
            <label>加密<select v-model="edit.security"><option>auto</option><option>aes-128-gcm</option><option>chacha20-poly1305</option><option>none</option><option>zero</option></select></label></div>
          <label class="checkbox"><input v-model="edit.tls" type="checkbox">启用 TLS</label>
          <div class="editor-grid"><label>TLS 服务名<input v-model="edit.server_name" maxlength="253"></label><label>Host<input v-model="edit.host" maxlength="253"></label></div>
          <label>路径或 gRPC 服务名<input v-model="edit.path" maxlength="1024"></label>
          <div class="editor-grid"><label>ALPN<input v-model="edit.alpn" maxlength="100"></label><label>TLS 指纹<input v-model="edit.fingerprint" maxlength="32"></label></div>
        </template>
        <div v-else class="editor-grid"><label>新账号<input v-model="edit.username" autocomplete="off" placeholder="留空保留原值"></label>
          <label>新密码<input v-model="edit.password" type="password" autocomplete="new-password" placeholder="留空保留原值"></label></div>
        <div><button type="submit" class="primary" :disabled="blocked">检测修改</button><button type="button" @click="clearEdit">取消</button></div>
      </form>
      <form class="import-form" @submit.prevent="submit">
        <div class="editor-grid"><label>协议<select v-model="form.protocol"><option value="socks">SOCKS5</option><option value="http">HTTP</option><option value="vmess">VMess</option></select></label>
          <label>名称前缀<input v-model="form.label" maxlength="30" required></label></div>
        <label>{{ form.protocol === 'vmess' ? 'VMess 分享链接' : '代理列表（每行：IP:端口:账号:密码）' }}
          <textarea v-model="form.text" rows="4" maxlength="12000" autocomplete="off" spellcheck="false" required></textarea></label>
        <div><button class="primary" type="submit" :disabled="blocked || !form.label.trim() || !form.text.trim()">{{ busy ? '正在提交…' : '检测代理' }}</button></div>
      </form>
    </template>
    <p v-if="failure" class="message" role="alert">{{ failure }}</p><p v-if="notice" class="notice" aria-live="polite">{{ notice }}</p>
  </section>
</template>
