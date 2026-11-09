<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, reactive, ref } from 'vue';

type Row = { tag?: string; label?: string; exit_ip?: string; country?: string; port?: number; hysteria2?: boolean };
type ProxyItem = { tag: string; protocol: string; address: string; port: number; label: string; country: string; exit_ip: string; enabled: boolean; deleted_at: number;
  network?: string; security?: string; server_name?: string; host?: string; path?: string; alpn?: string; fingerprint?: string; tls?: boolean };
type Report = { status: string; id?: string; updated?: number; expires?: number; rows?: Row[]; reason?: string; apply_enabled?: boolean; items?: ProxyItem[] | null };
type Operation = 'import' | 'edit' | 'delete' | 'enable' | 'disable' | 'restore';
type Current = { kind: Operation; name: string; tags: string[]; phase: 'preview' | 'apply' };
const props = defineProps<{ csrf: string }>();
const emit = defineEmits<{ expired: [] }>();
const report = ref<Report | null>(null); const loading = ref(true); const busy = ref(false);
const failure = ref(''); const fetchFailure = ref(''); const pendingId = ref(''); const notice = ref('');
const current = ref<Current | null>(null); const dismissedId = ref('');
const panel = ref<'import' | 'edit' | null>(null); const panelElement = ref<HTMLElement | null>(null);
const confirmationElement = ref<HTMLElement | null>(null);
const listElement = ref<HTMLElement | null>(null);
const query = ref(''); const filter = ref<'all' | 'enabled' | 'disabled' | 'trash'>('all');
const selected = ref<string[]>([]); const recent = ref<string[]>([]);
const form = reactive({ protocol: 'socks', label: '', text: '' });
const editing = ref<ProxyItem | null>(null);
const edit = reactive({ label:'', address:'', port:0, protocol:'socks', username:'', password:'', uuid:'', network:'tcp',
  security:'auto', tls:false, server_name:'', host:'', path:'', alpn:'', fingerprint:'' });
let timer: ReturnType<typeof setInterval> | undefined;
const items = computed(() => report.value?.items ?? []);
const counts = computed(() => ({ all: items.value.filter(i => !i.deleted_at).length,
  enabled: items.value.filter(i => !i.deleted_at && i.enabled).length,
  disabled: items.value.filter(i => !i.deleted_at && !i.enabled).length,
  trash: items.value.filter(i => Boolean(i.deleted_at)).length }));
const visibleItems = computed(() => {
  const term = query.value.trim().toLocaleLowerCase();
  return items.value.filter(i => {
    if (filter.value === 'trash' ? !i.deleted_at : Boolean(i.deleted_at)) return false;
    if (filter.value === 'enabled' && !i.enabled || filter.value === 'disabled' && i.enabled) return false;
    return !term || [i.label, i.tag, i.address, i.exit_ip, i.country, i.protocol].some(v => v.toLocaleLowerCase().includes(term));
  }).sort((a, b) => Number(recent.value.includes(b.tag)) - Number(recent.value.includes(a.tag)));
});
const visibleSelected = computed(() => visibleItems.value.filter(i => selected.value.includes(i.tag)).length);
const waiting = computed(() => Boolean(pendingId.value && report.value?.id !== pendingId.value));
const confirming = computed(() => report.value?.status === 'ready' && !waiting.value && report.value.id !== dismissedId.value);
const blocked = computed(() => busy.value || waiting.value || !report.value ||
  ['unavailable', 'verifying', 'applying'].includes(report.value.status));
const locked = computed(() => blocked.value || confirming.value);
const actionName: Record<Operation, string> = { import:'导入', edit:'保存修改', delete:'删除', enable:'启用', disable:'停用', restore:'找回' };
const previewTitle = computed(() => {
  if (!current.value) return '待确认的代理变更';
  if (current.value.kind === 'delete') return `确认删除 ${current.value.tags.length} 个代理？`;
  if (current.value.kind === 'import') return `检测完成，可以导入 ${report.value?.rows?.length ?? 0} 个代理`;
  return `确认${actionName[current.value.kind]}「${current.value.name}」？`;
});

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
function closePanel() { panel.value = null; editing.value = null; form.text = ''; edit.username = ''; edit.password = ''; edit.uuid = ''; }
function scrollPanel() { void nextTick(() => { if (window.matchMedia('(max-width: 800px)').matches) panelElement.value?.scrollIntoView({ behavior:'smooth', block:'start' }); }); }
function finish(value: Report) {
  const op = current.value;
  if (!op) { notice.value = '代理变更已应用。'; return; }
  if (op.kind === 'import') {
    recent.value = op.tags;
    filter.value = 'all'; query.value = '';
    const shown = op.tags.filter(tag => value.items?.some(item => item.tag === tag && !item.deleted_at)).length;
    notice.value = shown === op.tags.length && shown > 0 ? `已导入 ${shown} 个代理，已在列表顶部标出。` : '导入已完成，正在同步列表，请刷新查看。';
    form.label = '';
    void nextTick(() => listElement.value?.scrollIntoView({ behavior:'smooth', block:'start' }));
  } else if (op.kind === 'delete') {
    notice.value = `已将 ${op.tags.length} 个代理移入回收站，可在“回收站”中找回。`;
    selected.value = [];
  } else {
    notice.value = op.kind === 'restore' ? `已找回「${op.name}」，当前为停用状态，可在列表中启用。` : `已${actionName[op.kind]}「${op.name}」。`;
  }
  current.value = null; closePanel();
}
async function refresh() {
  try {
    const response = await fetch('/api/proxy-import', { credentials:'same-origin', cache:'no-store', signal:AbortSignal.timeout(10000) });
    if (response.status === 401) { emit('expired'); return; }
    if (!response.ok) throw new Error('unavailable');
    const value = parse(await response.json()); report.value = value; fetchFailure.value = '';
    if (value.items) selected.value = selected.value.filter(tag => value.items?.some(item => item.tag === tag && !item.deleted_at));
    if (pendingId.value && value.id === pendingId.value && ['ready', 'complete', 'failed', 'expired'].includes(value.status)) {
      pendingId.value = '';
      if (value.status === 'ready') {
        if (current.value?.kind === 'import') current.value.tags = (value.rows ?? []).flatMap(row => row.tag ? [row.tag] : []);
        notice.value = ''; void nextTick(() => confirmationElement.value?.scrollIntoView({ behavior:'smooth', block:'start' }));
      } else if (value.status === 'complete') finish(value);
      else { notice.value = ''; current.value = null; }
    }
  } catch { fetchFailure.value = '暂时无法读取代理列表或处理状态，请刷新重试。'; }
  finally { loading.value = false; }
}
async function send(payload: object, op: Current) {
  if (locked.value) return;
  busy.value = true; failure.value = ''; notice.value = '';
  try {
    const response = await fetch('/api/proxy-import', { method:'POST', credentials:'same-origin', cache:'no-store',
      headers: { 'Content-Type':'application/json', 'X-CSRF-Token':props.csrf }, body:JSON.stringify(payload), signal:AbortSignal.timeout(15000) });
    if (response.status === 401) { emit('expired'); return; }
    if (!response.ok) {
      const body: unknown = await response.json().catch(() => null);
      failure.value = body && typeof body === 'object' && 'detail' in body && typeof body.detail === 'string' ? body.detail : '请求未完成。'; return;
    }
    const body: unknown = await response.json();
    if (!body || typeof body !== 'object' || !('id' in body) || typeof body.id !== 'string' || !/^[0-9a-f]{32}$/.test(body.id)) throw new Error('invalid response');
    current.value = op; pendingId.value = body.id; dismissedId.value = ''; form.text = ''; edit.username = ''; edit.password = ''; edit.uuid = '';
    notice.value = op.kind === 'import' || op.kind === 'edit' || op.kind === 'enable' ? '正在检测，请稍候。' : '正在准备变更，请稍候。';
    await refresh();
  } catch { failure.value = '提交结果暂时未知，请刷新状态后重试。'; }
  finally { busy.value = false; }
}
function startImport() { closePanel(); panel.value = 'import'; notice.value = ''; scrollPanel(); }
function submit() {
  if (!form.label.trim() || !form.text.trim()) return;
  void send({ action:'preview', ...form }, { kind:'import', name:'', tags:[], phase:'preview' });
}
function startEdit(item: ProxyItem) {
  closePanel(); panel.value = 'edit'; editing.value = item; notice.value = '';
  Object.assign(edit, { label:item.label, address:item.address, port:item.port, protocol:item.protocol, username:'', password:'', uuid:'',
    network:item.network || 'tcp', security:item.security || 'auto', tls:item.tls || false, server_name:item.server_name || '',
    host:item.host || '', path:item.path || '', alpn:item.alpn || '', fingerprint:item.fingerprint || '' });
  scrollPanel();
}
function manage(item: ProxyItem, operation: 'enable' | 'disable' | 'restore' | 'edit') {
  if (!report.value?.apply_enabled) return;
  const changes = operation === 'edit' ? {
    label:edit.label, address:edit.address, port:edit.port, protocol:edit.protocol,
    ...(edit.protocol === 'vmess' ? { uuid:edit.uuid, network:edit.network, security:edit.security, tls:edit.tls,
      server_name:edit.tls ? edit.server_name : '', host:edit.host, path:edit.path,
      alpn:edit.tls ? edit.alpn : '', fingerprint:edit.tls ? edit.fingerprint : '' } : { username:edit.username, password:edit.password }),
  } : undefined;
  void send({ action:'manage', operation, tag:item.tag, ...(changes ? { changes } : {}) },
    { kind:operation, name:item.label, tags:[item.tag], phase:'preview' });
}
function remove(tags: string[]) {
  if (!report.value?.apply_enabled || !tags.length) return;
  closePanel();
  void send({ action:'manage', operation:'delete', tags }, { kind:'delete', name:'', tags:[...tags], phase:'preview' });
}
function toggleAll() {
  const visible = visibleItems.value.map(i => i.tag);
  selected.value = visibleSelected.value === visible.length ? selected.value.filter(tag => !visible.includes(tag)) : [...new Set([...selected.value, ...visible])];
}
function cancelPreview() { dismissedId.value = report.value?.id ?? ''; current.value = null; notice.value = '已取消预览，变更未应用。'; }
async function apply() {
  if (blocked.value || !report.value?.apply_enabled || !confirming.value || !report.value.id) return;
  busy.value = true; failure.value = ''; notice.value = '';
  try {
    const response = await fetch('/api/proxy-import', { method:'POST', credentials:'same-origin', cache:'no-store',
      headers: { 'Content-Type':'application/json', 'X-CSRF-Token':props.csrf },
      body:JSON.stringify({ action:'apply', preview_id:report.value.id }), signal:AbortSignal.timeout(15000) });
    if (response.status === 401) { emit('expired'); return; }
    if (!response.ok) {
      const body: unknown = await response.json().catch(() => null);
      failure.value = body && typeof body === 'object' && 'detail' in body && typeof body.detail === 'string' ? body.detail : '应用未完成。'; return;
    }
    const body: unknown = await response.json();
    if (!body || typeof body !== 'object' || !('id' in body) || typeof body.id !== 'string' || !/^[0-9a-f]{32}$/.test(body.id)) throw new Error('invalid response');
    pendingId.value = body.id; if (current.value) current.value.phase = 'apply'; notice.value = '正在应用变更，请稍候。'; await refresh();
  } catch { failure.value = '应用结果暂时未知，请刷新状态后重试。'; }
  finally { busy.value = false; }
}
function reason(value?: string): string {
  return ({ invalid:'输入或现有配置不符合要求。', probe:'代理连接或出口检测未通过。', conflict:'配置在检测期间发生变化，请重新操作。',
    expired:'检测结果已过期，请重新操作。', unavailable:'检测服务暂时不可用。', apply_disabled:'应用功能尚未启用。',
    interrupted:'检测过程已中断，请重新操作。' } as Record<string, string>)[value ?? ''] ?? '请检查输入和检测服务后重试。';
}
function leave() { form.text = ''; edit.username = ''; edit.password = ''; edit.uuid = ''; }
defineExpose({ refresh, leave });
onMounted(() => { void refresh(); timer = setInterval(() => { void refresh(); }, 3000); });
onUnmounted(() => { if (timer) clearInterval(timer); closePanel(); });
</script>

<template>
  <section aria-labelledby="import-heading" class="fixed-proxies">
    <div class="users-heading"><div><h2 id="import-heading">固定代理</h2><p>导入、编辑和管理 SOCKS5、HTTP、VMess 出口。</p></div>
      <div class="heading-actions"><button type="button" @click="refresh">刷新</button><button type="button" class="primary" :disabled="locked" @click="startImport">导入代理</button></div></div>
    <p v-if="report && !report.apply_enabled" class="preview-note">当前服务只能检测，无法应用变更。</p>
    <p v-if="loading" class="table-message">正在读取代理列表…</p>
    <p v-if="fetchFailure" class="message" role="alert">{{ fetchFailure }}</p><p v-if="failure" class="message" role="alert">{{ failure }}</p><p v-if="notice" class="notice" role="status">{{ notice }}</p>
    <p v-if="report?.status === 'unavailable'" class="message" role="alert">代理检测服务暂时不可用，请稍后刷新重试。</p>
    <p v-if="report?.status === 'failed' && !waiting" class="message" role="alert">{{ reason(report.reason) }}</p>
    <p v-if="report?.status === 'expired' && !waiting" class="message" role="alert">检测结果已过期，请重新操作。</p>
    <template v-if="!loading && report">
      <div v-if="confirming" ref="confirmationElement" class="proxy-confirmation" role="region" aria-label="确认代理变更">
        <div><h3>{{ previewTitle }}</h3><p v-if="current?.kind === 'delete'">删除后会移入回收站，可随时找回。应用时现有连接可能短暂中断。</p>
          <p v-else-if="current?.kind === 'import'">请核对出口信息。确认导入后，代理会出现在下方列表中。</p>
          <p v-else>变更尚未应用。应用时现有连接可能短暂中断。</p></div>
        <ul v-if="report.rows?.length" class="proxy-preview-list"><li v-for="(row, index) in report.rows" :key="row.tag || index">
          <strong>{{ row.label || row.tag || '代理' }}</strong><span>{{ [row.exit_ip, row.country].filter(Boolean).join(' · ') }}</span></li></ul>
        <div class="proxy-actions"><button v-if="report.apply_enabled" type="button" class="primary" :disabled="blocked" @click="apply">{{ current ? `确认${actionName[current.kind]}` : '确认应用' }}</button>
          <button type="button" :disabled="blocked" @click="cancelPreview">取消</button></div>
      </div>
      <div class="proxy-workspace" :class="{ 'with-editor': panel }">
        <div class="proxy-list-pane">
          <div ref="listElement" class="proxy-list-heading"><div><h3>已导入的代理</h3><p>共 {{ counts.all }} 个 · 已启用 {{ counts.enabled }} 个</p></div></div>
          <div class="proxy-filters"><label class="proxy-search"><span class="sr-only">搜索代理</span><input v-model="query" type="search" placeholder="搜索名称、地址或地区"></label>
            <div class="proxy-tabs" aria-label="代理状态筛选"><button v-for="tab in ([['all','全部'],['enabled','已启用'],['disabled','已停用'],['trash','回收站']] as const)" :key="tab[0]"
              type="button" :class="{ active: filter === tab[0] }" :aria-pressed="filter === tab[0]" @click="filter = tab[0]">{{ tab[1] }} <span>{{ counts[tab[0]] }}</span></button></div></div>
          <div v-if="filter !== 'trash' && report.apply_enabled && visibleItems.length" class="proxy-bulk">
            <label class="checkbox"><input type="checkbox" :checked="visibleSelected === visibleItems.length" :indeterminate="visibleSelected > 0 && visibleSelected < visibleItems.length" :disabled="locked" @change="toggleAll">全选当前结果</label>
            <span>已选 {{ selected.length }} 个</span><button type="button" class="danger" :disabled="locked || !selected.length" @click="remove(selected)">删除已选</button>
            <button v-if="selected.length" type="button" :disabled="locked" @click="selected = []">清除选择</button>
          </div>
          <p v-if="report.items == null" class="proxy-empty">无法读取已导入的代理，请刷新后重试。</p>
          <p v-else-if="!visibleItems.length" class="proxy-empty">{{ query ? '没有找到匹配的代理。' : filter === 'trash' ? '回收站为空。' : filter === 'all' ? '还没有导入代理，点击右上角“导入代理”开始。' : '此状态下没有代理。' }}</p>
          <ul v-else class="proxy-list"><li v-for="item in visibleItems" :key="item.tag" :class="{ recent: recent.includes(item.tag), selected: editing?.tag === item.tag }">
            <label v-if="filter !== 'trash' && report.apply_enabled" class="proxy-select"><input v-model="selected" type="checkbox" :value="item.tag" :disabled="locked" :aria-label="`选择 ${item.label}`"></label>
            <span v-else class="proxy-select" aria-hidden="true"></span>
            <div class="proxy-identity"><div><strong>{{ item.label }}</strong><span v-if="recent.includes(item.tag)" class="proxy-new">新导入</span></div>
              <small>{{ item.address }}:{{ item.port }} · {{ item.protocol.toUpperCase() }}</small><small>出口 {{ item.exit_ip || '—' }}<template v-if="item.country"> · {{ item.country }}</template></small></div>
            <span class="status-badge" :class="{ active:item.enabled && !item.deleted_at }">{{ item.deleted_at ? '回收站' : item.enabled ? '已启用' : '已停用' }}</span>
            <div v-if="report.apply_enabled" class="proxy-row-actions"><button v-if="item.deleted_at" type="button" :disabled="locked" @click="manage(item, 'restore')">找回</button>
              <template v-else><button type="button" :disabled="locked" @click="startEdit(item)">编辑</button><button type="button" :disabled="locked" @click="manage(item, item.enabled ? 'disable' : 'enable')">{{ item.enabled ? '停用' : '启用' }}</button>
                <button type="button" class="danger" :disabled="locked" @click="remove([item.tag])">删除</button></template></div>
          </li></ul>
          <p v-if="filter === 'trash' && counts.trash" class="proxy-hint">找回的代理默认处于停用状态，可在列表中重新启用。</p>
        </div>
        <aside v-if="panel" ref="panelElement" class="proxy-editor-pane" aria-label="代理操作">
          <template v-if="panel === 'import'"><div class="proxy-editor-heading"><div><h3>导入代理</h3><p>填写信息 → 检测 → 确认导入</p></div><button type="button" :disabled="blocked" @click="closePanel">关闭</button></div>
            <form class="import-form" @submit.prevent="submit"><label>协议<select v-model="form.protocol"><option value="socks">SOCKS5</option><option value="http">HTTP</option><option value="vmess">VMess</option></select></label>
              <label>名称前缀<input v-model="form.label" maxlength="30" placeholder="例如：住宅代理" required></label>
              <label>{{ form.protocol === 'vmess' ? 'VMess 分享链接（每行一个）' : '代理列表（每行：IP:端口:账号:密码）' }}
                <textarea v-model="form.text" rows="6" maxlength="12000" autocomplete="off" spellcheck="false" required></textarea></label>
              <p class="proxy-hint">检测通过后还需确认导入；导入成功后可在代理列表查看。</p><button class="primary" type="submit" :disabled="locked || !form.label.trim() || !form.text.trim()">检测代理</button></form></template>
          <template v-else-if="editing"><div class="proxy-editor-heading"><div><h3>编辑代理</h3><p>{{ editing.label }}</p></div><button type="button" :disabled="blocked" @click="closePanel">关闭</button></div>
            <form class="import-form" @submit.prevent="manage(editing, 'edit')"><div class="proxy-form-grid"><label>名称<input v-model="edit.label" maxlength="60" required></label>
              <label>协议<select v-model="edit.protocol"><template v-if="editing.protocol === 'vmess'"><option value="vmess">VMess</option></template>
                <template v-else><option value="socks">SOCKS5</option><option value="http">HTTP</option></template></select></label></div>
              <div class="proxy-form-grid"><label>代理地址<input v-model="edit.address" maxlength="253" required></label><label>端口<input v-model.number="edit.port" type="number" min="1" max="65535" required></label></div>
              <template v-if="edit.protocol === 'vmess'"><label>新 UUID<input v-model="edit.uuid" type="password" autocomplete="new-password" placeholder="留空保留原值"></label>
                <div class="proxy-form-grid"><label>传输<select v-model="edit.network"><option value="tcp">TCP</option><option value="ws">WebSocket</option><option value="grpc">gRPC</option></select></label>
                  <label>加密<select v-model="edit.security"><option>auto</option><option>aes-128-gcm</option><option>chacha20-poly1305</option><option>none</option><option>zero</option></select></label></div>
                <label class="checkbox"><input v-model="edit.tls" type="checkbox">启用 TLS</label><div class="proxy-form-grid"><label>TLS 服务名<input v-model="edit.server_name" maxlength="253"></label><label>Host<input v-model="edit.host" maxlength="253"></label></div>
                <label>路径或 gRPC 服务名<input v-model="edit.path" maxlength="1024"></label><div class="proxy-form-grid"><label>ALPN<input v-model="edit.alpn" maxlength="100"></label><label>TLS 指纹<input v-model="edit.fingerprint" maxlength="32"></label></div></template>
              <div v-else class="proxy-form-grid"><label>新账号<input v-model="edit.username" autocomplete="off" placeholder="留空保留原值"></label><label>新密码<input v-model="edit.password" type="password" autocomplete="new-password" placeholder="留空保留原值"></label></div>
              <p class="proxy-hint">修改需要先检测，通过后再确认保存。</p><button type="submit" class="primary" :disabled="locked || !report.apply_enabled">检测修改</button></form></template>
        </aside>
      </div>
    </template>
  </section>
</template>
