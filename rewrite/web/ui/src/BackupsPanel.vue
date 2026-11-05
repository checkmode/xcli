<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue';

type Backup = { id: string; valid: boolean; created: number; reason: string; users?: number; bytes?: number };
type Status = { automatic: boolean; interval: number; retention: number; last_backup: number; error: string; backups: Backup[] };
type Inspection = { id: string; same_server: boolean; users: number; created: number; preserves: string[] };
const props = defineProps<{ csrf: string }>();
const emit = defineEmits<{ expired: []; restored: [] }>();
const status = ref<Status | null>(null); const inspection = ref<Inspection | null>(null);
const loading = ref(true); const busy = ref(false); const failure = ref(''); const notice = ref('');
const password = ref(''); const code = ref('');
const validId = (value: string) => /^\d{10,12}-[0-9a-f]{32}\.xgb$/.test(value);
function parse(value: unknown): Status {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid status');
  const data = value as Partial<Status>;
  if (typeof data.automatic !== 'boolean' || !Number.isSafeInteger(data.interval) || !Number.isSafeInteger(data.retention) ||
      !Number.isSafeInteger(data.last_backup) || typeof data.error !== 'string' || !Array.isArray(data.backups) ||
      !data.backups.every(row => row && typeof row.id === 'string' && row.id.length <= 255 && typeof row.valid === 'boolean' &&
        Number.isSafeInteger(row.created) && typeof row.reason === 'string' && (!row.valid || validId(row.id)) &&
        (row.users === undefined || Number.isSafeInteger(row.users)) && (row.bytes === undefined || Number.isSafeInteger(row.bytes)))) throw new Error('invalid status');
  return data as Status;
}
async function request(path: string, options: RequestInit = {}): Promise<Response> {
  const response = await fetch(path, { ...options, credentials: 'same-origin', cache: 'no-store', signal: options.signal ?? AbortSignal.timeout(20000) });
  if (response.status === 401) emit('expired');
  return response;
}
async function refresh() {
  try {
    const response = await request('/api/backups');
    if (!response.ok) throw new Error('unavailable');
    status.value = parse(await response.json()); failure.value = '';
  } catch { failure.value = '暂时无法读取备份列表。'; }
  finally { loading.value = false; }
}
async function create() {
  if (busy.value) return;
  busy.value = true; failure.value = ''; notice.value = ''; inspection.value = null;
  try {
    const response = await request('/api/backups', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': props.csrf }, body: '{}' });
    if (!response.ok) throw new Error('create failed');
    notice.value = '加密备份已创建。';
    await refresh();
  } catch { failure.value = '备份结果暂时未知，请刷新列表后重试。'; }
  finally { busy.value = false; }
}
async function inspect(id: string) {
  if (busy.value || !validId(id)) return;
  busy.value = true; failure.value = ''; inspection.value = null; password.value = ''; code.value = '';
  try {
    const response = await request(`/api/backups/${encodeURIComponent(id)}/inspect`);
    if (!response.ok) throw new Error('inspect failed');
    const value: unknown = await response.json();
    if (!value || typeof value !== 'object' || !('id' in value) || value.id !== id ||
      !('same_server' in value) || typeof value.same_server !== 'boolean' || !('users' in value) || !Number.isSafeInteger(value.users) ||
      !('created' in value) || !Number.isSafeInteger(value.created) || !('preserves' in value) || !Array.isArray(value.preserves) ||
      !value.preserves.every(item => typeof item === 'string')) throw new Error('invalid inspection');
    inspection.value = value as Inspection;
  } catch { failure.value = '暂时无法检查该备份。'; }
  finally { busy.value = false; }
}
async function restore() {
  const backup = inspection.value;
  if (busy.value || !backup?.same_server || !password.value) return;
  busy.value = true; failure.value = '';
  try {
    const response = await request('/api/backups/restore', {
      method: 'POST', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': props.csrf },
      body: JSON.stringify({ id: backup.id, confirm: backup.id, current_password: password.value, code: code.value }),
      signal: AbortSignal.timeout(120000),
    });
    if (!response.ok) {
      const value: unknown = await response.json().catch(() => null);
      failure.value = typeof value === 'object' && value !== null && 'detail' in value && typeof value.detail === 'string'
        ? value.detail : '恢复未完成，请检查服务状态后重试。';
      return;
    }
    emit('restored');
  } catch { failure.value = '恢复结果暂时未知，请重新登录并检查备份和用户状态。'; }
  finally { password.value = ''; code.value = ''; busy.value = false; }
}
function when(value: number): string { return value > 0 ? new Date(value * 1000).toLocaleString() : '尚无'; }
function size(value?: number): string {
  if (value === undefined || value < 0) return '—';
  let amount = value; let unit = 0; const units = ['B', 'KB', 'MB', 'GB'];
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit++; }
  return `${amount.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}
function reason(value: string): string {
  return ({ manual: '手动', automatic: '自动', 'before-restore': '恢复前' } as Record<string, string>)[value] ?? value;
}
onMounted(() => { void refresh(); });
onUnmounted(() => { password.value = ''; code.value = ''; });
</script>

<template>
  <section aria-labelledby="backups-heading">
    <div class="users-heading"><div><h2 id="backups-heading">加密备份</h2><p>创建和检查面板备份。</p></div>
      <div class="heading-actions"><button type="button" :disabled="busy" @click="refresh">刷新</button>
        <button class="primary" type="button" :disabled="busy || !status" @click="create">创建备份</button></div></div>
    <p class="preview-note">备份包含面板数据库和服务器设置，解密需要原服务器密钥；证书、住宅状态和独立节点数据需另行备份。</p>
    <p v-if="loading" class="table-message">正在读取备份…</p>
    <template v-else-if="status">
      <div class="webshare-status"><strong>{{ status.automatic ? '自动备份已启用' : '自动备份已关闭' }}</strong>
        <span>保留最近 {{ status.retention }} 份 · 最近备份：{{ when(status.last_backup) }}</span></div>
      <p v-if="status.error" class="message" role="alert">{{ status.error }}</p>
      <p v-if="!status.backups.length" class="table-message">尚无备份。</p>
      <div v-else class="table-wrap"><table><thead><tr><th>时间</th><th>类型</th><th>用户</th><th>大小</th><th>操作</th></tr></thead>
        <tbody><tr v-for="row in status.backups" :key="row.id"><td>{{ when(row.created) }}</td><td>{{ row.valid ? reason(row.reason) : '校验失败' }}</td>
          <td>{{ row.users ?? '—' }}</td><td>{{ size(row.bytes) }}</td><td><div v-if="row.valid" class="user-actions">
            <button type="button" :disabled="busy" @click="inspect(row.id)">检查</button>
            <a :href="`/api/backups/${encodeURIComponent(row.id)}/download`" download>下载</a></div><span v-else>不可用</span></td></tr></tbody></table></div>
      <div v-if="inspection" class="backup-inspection"><h3>备份检查</h3><p>{{ when(inspection.created) }} · {{ inspection.users }} 位用户 · {{ inspection.same_server ? '与当前服务器配置一致' : '服务器配置不同' }}</p>
        <p>恢复时计划保留：{{ inspection.preserves.join('、') }}。</p>
        <template v-if="inspection.same_server">
          <p>恢复用户、凭据和规则；备份后新增的用户将停用并隐藏，已有流量保留。恢复前会自动创建一份备份，完成后需重新登录，节点连接可能短暂中断。</p>
          <form class="backup-restore" @submit.prevent="restore">
            <label>管理密码<input v-model="password" type="password" autocomplete="current-password" required></label>
            <label>二次验证码或恢复码（如已启用）<input v-model="code" autocomplete="one-time-code"></label>
            <button class="danger" type="submit" :disabled="busy || !password">恢复此备份</button>
          </form>
        </template>
        <p v-else>服务器配置不同，无法直接恢复此备份。</p></div>
    </template>
    <p v-if="failure" class="message" role="alert">{{ failure }}</p><p v-if="notice" class="notice" aria-live="polite">{{ notice }}</p>
  </section>
</template>
