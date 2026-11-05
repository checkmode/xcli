<script setup lang="ts">
import { onMounted, onUnmounted, reactive, ref } from 'vue';

type Plan = { id: number; label?: string; eligible?: boolean; bandwidth_limit?: number };
type Region = { country: string; label: string; group: string };
type Pool = { country: string; status?: string; exit_ip?: string; exit_country?: string; https_ms?: number;
  doh_ms?: number; ready_standby?: number; failovers?: number; last_success?: number };
type Event = { country: string; ts: number; reason: string };
type Status = { installed: boolean; key_saved: boolean; enabled: boolean; plan_id: number; status: string;
  message: string; requested_revision: string; revision?: string; sync_error?: string; usage_error?: string;
  last_sync?: number; active_plan_id?: number; bandwidth_total?: number; requests_total?: number;
  requests_successful?: number; usage_updated?: number; plans: Plan[]; regions: Region[]; pools: Pool[]; events: Event[] };
const props = defineProps<{ csrf: string }>();
const emit = defineEmits<{ expired: [] }>();
const status = ref<Status | null>(null);
const loading = ref(true); const busy = ref(false); const dirty = ref(false);
const message = ref(''); const loadError = ref(''); const notice = ref('');
const form = reactive({ key: '', plan: 0, enabled: false });
let timer: ReturnType<typeof setInterval> | undefined;

function parseStatus(value: unknown): Status {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid status');
  const body = value as Partial<Status>;
  if (typeof body.installed !== 'boolean' || typeof body.key_saved !== 'boolean' || typeof body.enabled !== 'boolean' ||
      !Number.isSafeInteger(body.plan_id) || typeof body.status !== 'string' || typeof body.message !== 'string' ||
      typeof body.requested_revision !== 'string' || !Array.isArray(body.plans) || !Array.isArray(body.regions) ||
      !Array.isArray(body.pools) || !Array.isArray(body.events)) throw new Error('invalid status');
  if (!body.plans.every(plan => plan && Number.isSafeInteger(plan.id)) ||
      !body.regions.every(region => region && typeof region.country === 'string' && typeof region.label === 'string' && typeof region.group === 'string') ||
      !body.pools.every(pool => pool && typeof pool.country === 'string') ||
      !body.events.every(event => event && typeof event.country === 'string' && typeof event.reason === 'string' && typeof event.ts === 'number')) throw new Error('invalid data');
  return body as Status;
}
async function request(path: string, options: RequestInit = {}): Promise<Response> {
  const response = await fetch(path, { ...options, credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(15000) });
  if (response.status === 401) emit('expired');
  return response;
}
async function refresh(reset = false) {
  if (busy.value) return;
  try {
    const response = await request('/api/webshare');
    if (!response.ok) throw new Error('request failed');
    const value = parseStatus(await response.json());
    status.value = value;
    if (reset || !dirty.value) { form.plan = value.plan_id; form.enabled = value.enabled; dirty.value = false; }
    loadError.value = '';
  } catch { loadError.value = '无法加载住宅池状态，请稍后重试。'; }
  finally { loading.value = false; }
}
async function change(path: string, method: 'PUT' | 'POST', body: object, reset = false) {
  if (busy.value) return;
  busy.value = true; message.value = ''; notice.value = '';
  let failure = ''; let saved = false;
  try {
    const response = await request(path, { method, headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': props.csrf }, body: JSON.stringify(body) });
    if (!response.ok) {
      const value: unknown = await response.json().catch(() => null);
      failure = typeof value === 'object' && value !== null && 'detail' in value && typeof value.detail === 'string'
        ? value.detail : '操作未完成，请稍后重试。';
      return;
    }
    saved = true;
    notice.value = '已提交，后台正在应用。';
    if (reset) dirty.value = false;
  } catch { failure = '操作结果暂不可用，请刷新状态后再试。'; }
  finally { form.key = ''; busy.value = false; await refresh(saved && reset); if (failure) message.value = failure; }
}
function saveKey() { if (form.key) void change('/api/webshare', 'PUT', { api_key: form.key.trim() }); }
function savePlan() { void change('/api/webshare', 'PUT', { plan_id: Number(form.plan), enabled: form.enabled }, true); }
function clearKey() {
  if (window.confirm('移除 API Key 并关闭动态住宅连接？')) void change('/api/webshare', 'PUT', { clear_key: true }, true);
}
function action(name: 'sync' | 'rotate', country?: string) {
  void change('/api/webshare/action', 'POST', country ? { action: name, country } : { action: name });
}
function time(value?: number): string { return value && Number.isFinite(value) ? new Date(value * 1000).toLocaleString() : '尚无'; }
function bytes(value?: number): string {
  if (value === undefined || !Number.isFinite(value) || value < 0) return '等待供应商统计';
  let amount = value; let unit = 0; const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit++; }
  return `${amount.toFixed(unit ? 2 : 0)} ${units[unit]}`;
}
function pool(country: string): Pool | undefined { return status.value?.pools.find(value => value.country === country); }
function stateLabel(value: string): string {
  return ({ healthy: '运行正常', degraded: '部分地区不可用', disabled: '未启用', unconfigured: '待配置', unknown: '等待服务', stale: '状态已过期' } as Record<string, string>)[value] ?? '等待服务';
}
onMounted(() => { void refresh(); timer = setInterval(() => { void refresh(); }, 5000); });
onUnmounted(() => { if (timer) clearInterval(timer); form.key = ''; });
</script>

<template>
  <section aria-labelledby="webshare-heading">
    <div class="users-heading"><div><h2 id="webshare-heading">动态住宅池</h2><p>配置 Webshare 套餐并查看各地区出口。</p></div>
      <button type="button" :disabled="busy" @click="refresh()">刷新</button></div>
    <p class="preview-note">保存 API Key 并选择套餐后即可启用；未启用时不会向订阅添加动态住宅节点。</p>
    <p v-if="loading" class="table-message">正在加载住宅池…</p>
    <template v-else-if="status">
      <div class="webshare-status"><strong>{{ stateLabel(status.status) }}</strong><span>{{ !status.installed ? '尚未配置动态住宅入口。' : status.message }}</span>
        <span v-if="status.requested_revision && status.requested_revision !== status.revision">正在应用配置…</span></div>
      <p v-if="status.sync_error || status.usage_error" class="message" role="alert">{{ status.sync_error || status.usage_error }}</p>
      <div class="webshare-config">
        <form class="webshare-form" @submit.prevent="saveKey">
          <label>Webshare API Key<input v-model="form.key" type="password" autocomplete="off" maxlength="256" placeholder="输入密钥以保存或替换"></label>
          <small>{{ status.key_saved ? '已保存，原密钥不会回显。' : '尚未保存 API Key。' }}</small>
          <div class="heading-actions"><button class="primary" type="submit" :disabled="busy || !form.key.trim()">保存密钥</button>
            <button type="button" :disabled="busy || !status.key_saved" @click="clearKey">移除密钥</button>
            <button type="button" :disabled="busy || !status.key_saved" @click="action('sync')">同步套餐</button></div>
        </form>
        <form class="webshare-form" @submit.prevent="savePlan">
          <label>动态住宅套餐<select v-model.number="form.plan" @change="dirty = true">
            <option :value="0">请选择套餐</option><option v-for="plan in status.plans" :key="plan.id" :value="plan.id" :disabled="!plan.eligible">{{ plan.label || `套餐 #${plan.id}` }}{{ plan.bandwidth_limit ? ` · ${plan.bandwidth_limit} GB` : '' }}</option>
          </select></label>
          <label class="checkbox"><input v-model="form.enabled" type="checkbox" @change="dirty = true">启用动态住宅池</label>
          <div><button class="primary" type="submit" :disabled="busy || !status.installed || !status.key_saved">保存套餐</button></div>
        </form>
      </div>
      <dl class="webshare-summary"><div><dt>最后同步</dt><dd>{{ time(status.last_sync) }}</dd></div><div><dt>当前套餐</dt><dd>{{ status.active_plan_id ? `#${status.active_plan_id}` : '未选择' }}</dd></div>
        <div><dt>最近 24 小时流量</dt><dd>{{ bytes(status.bandwidth_total) }}</dd></div><div><dt>请求成功 / 总数</dt><dd>{{ status.requests_total === undefined ? '等待供应商统计' : `${status.requests_successful ?? 0} / ${status.requests_total}` }}</dd></div>
        <div><dt>用量更新时间</dt><dd>{{ time(status.usage_updated) }}</dd></div></dl>
      <div v-if="status.regions.length" class="table-wrap"><table><thead><tr><th>地区</th><th>出口</th><th>HTTPS / DoH</th><th>备用</th><th>最近成功</th><th>操作</th></tr></thead>
        <tbody><tr v-for="region in status.regions" :key="region.country"><td>{{ region.label }} · {{ region.country }}</td>
          <td>{{ pool(region.country)?.exit_ip || '尚未分配' }}</td><td>{{ pool(region.country)?.https_ms ?? '—' }} / {{ pool(region.country)?.doh_ms ?? '—' }} ms</td>
          <td>{{ pool(region.country)?.ready_standby ?? 0 }}</td><td>{{ time(pool(region.country)?.last_success) }}</td>
          <td class="user-actions"><button type="button" :disabled="busy || !status.enabled || status.status === 'stale'" @click="action('rotate', region.country)">更换出口</button></td></tr></tbody></table></div>
      <details v-if="status.events.length" class="webshare-events"><summary>最近切换记录</summary><p v-for="(event, index) in status.events" :key="index">{{ time(event.ts) }} · {{ event.country }} · {{ event.reason }}</p></details>
    </template>
    <p v-if="loadError" class="message" role="alert">{{ loadError }}</p><p v-if="message" class="message" role="alert">{{ message }}</p><p v-if="notice" class="notice" aria-live="polite">{{ notice }}</p>
  </section>
</template>
