<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue';

type Check = { transport: string; status: 'healthy' | 'failed' | 'unknown'; https_ms: number | null;
  udp_ms: number | null; doh_ms: number | null; udp_supported: boolean; last_success: number; error: string };
type Monitor = { scope: 'server' | 'external'; status: 'healthy' | 'failed' | 'unknown' | 'stale';
  updated: number; message?: string; checks: Check[] };
const emit = defineEmits<{ expired: [] }>();
const monitor = ref<Monitor | null>(null);
const loading = ref(true); const failure = ref('');
let timer: ReturnType<typeof setInterval> | undefined;

function parse(value: unknown): Monitor {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid report');
  const data = value as Partial<Monitor>;
  if (!['healthy', 'failed', 'unknown', 'stale'].includes(data.status ?? '') ||
      !['server', 'external'].includes(data.scope ?? '') || !Number.isSafeInteger(data.updated) ||
      (data.updated ?? -1) < 0 || !Array.isArray(data.checks) || data.checks.length > 44) throw new Error('invalid report');
  if (!data.checks.every(row => row && typeof row.transport === 'string' &&
      ['healthy', 'failed', 'unknown'].includes(row.status) && typeof row.udp_supported === 'boolean' &&
      Number.isSafeInteger(row.last_success) && typeof row.error === 'string' &&
      [row.https_ms, row.udp_ms, row.doh_ms].every(value => value === null || (Number.isSafeInteger(value) && value >= 0)))) {
    throw new Error('invalid checks');
  }
  return data as Monitor;
}
async function refresh() {
  try {
    const response = await fetch('/api/monitor', { credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(10000) });
    if (response.status === 401) { emit('expired'); return; }
    if (!response.ok) throw new Error('unavailable');
    monitor.value = parse(await response.json()); failure.value = '';
  } catch { failure.value = '暂时无法读取自检状态。'; }
  finally { loading.value = false; }
}
function label(value: string): string {
  return ({ reality: 'REALITY', websocket: 'WebSocket / TLS', hysteria2: 'Hysteria 2', vmess: 'VMess / TLS' } as Record<string, string>)[value] ?? value;
}
function state(value: string): string {
  return ({ healthy: '正常', failed: '失败', unknown: '等待结果', stale: '结果已过期' } as Record<string, string>)[value] ?? '未知';
}
function time(value: number): string { return value ? new Date(value * 1000).toLocaleString() : '尚无'; }
function latency(value: number | null): string { return value === null ? '—' : `${value} ms`; }
onMounted(() => { void refresh(); timer = setInterval(() => { void refresh(); }, 10000); });
onUnmounted(() => { if (timer) clearInterval(timer); });
</script>

<template>
  <section aria-labelledby="monitor-heading">
    <div class="users-heading"><div><h2 id="monitor-heading">入口自检</h2><p>{{ monitor?.scope === 'external' ? '检查外部网络连接和 DNS；结果仅反映探测地点的网络状况。' : '检查服务器侧连接和 DNS；结果不代表所有客户端网络都可用。' }}</p></div>
      <button type="button" @click="refresh">刷新</button></div>
    <p v-if="loading" class="table-message">正在读取自检结果…</p>
    <template v-else-if="monitor && !failure">
      <div class="webshare-status"><strong>{{ state(monitor.status) }}</strong><span>{{ monitor.message || `最近更新：${time(monitor.updated)}` }}</span></div>
      <div v-if="monitor.checks.length" class="table-wrap"><table><thead><tr><th>入口</th><th>状态</th><th>HTTPS</th><th>DNS</th><th>最近成功</th><th>说明</th></tr></thead>
        <tbody><tr v-for="check in monitor.checks" :key="check.transport"><td>{{ label(check.transport) }}</td>
          <td>{{ monitor.status === 'stale' ? '结果已过期' : state(check.status) }}</td><td>{{ latency(check.https_ms) }}</td>
          <td>{{ check.udp_supported ? 'UDP ' + latency(check.udp_ms) : 'DoH ' + latency(check.doh_ms) }}</td>
          <td>{{ time(check.last_success) }}</td><td>{{ check.error || '—' }}</td></tr></tbody></table></div>
    </template>
    <p v-if="failure" class="message" role="alert">{{ failure }}</p>
  </section>
</template>
