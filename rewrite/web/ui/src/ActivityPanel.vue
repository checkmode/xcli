<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue';

type ActivityRow = { id: string; name: string; transport: string; status: 'recent' | 'idle' | 'never' | 'unknown';
  last: number; upload: number; download: number };
const emit = defineEmits<{ expired: [] }>();
const rows = ref<ActivityRow[]>([]);
const loading = ref(false);
const message = ref('');
let timer: ReturnType<typeof setInterval> | null = null;
let disposed = false;
const names: Record<string, string> = { reality: 'REALITY', websocket: 'WebSocket / TLS', hysteria2: 'Hysteria 2', vmess: 'VMess' };
const labels: Record<ActivityRow['status'], string> = { recent: '近期活跃', idle: '暂无近期流量', never: '尚未观察到流量', unknown: '采样中断' };
function rate(value: number): string {
  if (value < 1000) return `${value.toFixed(1)} B/s`;
  const units = ['KB/s','MB/s','GB/s','TB/s']; let result = value / 1000; let unit = 0;
  while (result >= 1000 && unit < units.length - 1) { result /= 1000; unit++; }
  return `${result.toFixed(1)} ${units[unit]}`;
}
async function refresh() {
  if (loading.value) return;
  loading.value = true; message.value = '';
  try {
    const options: RequestInit = { cache: 'no-store', credentials: 'same-origin', signal: AbortSignal.timeout(15000) };
    const [response, usersResponse] = await Promise.all([fetch('/api/activity', options), fetch('/api/users', options)]);
    if (response.status === 401 || usersResponse.status === 401) { emit('expired'); return; }
    if (!response.ok || !usersResponse.ok) throw new Error('unavailable');
    const data: unknown = await response.json(); const users: unknown = await usersResponse.json();
    if (!data || typeof data !== 'object' || !('scope' in data) || data.scope !== 'local' || !('activity' in data) ||
        !data.activity || typeof data.activity !== 'object' || Array.isArray(data.activity) ||
        !users || typeof users !== 'object' || !('users' in users) || !Array.isArray(users.users)) throw new Error('invalid');
    const userNames = new Map<string, string>();
    for (const user of users.users) if (user && typeof user === 'object' && typeof user.id === 'string' && typeof user.name === 'string') userNames.set(user.id, user.name);
    const output: ActivityRow[] = [];
    for (const [id, transports] of Object.entries(data.activity)) {
      if (!userNames.has(id) || !transports || typeof transports !== 'object' || Array.isArray(transports)) continue;
      for (const [transport, raw] of Object.entries(transports)) {
        if (!raw || typeof raw !== 'object') throw new Error('invalid');
        const item = raw as Record<string, unknown>;
        if (typeof item.status !== 'string' || !Object.hasOwn(labels, item.status) ||
            typeof item.last_seen !== 'number' || !Number.isSafeInteger(item.last_seen) || item.last_seen < 0 ||
            typeof item.upload_rate !== 'number' || !Number.isFinite(item.upload_rate) || item.upload_rate < 0 ||
            typeof item.download_rate !== 'number' || !Number.isFinite(item.download_rate) || item.download_rate < 0) throw new Error('invalid');
        output.push({ id, name: userNames.get(id)!, transport, status: item.status as ActivityRow['status'],
          last: item.last_seen, upload: item.upload_rate, download: item.download_rate });
      }
    }
    output.sort((a, b) => a.name.localeCompare(b.name, 'zh-CN') || a.transport.localeCompare(b.transport));
    if (!disposed) rows.value = output;
  } catch { if (!disposed) message.value = '无法读取活动采样，请检查核心和管理服务。'; }
  finally { loading.value = false; }
}
onMounted(() => { void refresh(); timer = setInterval(() => { void refresh(); }, 15000); });
onUnmounted(() => { disposed = true; if (timer) clearInterval(timer); });
</script>

<template>
  <section aria-labelledby="activity-heading">
    <div class="section-heading"><div><h2 id="activity-heading">用户入口活动</h2><p>仅显示本机按用户和入口汇总的流量采样；无法区分具体设备，也不包含独立节点。</p></div><button type="button" :disabled="loading" @click="refresh">刷新</button></div>
    <p v-if="message" class="message" role="alert">{{ message }}</p>
    <p v-else-if="loading && !rows.length" class="table-message">正在读取活动…</p>
    <p v-else-if="!rows.length" class="table-message">尚无本机活动采样。</p>
    <div v-else class="table-wrap"><table>
      <thead><tr><th>用户</th><th>入口</th><th>活动状态</th><th>最近流量</th><th>当前速率</th></tr></thead>
      <tbody><tr v-for="row in rows" :key="row.id + ':' + row.transport">
        <td>{{ row.name }}</td><td>{{ names[row.transport] || row.transport }}</td><td>{{ labels[row.status] }}</td>
        <td>{{ row.last ? new Date(row.last * 1000).toLocaleString() : '尚无' }}</td>
        <td v-if="row.status === 'unknown'">未知</td><td v-else>↑ {{ rate(row.upload) }}<br>↓ {{ rate(row.download) }}</td>
      </tr></tbody>
    </table></div>
  </section>
</template>
