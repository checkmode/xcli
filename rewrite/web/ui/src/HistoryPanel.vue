<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';

type Traffic = { ts: number; upload: number; download: number; minutes: number };
type Summary = { transport: string; healthy: number; failed: number; unknown: number;
  https_ms: number | null; udp_ms: number | null; success_percent: number | null };
type History = { start: number; end: number; bucket_seconds: number; traffic: Traffic[]; summary: Summary[] };
const emit = defineEmits<{ expired: [] }>();
const range = ref('24h'); const history = ref<History | null>(null);
const loading = ref(true); const failure = ref(''); let sequence = 0;
const integer = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const metric = (value: unknown): boolean => value === null || (typeof value === 'number' && Number.isFinite(value) && value >= 0);
function parse(value: unknown): History {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid history');
  const data = value as Partial<History>;
  if (!integer(data.start) || !integer(data.end) || !integer(data.bucket_seconds) || data.bucket_seconds === 0 ||
      !Array.isArray(data.traffic) || data.traffic.length > 1000 || !Array.isArray(data.summary) || data.summary.length > 1000 ||
      !data.traffic.every(row => row && integer(row.ts) && integer(row.upload) && integer(row.download) && integer(row.minutes)) ||
      !data.summary.every(row => row && typeof row.transport === 'string' && integer(row.healthy) && integer(row.failed) &&
        integer(row.unknown) && metric(row.https_ms) && metric(row.udp_ms) && metric(row.success_percent))) throw new Error('invalid history');
  return data as History;
}
async function refresh() {
  const request = ++sequence; loading.value = true; failure.value = '';
  try {
    const response = await fetch(`/api/history?range=${encodeURIComponent(range.value)}`,
      { credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(15000) });
    if (response.status === 401) { emit('expired'); return; }
    if (!response.ok) throw new Error('unavailable');
    const value = parse(await response.json());
    if (request === sequence) history.value = value;
  } catch { if (request === sequence) failure.value = '暂时无法读取历史数据。'; }
  finally { if (request === sequence) loading.value = false; }
}
function label(value: string): string {
  return ({ reality: 'REALITY', websocket: 'WebSocket / TLS', hysteria2: 'Hysteria 2', vmess: 'VMess / TLS' } as Record<string, string>)[value] ?? value;
}
function bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB']; let size = value / 1024; let index = 0;
  while (size >= 1024 && index < units.length - 1) { size /= 1024; index++; }
  return `${size.toFixed(1)} ${units[index]}`;
}
function latency(value: number | null): string { return value === null ? '—' : `${value.toFixed(1)} ms`; }
const bars = computed(() => {
  if (!history.value || !history.value.traffic.length) return [];
  const data = history.value; const max = Math.max(1, ...data.traffic.flatMap(row => [row.upload, row.download]));
  const span = Math.max(1, data.end - data.start);
  return data.traffic.map(row => ({ ts: row.ts, x: 4 + (row.ts - data.start) / span * 590,
    upload: row.upload / max * 115, download: row.download / max * 115 }));
});
onMounted(() => { void refresh(); });
</script>

<template>
  <section aria-labelledby="history-heading">
    <div class="users-heading"><div><h2 id="history-heading">历史趋势</h2><p>按时间段查看流量和入口探测结果；没有采样的时段留空。</p></div>
      <label>时间范围 <select v-model="range" @change="refresh"><option value="1h">最近 1 小时</option><option value="24h">最近 24 小时</option><option value="7d">最近 7 天</option><option value="30d">最近 30 天</option></select></label></div>
    <p v-if="loading" class="table-message">正在读取历史数据…</p>
    <p v-else-if="failure" class="message" role="alert">{{ failure }}</p>
    <template v-else-if="history">
      <h3>流量</h3>
      <div v-if="bars.length" class="history-chart">
        <p class="history-legend"><span class="upload-key">● 上传</span><span class="download-key">● 下载</span><span>每个柱线表示一个时间段的流量</span></p>
        <svg viewBox="0 0 600 130" role="img" aria-label="按时间段显示上传和下载流量">
          <line x1="0" y1="120" x2="600" y2="120" stroke="currentColor" opacity=".2" />
          <g v-for="bar in bars" :key="bar.ts"><line :x1="bar.x" y1="120" :x2="bar.x" :y2="120 - bar.upload" class="upload" />
            <line :x1="bar.x + 1.3" y1="120" :x2="bar.x + 1.3" :y2="120 - bar.download" class="download" /></g>
        </svg>
        <p class="history-axis"><span>{{ new Date(history.start * 1000).toLocaleString() }}</span><span>{{ new Date(history.end * 1000).toLocaleString() }}</span></p>
        <details><summary>查看流量明细</summary><div class="table-wrap"><table><thead><tr><th>时间</th><th>上传</th><th>下载</th><th>采样分钟数</th></tr></thead>
          <tbody><tr v-for="row in [...history.traffic].reverse()" :key="row.ts"><td>{{ new Date(row.ts * 1000).toLocaleString() }}</td><td>{{ bytes(row.upload) }}</td><td>{{ bytes(row.download) }}</td><td>{{ row.minutes }}</td></tr></tbody></table></div></details>
      </div>
      <p v-else class="table-message">所选时间范围内没有流量采样。</p>
      <h3>入口探测汇总</h3>
      <div v-if="history.summary.length" class="table-wrap"><table><thead><tr><th>入口</th><th>成功率</th><th>成功 / 失败</th><th>未知</th><th>HTTPS 均值</th><th>UDP DNS 均值</th></tr></thead>
        <tbody><tr v-for="row in history.summary" :key="row.transport"><td>{{ label(row.transport) }}</td><td>{{ row.success_percent === null ? '—' : row.success_percent.toFixed(1) + '%' }}</td>
          <td>{{ row.healthy }} / {{ row.failed }}</td><td>{{ row.unknown }}</td><td>{{ latency(row.https_ms) }}</td><td>{{ latency(row.udp_ms) }}</td></tr></tbody></table></div>
      <p v-else class="table-message">所选时间范围内没有探测采样。</p>
      <p class="footnote">成功率只计算成功和失败的探测；未知结果不计入分母。</p>
    </template>
  </section>
</template>

<style scoped>
.history-chart svg { width: 100%; height: auto; max-height: 200px; display: block; color: #8992a1; }
.history-chart .upload { stroke: #315fb1; stroke-width: 1.3; }
.history-chart .download { stroke: #218476; stroke-width: 1.3; }
.history-legend, .history-axis { display: flex; gap: 1rem; flex-wrap: wrap; font-size: .8rem; color: #687385; }
.history-axis { justify-content: space-between; }
.upload-key { color: #315fb1; } .download-key { color: #218476; }
details { margin: .8rem 0; } summary { cursor: pointer; }
</style>
