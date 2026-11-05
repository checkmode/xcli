<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue';

type Memory = { total: number; used: number };
type Host = { cpu_percent: number | null; uptime_seconds: number | null; load: number[] | null; memory: Memory | null; swap: Memory | null; disk: Memory | null };
type Snapshot = { sampled: number; stale: boolean; host: Host | null };
const emit = defineEmits<{ expired: [] }>();
const snapshot = ref<Snapshot | null>(null);
const loading = ref(true);
let timer: ReturnType<typeof setInterval> | undefined;
function numberOrNull(value: unknown): value is number | null {
  return value === null || typeof value === 'number' && Number.isFinite(value) && value >= 0;
}
function memory(value: unknown): value is Memory | null {
  if (value === null) return true;
  if (!value || typeof value !== 'object' || !('total' in value) || !('used' in value)) return false;
  return typeof value.total === 'number' && Number.isSafeInteger(value.total) && value.total >= 0 &&
    typeof value.used === 'number' && Number.isSafeInteger(value.used) && value.used >= 0 && value.used <= value.total;
}
function parse(value: unknown): Snapshot {
  if (!value || typeof value !== 'object' || !('scope' in value) || value.scope !== 'server' ||
      !('sampled' in value) || !Number.isSafeInteger(value.sampled) || (value.sampled as number) < 0 ||
      !('stale' in value) || typeof value.stale !== 'boolean' || !('host' in value)) throw new Error('invalid host report');
  if (value.host !== null) {
    if (!value.host || typeof value.host !== 'object' || !('cpu_percent' in value.host) || !numberOrNull(value.host.cpu_percent) ||
        typeof value.host.cpu_percent === 'number' && value.host.cpu_percent > 100 ||
        !('uptime_seconds' in value.host) || !numberOrNull(value.host.uptime_seconds) ||
        !('memory' in value.host) || !memory(value.host.memory) || !('swap' in value.host) || !memory(value.host.swap) ||
        !('disk' in value.host) || !memory(value.host.disk) || !('load' in value.host) || value.host.load !== null && (!Array.isArray(value.host.load) || value.host.load.length !== 3 ||
          !value.host.load.every(v => typeof v === 'number' && Number.isFinite(v) && v >= 0))) throw new Error('invalid host metrics');
  }
  return value as Snapshot;
}
async function refresh() {
  try {
    const response = await fetch('/api/host', { credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(10000) });
    if (response.status === 401) { emit('expired'); return; }
    if (!response.ok) throw new Error('unavailable');
    snapshot.value = parse(await response.json());
  } catch { snapshot.value = null; }
  finally { loading.value = false; }
}
function size(value: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB']; let index = 0; let current = value;
  while (current >= 1024 && index < units.length - 1) { current /= 1024; index++; }
  return `${current.toFixed(index ? 1 : 0)} ${units[index]}`;
}
function usage(value: Memory | null | undefined): string { return value ? `${size(value.used)} / ${size(value.total)}` : '未知'; }
function percentage(value: Memory | null | undefined): number | null {
  return value && value.total > 0 ? Math.min(100, value.used / value.total * 100) : null;
}
function uptime(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '未知';
  const hours = Math.floor(seconds / 3600); const days = Math.floor(hours / 24);
  return days ? `${days} 天 ${hours % 24} 小时` : `${hours} 小时`;
}
onMounted(() => { void refresh(); timer = setInterval(() => { void refresh(); }, 10000); });
onUnmounted(() => { if (timer) clearInterval(timer); });
</script>

<template>
  <section class="host-panel" aria-labelledby="host-heading">
    <div class="users-heading"><div><h2 id="host-heading">主机状态</h2><p>数据来自服务器内核，不能代表客户端的网络质量。</p></div><button type="button" @click="refresh">刷新</button></div>
    <p v-if="loading" class="table-message">正在读取主机状态…</p>
    <p v-else-if="!snapshot || snapshot.stale || !snapshot.host" class="table-message">主机采样暂不可用或已过期。</p>
    <template v-else><dl class="host-grid">
      <div><dt>CPU</dt><dd>{{ snapshot.host.cpu_percent === null ? '等待下一次采样' : `${snapshot.host.cpu_percent.toFixed(1)}%` }}</dd><span v-if="snapshot.host.cpu_percent !== null" class="metric-track" aria-hidden="true"><span :style="{ width: `${snapshot.host.cpu_percent}%` }"></span></span></div>
      <div><dt>内存</dt><dd>{{ usage(snapshot.host.memory) }}</dd><span v-if="percentage(snapshot.host.memory) !== null" class="metric-track" aria-hidden="true"><span :style="{ width: `${percentage(snapshot.host.memory)}%` }"></span></span></div>
      <div><dt>磁盘</dt><dd>{{ usage(snapshot.host.disk) }}</dd><span v-if="percentage(snapshot.host.disk) !== null" class="metric-track" aria-hidden="true"><span :style="{ width: `${percentage(snapshot.host.disk)}%` }"></span></span></div>
      <div><dt>运行时间</dt><dd>{{ uptime(snapshot.host.uptime_seconds) }}</dd></div>
      <div><dt>系统负载（1 / 5 / 15 分钟）</dt><dd>{{ snapshot.host.load ? snapshot.host.load.map(v => v.toFixed(2)).join(' / ') : '未知' }}</dd></div>
    </dl><p class="host-sampled">最近采样：{{ new Date(snapshot.sampled * 1000).toLocaleString() }} · {{ snapshot.host.disk ? '磁盘为面板状态目录所在文件系统' : '磁盘状态未知' }}</p></template>
  </section>
</template>
