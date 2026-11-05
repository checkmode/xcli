<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue';

const emit = defineEmits<{ expired: [] }>();
const status = ref<'checking' | 'ready' | 'pending' | 'unavailable'>('checking');
let timer: ReturnType<typeof setInterval> | undefined;
async function refresh() {
  try {
    const response = await fetch('/api/core-sync', { credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(10000) });
    if (response.status === 401) { emit('expired'); return; }
    const body: unknown = await response.json();
    if (!response.ok || !body || typeof body !== 'object' || !('scope' in body) || body.scope !== 'local' ||
        !('state' in body) || (body.state !== 'ready' && body.state !== 'pending' && body.state !== 'unavailable')) throw new Error('invalid status');
    status.value = body.state;
  } catch { status.value = 'unavailable'; }
}
onMounted(() => { void refresh(); timer = setInterval(() => { void refresh(); }, 10000); });
onUnmounted(() => { if (timer) clearInterval(timer); });
</script>

<template>
  <section class="health" aria-labelledby="core-status-heading">
    <div><h2 id="core-status-heading">本地核心同步</h2>
      <p>{{ status === 'ready' ? '最近一次核对已应用用户更改。独立节点状态需另行检查。' : status === 'pending' ? '正在应用用户更改，旧连接可能仍然有效。' : status === 'checking' ? '正在检查本地核心。' : '无法确认本地核心状态，旧连接可能仍然有效。' }}</p></div>
    <div class="result"><span class="status-badge" :class="status" aria-live="polite">{{ status === 'ready' ? '已同步' : status === 'pending' ? '同步中' : status === 'checking' ? '正在检查' : '状态未知' }}</span><button type="button" @click="refresh">重新检查</button></div>
  </section>
</template>
