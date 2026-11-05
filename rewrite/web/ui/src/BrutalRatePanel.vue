<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';

const props = defineProps<{ csrf: string }>();
const emit = defineEmits<{ expired: [] }>();
const rate = ref<number | null>(null);
const input = ref<number>(40);
const enabled = ref(false);
const status = ref('unavailable');
const pendingId = ref('');
const busy = ref(false);
const message = ref('');
const failure = ref('');
let timer: ReturnType<typeof setInterval> | undefined;
let refreshing = false;
const blocked = computed(() => busy.value || !!pendingId.value || ['verifying', 'applying'].includes(status.value));

async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    const response = await fetch('/api/proxy-import', { credentials:'same-origin', cache:'no-store', signal:AbortSignal.timeout(5000) });
    if (response.status === 401) { emit('expired'); return; }
    if (!response.ok) throw new Error('unavailable');
    const data: unknown = await response.json();
    if (!data || typeof data !== 'object' || !('status' in data) || typeof data.status !== 'string' ||
        !('brutal_rate_mbps' in data) || (data.brutal_rate_mbps !== null &&
        (!Number.isSafeInteger(data.brutal_rate_mbps) || Number(data.brutal_rate_mbps) < 1 || Number(data.brutal_rate_mbps) > 1000))) throw new Error('invalid response');
    const oldRate = rate.value;
    rate.value = data.brutal_rate_mbps === null ? null : Number(data.brutal_rate_mbps);
    enabled.value = 'apply_enabled' in data && data.apply_enabled === true;
    status.value = data.status;
    if (oldRate === null && rate.value !== null) input.value = rate.value;
    if (pendingId.value && 'id' in data && data.id === pendingId.value && ['complete','failed','expired'].includes(data.status)) {
      pendingId.value = '';
      if (data.status === 'complete') {
        input.value = rate.value ?? 40;
        message.value = `速率已应用：${rate.value} Mbps。请更新客户端订阅。`;
        failure.value = '';
      } else {
        message.value = '';
        failure.value = '速率未能应用，请检查服务状态后重试。';
      }
    }
  } catch {
    if (!pendingId.value) failure.value = '暂时无法读取 Brutal 速率。';
  } finally { refreshing = false; }
}
async function save() {
  if (blocked.value || !enabled.value || !Number.isSafeInteger(input.value) || input.value < 1 || input.value > 1000 || input.value === rate.value) return;
  busy.value = true; failure.value = ''; message.value = '';
  try {
    const response = await fetch('/api/proxy-import', { method:'POST', credentials:'same-origin', cache:'no-store',
      headers:{ 'Content-Type':'application/json', 'X-CSRF-Token':props.csrf },
      body:JSON.stringify({action:'brutal_rate',mbps:input.value}), signal:AbortSignal.timeout(15000) });
    if (response.status === 401) { emit('expired'); return; }
    if (!response.ok) {
      const body: unknown = await response.json().catch(() => null);
      failure.value = body && typeof body === 'object' && 'detail' in body && typeof body.detail === 'string' ? body.detail : '速率请求未完成。';
      return;
    }
    const body: unknown = await response.json();
    if (!body || typeof body !== 'object' || !('id' in body) || typeof body.id !== 'string' || !/^[0-9a-f]{32}$/.test(body.id)) throw new Error('invalid response');
    pendingId.value = body.id;
    message.value = '正在应用，服务短暂重启后会自动更新状态。';
    void refresh();
  } catch { failure.value = '提交结果暂时未知，请稍后刷新状态。'; }
  finally { busy.value = false; }
}
onMounted(() => { void refresh(); timer = setInterval(() => { void refresh(); }, 3000); });
onUnmounted(() => { if (timer) clearInterval(timer); });
</script>

<template>
  <section v-if="rate !== null" class="account" aria-labelledby="brutal-heading">
    <div class="section-heading"><div><h2 id="brutal-heading">Hysteria 2 Brutal 速率</h2>
      <p>当前服务器发送速率：{{ rate }} Mbps；原 Hysteria 2 BBR 入口不变。</p></div></div>
    <form @submit.prevent="save">
      <label>发送速率（Mbps）<input v-model.number="input" type="number" min="1" max="1000" step="1" required :disabled="blocked || !enabled"></label>
      <div><button class="primary" type="submit" :disabled="blocked || !enabled || input === rate || !Number.isSafeInteger(input) || input < 1 || input > 1000">{{ blocked ? '正在应用…' : '保存速率' }}</button></div>
    </form>
    <p class="footnote">范围 1–1000 Mbps。保存时会短暂重启核心，现有连接可能中断；完成后请更新客户端订阅。</p>
    <p class="footnote">新订阅提供“Hysteria 2 Brutal”；旧名称“Hysteria 2 Brutal 40 Mbps”保留供现有选择使用，两者指向同一入口。</p>
    <p v-if="!enabled" class="footnote">当前服务未启用配置变更。</p>
    <p v-if="message" class="message" aria-live="polite">{{ message }}</p>
    <p v-if="failure" class="message" role="alert">{{ failure }}</p>
  </section>
</template>
