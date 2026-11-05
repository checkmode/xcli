<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';

const stage = ref<'checking' | 'ready' | 'error'>('checking');
const message = ref('正在检查连接地址…');
const serviceRouting = ref(false);
const integrated = ref(false);
const token = ref('');
const copied = ref('');
const fallback = ref('');
const subscription = computed(() => token.value ? `${window.location.origin}/s/${token.value}` : '');
const resource = computed(() => serviceRouting.value ? `${subscription.value}/shadowrocket.conf` : `${window.location.origin}/shadowrocket-dns.sgmodule`);
const importLink = computed(() => serviceRouting.value ? `shadowrocket://config/add/${resource.value}` : `shadowrocket://add/${subscription.value}`);
const dnsLink = computed(() => `shadowrocket://install?module=${encodeURIComponent(resource.value)}`);
let checkGeneration = 0;

async function check() {
  const generation = ++checkGeneration;
  token.value = window.location.hash.slice(1); stage.value = 'checking'; copied.value = ''; fallback.value = '';
  if (!/^[A-Za-z0-9_-]{43}$/.test(token.value)) { stage.value = 'error'; message.value = '连接地址不完整，请向管理员重新获取。'; return; }
  try {
    const options: RequestInit = { credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(15000) };
    const response = await fetch(subscription.value, options);
    if (generation !== checkGeneration) return;
    if (response.status === 403) { stage.value = 'error'; message.value = '此订阅已停用、到期或达到配额，请联系管理员。'; return; }
    if (response.status === 404) { stage.value = 'error'; message.value = '连接地址已失效，请向管理员重新获取。'; return; }
    if (!response.ok) throw new Error('subscription unavailable');
    await response.text();
    const next = await fetch(`${subscription.value}/shadowrocket.json`, options);
    if (!next.ok) throw new Error('setup unavailable');
    const body: unknown = await next.json();
    if (generation !== checkGeneration) return;
    if (typeof body !== 'object' || !body || !('service_routing' in body) || !('resource' in body) ||
        typeof body.service_routing !== 'boolean' || typeof body.resource !== 'string') throw new Error('invalid setup');
    const expected = body.service_routing ? `/s/${token.value}/shadowrocket.conf` : '/shadowrocket-dns.sgmodule';
    if (body.resource !== expected) throw new Error('invalid setup resource');
    serviceRouting.value = body.service_routing;
    integrated.value = 'dns_routing' in body && body.dns_routing === 'integrated';
    stage.value = 'ready'; message.value = serviceRouting.value ? '专属配置可用。' : '连接地址可用，请按顺序完成设置。';
  } catch {
    if (generation === checkGeneration) { stage.value = 'error'; message.value = '暂时无法检查连接地址，请确认网络可用后重试。'; }
  }
}
async function copy(value: string, label: string) {
  fallback.value = '';
  try { await navigator.clipboard.writeText(value); copied.value = `${label}已复制。`; }
  catch { fallback.value = value; copied.value = '请手动选择下方地址复制。'; }
}
onMounted(() => { window.addEventListener('hashchange', check); void check(); });
onBeforeUnmount(() => { checkGeneration++; window.removeEventListener('hashchange', check); token.value = ''; fallback.value = ''; });
</script>

<template>
  <div class="client-page">
    <header><strong>XCLI</strong><span>Shadowrocket</span></header>
    <main class="client-setup">
      <p class="eyebrow">连接设置</p><h1>配置小火箭连接</h1>
      <p class="intro">{{ serviceRouting ? '安装或更新专属远程配置。' : '按顺序导入节点与 DNS 模块。' }}</p>
      <p class="client-status" role="status" aria-live="polite">{{ message }}</p>
      <button v-if="stage === 'error'" type="button" @click="check">重新检查</button>
      <ol v-if="stage === 'ready'" class="client-steps">
        <li><h2>{{ serviceRouting ? '安装或更新专属配置' : '导入节点订阅' }}</h2>
          <p v-if="serviceRouting">先更新首页节点订阅，再更新并使用此配置；全局路由保持「配置」。节点订阅和远程配置需要分别更新。</p>
          <p v-else>在小火箭中确认添加订阅，完成后返回此页。</p>
          <div class="client-actions"><a class="primary-link" :href="importLink">{{ serviceRouting ? '安装或更新配置' : '导入节点' }}</a><button type="button" @click="copy(serviceRouting ? resource : subscription, serviceRouting ? '配置地址' : '订阅地址')">复制地址</button></div>
        </li>
        <li v-if="!serviceRouting"><h2>安装 DNS 模块</h2><p>在「配置 → 模块」启用「Xcli DNS 随所选节点」。</p>
          <div class="client-actions"><a class="primary-link" :href="dnsLink">安装 DNS 模块</a><button type="button" @click="copy(resource, '模块地址')">复制模块地址</button></div>
        </li>
        <li v-if="!serviceRouting"><h2>关闭兼容模式</h2><p>在小火箭「设置 → 代理」中手动关闭兼容模式，然后重连 VPN。</p></li>
        <li v-if="!serviceRouting"><h2>选择节点并连接</h2><p>将「全局路由」切换为「代理」，选择节点并打开连接。</p><a class="primary-link" href="shadowrocket://route/proxy">切换为全局代理</a></li>
      </ol>
      <p v-if="integrated && stage === 'ready'" class="client-note">请关闭旧的「Xcli DNS 随所选节点」模块，避免覆盖配置内的 DNS 分流。更新后断开并重连 VPN。</p>
      <p v-if="copied" class="client-note" role="status">{{ copied }}</p>
      <label v-if="fallback">手动复制地址<textarea :value="fallback" rows="3" readonly @focus="($event.target as HTMLTextAreaElement).select()"></textarea></label>
      <p class="footnote">连接地址仅供对应用户使用。安装及开关状态需要在小火箭中确认。</p>
    </main>
  </div>
</template>
