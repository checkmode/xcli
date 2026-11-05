<script setup lang="ts">
import { onMounted, onUnmounted, reactive, ref } from 'vue';

type Alarm = { service: string; since: number; bad: number; good: number };
type Delivery = { id: string; service: string; kind: string; status: string; created: number; attempts: number; last_error: string };
type Status = { enabled: boolean; configured: boolean; destination: string; has_bearer: boolean; has_signing_secret: boolean;
  failures: number; recoveries: number; delivery_active: boolean; alarms: Alarm[]; deliveries: Delivery[] };
const emit = defineEmits<{ expired: [] }>();
const props = defineProps<{ csrf: string }>();
const status = ref<Status | null>(null); const loading = ref(true); const failure = ref('');
const editing=ref(false); const saving=ref(false); const message=ref('');
const testing=ref(false); const testMessage=ref('');
const form=reactive({ enabled:false,url:'',bearer:'',signing_secret:'',failures:3,recoveries:2,
  clear_auth:false,clear_url:false,current_password:'',code:'' });
function clearSecrets() { form.url=''; form.bearer=''; form.signing_secret=''; form.current_password=''; form.code=''; }
function parse(value: unknown): Status {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid status');
  const data=value as Partial<Status>;
  if (typeof data.enabled !== 'boolean' || typeof data.configured !== 'boolean' || typeof data.delivery_active !== 'boolean' ||
      typeof data.destination !== 'string' || typeof data.has_bearer !== 'boolean' || typeof data.has_signing_secret !== 'boolean' ||
      !Number.isSafeInteger(data.failures) || !Number.isSafeInteger(data.recoveries) ||
      !Array.isArray(data.alarms) || data.alarms.length > 50 || !Array.isArray(data.deliveries) || data.deliveries.length > 50 ||
      !data.alarms.every(row => row && typeof row.service === 'string' && Number.isSafeInteger(row.since)) ||
      !data.deliveries.every(row => row && typeof row.id === 'string' && typeof row.service === 'string' &&
        typeof row.kind === 'string' && typeof row.status === 'string' && typeof row.last_error === 'string' &&
        Number.isSafeInteger(row.created) && Number.isSafeInteger(row.attempts))) throw new Error('invalid status');
  return data as Status;
}
async function refresh() {
  loading.value=true; failure.value='';
  try {
    const response=await fetch('/api/notifications', { credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(10000) });
    if (response.status===401) { emit('expired'); return; }
    if (!response.ok) throw new Error('unavailable');
    status.value=parse(await response.json());
    if (!editing.value) { form.enabled=status.value.enabled; form.failures=status.value.failures; form.recoveries=status.value.recoveries; }
  } catch { failure.value='暂时无法读取通知配置。'; }
  finally { loading.value=false; }
}
function label(value:string):string {
  return ({reality:'REALITY',websocket:'WebSocket / TLS',hysteria2:'Hysteria 2','hysteria2-brutal':'Hysteria 2 Brutal',vmess:'VMess / TLS',probe:'探测结果采集',core:'Xray 管理接口',backup:'自动备份',test:'通知测试'} as Record<string,string>)[value] ?? value;
}
function state(value:string):string {
  return ({pending:'待投递',delivered:'已投递',failed:'失败',superseded:'已被新状态替代',cancelled:'已取消',fault:'故障',recovery:'恢复',test:'测试'} as Record<string,string>)[value] ?? value;
}
function edit() {
  if (!status.value) return;
  form.enabled=status.value.enabled; form.failures=status.value.failures; form.recoveries=status.value.recoveries;
  form.clear_auth=false; form.clear_url=false; message.value=''; editing.value=true;
}
function cancel() { clearSecrets(); editing.value=false; message.value=''; }
async function save() {
  if (saving.value) return;
  saving.value=true; message.value='';
  try {
    const response=await fetch('/api/notifications',{method:'PUT',credentials:'same-origin',cache:'no-store',
      headers:{'Content-Type':'application/json','X-CSRF-Token':props.csrf},body:JSON.stringify(form),signal:AbortSignal.timeout(15000)});
    if (response.status===401) { emit('expired'); return; }
    if (response.status===403) { message.value='密码、二次验证码或请求校验失败。'; return; }
    if (response.status===429) { message.value='验证尝试过于频繁，请稍后再试。'; return; }
    if (response.status===422) { const data: unknown=await response.json();
      message.value=typeof data==='object' && data!==null && 'detail' in data && typeof data.detail==='string' ? data.detail : '请检查通知设置。'; return; }
    if (!response.ok) throw new Error('unavailable');
    editing.value=false; await refresh();
  } catch { message.value='暂时无法保存通知设置。'; }
  finally { clearSecrets(); saving.value=false; }
}
async function sendTest() {
  if (testing.value || !status.value?.delivery_active) return;
  testing.value=true; testMessage.value='';
  try {
    const response=await fetch('/api/notifications/test',{method:'POST',credentials:'same-origin',cache:'no-store',
      headers:{'X-CSRF-Token':props.csrf},signal:AbortSignal.timeout(10000)});
    if (response.status===401) { emit('expired'); return; }
    if (response.status===429) { testMessage.value='请等待 30 秒后再发送测试。'; return; }
    if (!response.ok) throw new Error('unavailable');
    testMessage.value='测试通知已排队，请刷新投递记录并确认接收端。'; await refresh();
  } catch { testMessage.value='暂时无法发送测试通知。'; }
  finally { testing.value=false; }
}
onMounted(() => { void refresh(); });
onUnmounted(clearSecrets);
</script>
<template>
  <section aria-labelledby="notifications-heading">
    <div class="users-heading"><div><h2 id="notifications-heading">故障通知</h2><p>查看现有通知配置、持续故障及投递记录。</p></div><button type="button" @click="refresh">刷新</button></div>
    <p v-if="loading" class="table-message">正在读取通知配置…</p>
    <p v-else-if="failure" class="message" role="alert">{{ failure }}</p>
    <template v-else-if="status">
      <p v-if="!status.delivery_active" class="notice">通知投递尚未启用。</p>
      <p><strong>{{ status.configured ? (status.delivery_active ? (status.enabled ? '已启用' : '已关闭') : (status.enabled ? '原配置：启用' : '原配置：关闭')) : '尚未配置' }}</strong><span v-if="status.destination"> · {{ status.destination }}</span></p>
      <p class="footnote">认证：{{ status.has_bearer ? '已设置' : '未设置' }} · 签名：{{ status.has_signing_secret ? '已设置' : '未设置' }} · 连续失败 {{ status.failures }} 次 / 恢复 {{ status.recoveries }} 次</p>
      <div v-if="!editing" class="actions"><button type="button" @click="edit">修改通知设置</button>
        <button type="button" :disabled="!status.delivery_active || !status.configured || testing" @click="sendTest">{{ testing ? '正在排队…' : '发送测试通知' }}</button></div>
      <p v-if="testMessage" class="footnote" aria-live="polite">{{ testMessage }}</p>
      <form v-else class="notification-form" @submit.prevent="save">
        <label class="check"><input v-model="form.enabled" type="checkbox"> 启用故障与恢复通知</label>
        <div class="fields"><label>Webhook 地址<input v-model="form.url" type="password" autocomplete="off" maxlength="4096" placeholder="留空保留已保存地址"></label>
          <label>Bearer Token<input v-model="form.bearer" type="password" autocomplete="off" maxlength="2048" placeholder="留空保留已保存凭据"></label>
          <label>签名密钥<input v-model="form.signing_secret" type="password" autocomplete="off" maxlength="256" placeholder="留空保留已保存密钥"></label>
          <label>连续失败次数<input v-model.number="form.failures" type="number" min="1" max="10" required></label>
          <label>连续恢复次数<input v-model.number="form.recoveries" type="number" min="1" max="10" required></label></div>
        <label class="check"><input v-model="form.clear_auth" type="checkbox"> 清除已保存的认证和签名密钥</label>
        <label class="check"><input v-model="form.clear_url" type="checkbox"> 清除地址及凭据，并关闭通知</label>
        <div class="fields"><label>当前管理密码<input v-model="form.current_password" type="password" autocomplete="current-password" maxlength="256" required></label>
          <label>二次验证码或恢复码<input v-model="form.code" autocomplete="one-time-code" maxlength="128"></label></div>
        <p v-if="message" class="message" role="alert">{{ message }}</p>
        <div class="actions"><button type="submit" class="primary" :disabled="saving">{{ saving ? '正在保存…' : '保存设置' }}</button><button type="button" :disabled="saving" @click="cancel">取消</button></div>
      </form>
      <h3>当前故障</h3><p v-if="!status.alarms.length" class="table-message">没有持续故障记录。</p>
      <ul v-else><li v-for="alarm in status.alarms" :key="alarm.service">{{ label(alarm.service) }} · 自 {{ new Date(alarm.since * 1000).toLocaleString() }}</li></ul>
      <h3>最近投递记录</h3><p v-if="!status.deliveries.length" class="table-message">暂无投递记录。</p>
      <div v-else class="table-wrap"><table><thead><tr><th>时间</th><th>服务</th><th>类型</th><th>状态</th><th>尝试次数</th><th>说明</th></tr></thead>
        <tbody><tr v-for="delivery in status.deliveries" :key="delivery.id"><td>{{ new Date(delivery.created * 1000).toLocaleString() }}</td><td>{{ label(delivery.service) }}</td>
          <td>{{ state(delivery.kind) }}</td><td>{{ state(delivery.status) }}</td><td>{{ delivery.attempts }}</td><td>{{ delivery.last_error || '—' }}</td></tr></tbody></table></div>
    </template>
  </section>
</template>
<style scoped>
.notification-form { display: block; margin: 1rem 0; }
.fields { display: grid; grid-template-columns: repeat(auto-fit,minmax(210px,1fr)); gap: .6rem; margin: .6rem 0; }
.check { display: flex; align-items: center; gap: .4rem; margin: .5rem 0; }
.check input { width: 16px; height: 16px; padding: 0; margin: 0; }
.actions { display: flex; gap: .5rem; }
</style>
