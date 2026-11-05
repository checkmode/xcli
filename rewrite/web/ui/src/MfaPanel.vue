<script setup lang="ts">
import { onBeforeUnmount, onMounted, reactive, ref } from 'vue';

type Stage = 'idle' | 'setup' | 'enroll' | 'disable' | 'recovery' | 'codes';
type Status = { enabled: boolean; recovery_remaining: number };
type Setup = { secret: string; qr: string; expires: number };
const props = defineProps<{ csrf: string }>();
const emit = defineEmits<{ expired: []; disabled: [] }>();
const status = ref<Status | null>(null);
const stage = ref<Stage>('idle');
const setup = ref<Setup | null>(null);
const codes = ref<string[]>([]);
const busy = ref(false);
const message = ref('');
const input = reactive({ current_password: '', code: '' });

function clearInput() { input.current_password = ''; input.code = ''; }
function cancel() { clearInput(); setup.value = null; codes.value = []; message.value = ''; stage.value = 'idle'; }
async function refresh() {
  try {
    const response = await fetch('/api/security', { credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(10000) });
    if (response.status === 401) { emit('expired'); return; }
    const body: unknown = await response.json();
    if (!response.ok || typeof body !== 'object' || !body || !('enabled' in body) || !('recovery_remaining' in body) ||
        typeof body.enabled !== 'boolean' || typeof body.recovery_remaining !== 'number' || !Number.isSafeInteger(body.recovery_remaining) || body.recovery_remaining < 0) throw new Error('invalid security status');
    status.value = { enabled: body.enabled, recovery_remaining: body.recovery_remaining };
  } catch { status.value = null; message.value = '无法读取二次验证状态。'; }
}
function start(next: Stage) { cancel(); stage.value = next; }
async function submit() {
  if (busy.value || !['setup', 'enroll', 'disable', 'recovery'].includes(stage.value)) return;
  const action = stage.value;
  const path = action === 'enroll' ? 'enable' : action;
  busy.value = true; message.value = '';
  try {
    const response = await fetch('/api/security/' + path, { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': props.csrf }, body: JSON.stringify(input), signal: AbortSignal.timeout(15000) });
    if (response.status === 401) { emit('expired'); return; }
    if (response.status === 403) { message.value = '密码、验证码或请求校验不正确。'; return; }
    if (response.status === 409) { message.value = '安全状态已变化或绑定已过期，请重新开始。'; return; }
    if (response.status === 429) { message.value = '验证尝试过于频繁，请稍后重试。'; return; }
    if (!response.ok) throw new Error('security action failed');
    const body: unknown = await response.json();
    if (action === 'disable') { cancel(); emit('disabled'); return; }
    if (action === 'setup') {
      if (typeof body !== 'object' || !body || !('secret' in body) || !('qr' in body) || !('expires' in body) ||
          typeof body.secret !== 'string' || !/^[A-Z2-7]{32}$/.test(body.secret) || typeof body.qr !== 'string' ||
          body.qr.length > 1000000 || !/^data:image\/png;base64,[A-Za-z0-9+/]+=*$/.test(body.qr) ||
          typeof body.expires !== 'number' || !Number.isSafeInteger(body.expires)) throw new Error('invalid enrollment response');
      setup.value = { secret: body.secret, qr: body.qr, expires: body.expires }; stage.value = 'enroll'; return;
    }
    if (typeof body !== 'object' || !body || !('recovery_codes' in body) || !Array.isArray(body.recovery_codes) ||
        body.recovery_codes.length !== 10 || !body.recovery_codes.every(code => typeof code === 'string' && /^[0-9a-f]{8}(?:-[0-9a-f]{8}){3}$/.test(code))) throw new Error('invalid recovery codes');
    codes.value = body.recovery_codes as string[]; setup.value = null; stage.value = 'codes'; await refresh();
  } catch { message.value = '操作未完成，请检查安全状态后重试。'; }
  finally { clearInput(); busy.value = false; }
}
onMounted(() => { void refresh(); });
onBeforeUnmount(cancel);
</script>

<template>
  <section aria-labelledby="mfa-heading">
    <div class="users-heading"><div><h2 id="mfa-heading">二次验证</h2>
      <p>{{ status ? status.enabled ? `已启用 · 剩余 ${status.recovery_remaining} 个恢复码` : '未启用' : '状态不可用' }}</p></div>
      <div v-if="status && stage === 'idle'" class="heading-actions">
        <button v-if="!status.enabled" type="button" @click="start('setup')">启用二次验证</button>
        <template v-else><button type="button" @click="start('recovery')">重新生成恢复码</button><button type="button" @click="start('disable')">关闭二次验证</button></template>
      </div><button v-else-if="!status" type="button" @click="refresh">重试</button>
    </div>
    <form v-if="stage === 'setup' || stage === 'enroll' || stage === 'disable' || stage === 'recovery'" class="user-editor" @submit.prevent="submit">
      <h3>{{ stage === 'setup' ? '验证身份并生成绑定码' : stage === 'enroll' ? '使用验证器扫码并完成绑定' : stage === 'disable' ? '确认关闭二次验证' : '确认重新生成恢复码' }}</h3>
      <template v-if="stage === 'enroll' && setup">
        <img class="mfa-qr" :src="setup.qr" alt="二次验证绑定二维码">
        <p>也可以在验证器中手动输入密钥：<code>{{ setup.secret }}</code></p>
        <p>绑定码有效期至 {{ new Date(setup.expires * 1000).toLocaleTimeString() }}。</p>
      </template>
      <p v-if="stage === 'disable'">关闭后所有管理员会话将退出，需要重新登录。</p>
      <p v-if="stage === 'recovery'">重新生成后，所有旧恢复码立即失效。</p>
      <div class="editor-grid mfa-inputs">
        <label>当前密码<input v-model="input.current_password" type="password" autocomplete="current-password" maxlength="256" required></label>
        <label v-if="stage !== 'setup'">{{ stage === 'enroll' ? '验证器中的验证码' : '二次验证码或恢复码' }}<input v-model="input.code" autocomplete="one-time-code" maxlength="128" required></label>
      </div>
      <div class="editor-actions"><button type="button" :disabled="busy" @click="cancel">取消</button><button class="primary" type="submit" :disabled="busy">{{ busy ? '正在验证…' : stage === 'setup' ? '生成绑定码' : stage === 'enroll' ? '启用' : stage === 'disable' ? '确认关闭' : '重新生成' }}</button></div>
    </form>
    <div v-if="stage === 'codes'" class="user-editor" role="status">
      <h3>请立即妥善保存恢复码</h3><p>每个恢复码只能使用一次；离开此页面后将无法再次查看。</p>
      <pre class="recovery-codes">{{ codes.join('\n') }}</pre>
      <div class="editor-actions"><button class="primary" type="button" @click="cancel">已保存</button></div>
    </div>
    <p v-if="message" class="message" role="alert">{{ message }}</p>
  </section>
</template>
