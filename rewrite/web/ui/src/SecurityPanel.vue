<script setup lang="ts">
import { reactive, ref } from 'vue';

const props = defineProps<{ csrf: string }>();
const emit = defineEmits<{ expired: []; changed: [] }>();
const open = ref(false);
const busy = ref(false);
const message = ref('');
const form = reactive({ current_password: '', new_password: '', confirmation: '', code: '' });

function clear() {
  form.current_password = ''; form.new_password = ''; form.confirmation = ''; form.code = '';
}
async function save() {
  if (busy.value) return;
  if (form.new_password !== form.confirmation) { message.value = '两次输入的新密码不一致。'; return; }
  if ([...form.new_password].length < 16) { message.value = '新密码至少需要 16 个字符。'; return; }
  busy.value = true; message.value = '';
  try {
    const response = await fetch('/api/password', {
      method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(15000),
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': props.csrf },
      body: JSON.stringify({ current_password: form.current_password, new_password: form.new_password, code: form.code }),
    });
    if (response.status === 401) { emit('expired'); return; }
    if (response.status === 403) { message.value = '密码、二次验证码或请求校验不正确。'; return; }
    if (response.status === 429) { message.value = '验证尝试过于频繁，请稍后重试。'; return; }
    if (!response.ok) throw new Error('password change failed');
    emit('changed');
  } catch { message.value = '无法更新密码，请稍后重试。'; }
  finally { clear(); busy.value = false; }
}
</script>

<template>
  <section aria-labelledby="security-heading">
    <div class="users-heading"><div><h2 id="security-heading">账户安全</h2><p>修改管理员密码后，所有已登录的会话都将退出。</p></div>
      <button type="button" @click="open = !open; message = ''; clear()">{{ open ? '取消' : '修改密码' }}</button>
    </div>
    <form v-if="open" class="user-editor" @submit.prevent="save">
      <div class="editor-grid">
        <label>当前密码<input v-model="form.current_password" type="password" autocomplete="current-password" maxlength="256" required></label>
        <label>新密码<input v-model="form.new_password" type="password" autocomplete="new-password" maxlength="256" required><small>至少 16 个字符</small></label>
        <label>再次输入新密码<input v-model="form.confirmation" type="password" autocomplete="new-password" maxlength="256" required></label>
        <label>二次验证码或恢复码<input v-model="form.code" autocomplete="one-time-code" maxlength="128"><small>启用二次验证时需要填写</small></label>
      </div>
      <div class="editor-actions"><button class="primary" type="submit" :disabled="busy">{{ busy ? '正在更新…' : '更新密码' }}</button></div>
      <p v-if="message" class="message" role="alert">{{ message }}</p>
    </form>
  </section>
</template>
