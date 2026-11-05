<script setup lang="ts">
import { onMounted, ref } from 'vue';

type AuditEvent = { ts: number; action: string; detail: string };
const emit = defineEmits<{ expired: [] }>();
const events = ref<AuditEvent[]>([]);
const loading = ref(false);
const message = ref('');
const labels: Record<string, string> = {
  login:'管理员登录', login_failed:'登录失败', user_created:'新建用户', user_updated:'更新用户',
  user_deleted:'删除用户', credentials_rotated:'重置凭据', traffic_reset:'清零流量', password_changed:'修改密码',
  core_restart:'更新访问权限', mfa_setup:'准备绑定二次验证', mfa_enabled:'启用二次验证', mfa_disabled:'关闭二次验证',
  recovery_regenerated:'重新生成恢复码', backup_created:'创建加密备份', backup_restored:'恢复备份',
  rule_template_created:'新建规则模板', rule_template_saved:'保存规则草稿', rule_template_published:'发布规则模板',
  rule_template_reset:'恢复模板默认', rule_template_reset_undone:'撤销模板恢复', user_rule_template_changed:'切换用户规则模板',
  node_added:'添加服务器节点', node_updated:'更新服务器节点', proxy_import_requested:'固定代理导入',
  webshare_configured:'动态住宅池配置变更', webshare_requested:'动态住宅池操作', notifications_configured:'通知配置变更',
  notification_test:'发送测试通知', fault_detected:'检测到持续故障', fault_recovered:'故障已恢复',
};
async function refresh() {
  if (loading.value) return;
  loading.value = true; message.value = '';
  try {
    const response = await fetch('/api/events', { cache:'no-store', credentials:'same-origin', signal:AbortSignal.timeout(10000) });
    if (response.status === 401) { emit('expired'); return; }
    if (!response.ok) throw new Error('unavailable');
    const body: unknown = await response.json();
    if (!body || typeof body !== 'object' || !('events' in body) || !Array.isArray(body.events) || body.events.length > 30 ||
        !body.events.every(item => item && typeof item === 'object' && typeof item.ts === 'number' && Number.isSafeInteger(item.ts) && item.ts >= 0 &&
          typeof item.action === 'string' && typeof item.detail === 'string')) throw new Error('invalid');
    events.value = body.events as AuditEvent[];
  } catch { message.value = '无法读取操作记录，请稍后重试。'; }
  finally { loading.value = false; }
}
onMounted(() => { void refresh(); });
</script>

<template>
  <section aria-labelledby="events-heading">
    <div class="section-heading"><div><h2 id="events-heading">操作记录</h2><p>显示最近 30 条管理操作和服务事件。</p></div><button type="button" :disabled="loading" @click="refresh">刷新</button></div>
    <p v-if="message" class="message" role="alert">{{ message }}</p>
    <p v-else-if="loading && !events.length" class="table-message">正在读取记录…</p>
    <p v-else-if="!events.length" class="table-message">暂无操作记录。</p>
    <div v-else class="table-wrap"><table>
      <thead><tr><th>时间</th><th>操作</th><th>详情</th></tr></thead>
      <tbody><tr v-for="(event, index) in events" :key="index">
        <td>{{ event.ts ? new Date(event.ts * 1000).toLocaleString() : '未知' }}</td><td>{{ labels[event.action] || event.action }}</td><td>{{ event.detail || '—' }}</td>
      </tr></tbody>
    </table></div>
  </section>
</template>
