<script setup lang="ts">
import { probeReason, probeTitle, type ProxyPreviewRow } from './proxy-probe';
const props = defineProps<{ rows: ProxyPreviewRow[]; selected: number[]; available: number; mode: 'live' | 'select' | 'review' | 'remaining' }>();
const emit = defineEmits<{ 'update:selected': [value: number[]] }>();
function toggle(index: number, checked: boolean) {
  if (props.mode !== 'select') return;
  emit('update:selected', checked ? [...props.selected, index] : props.selected.filter(value => value !== index));
}
const labels = { waiting:'等待检测', testing:'检测中', success:'检测成功', failed:'检测失败' };
</script>

<template>
  <ul class="proxy-probe-list" aria-label="代理检测结果">
    <li v-for="(row, position) in rows" :key="row.index ?? position" :class="row.state">
      <label v-if="(mode === 'select' || mode === 'review') && row.state === 'success' && row.index" class="proxy-select">
        <input type="checkbox" :checked="selected.includes(row.index)" :disabled="mode !== 'select' || (!selected.includes(row.index) && selected.length >= available)"
          :aria-label="`选择 ${probeTitle(row)}`" @change="toggle(row.index, ($event.target as HTMLInputElement).checked)">
      </label>
      <span v-else-if="mode === 'select' || mode === 'review'" class="proxy-select" aria-hidden="true"></span>
      <div class="proxy-probe-detail"><strong>{{ probeTitle(row) }}</strong>
        <small v-if="row.state === 'failed'" class="probe-failure">{{ probeReason(row.reason) }}</small>
        <small v-else-if="row.state === 'success'">{{ [row.exit_ip, row.country].filter(Boolean).join(' · ') }}<template v-if="row.https_ms !== undefined"> · HTTPS {{ row.https_ms }} ms</template><template v-if="row.doh_ms !== undefined"> · DNS {{ row.doh_ms }} ms</template></small>
        <small v-if="mode === 'remaining' && row.state === 'success'">本次未选择导入</small>
      </div>
      <span class="proxy-probe-status">{{ row.state ? labels[row.state] : '等待检测' }}</span>
    </li>
  </ul>
</template>
