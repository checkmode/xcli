<script setup lang="ts">
import { nextTick, onMounted, reactive, ref, type Component } from 'vue';
import { Activity, BellRing, Cable, ChartNoAxesCombined, ChevronDown, House, LayoutDashboard, ListFilter,
  LogOut, Menu, ScrollText, Server, ShieldCheck, UsersRound } from '@lucide/vue';
import UsersPanel from './UsersPanel.vue';
import NodesPanel from './NodesPanel.vue';
import RulesPanel from './RulesPanel.vue';
import SecurityPanel from './SecurityPanel.vue';
import MfaPanel from './MfaPanel.vue';
import WebsharePanel from './WebsharePanel.vue';
import MonitorPanel from './MonitorPanel.vue';
import CoreStatusPanel from './CoreStatusPanel.vue';
import BrutalRatePanel from './BrutalRatePanel.vue';
import HostPanel from './HostPanel.vue';
import HistoryPanel from './HistoryPanel.vue';
import NotificationsPanel from './NotificationsPanel.vue';
import ActivityPanel from './ActivityPanel.vue';
import EventsPanel from './EventsPanel.vue';
import ImportPanel from './ImportPanel.vue';
import BackupsPanel from './BackupsPanel.vue';

type Session = { username: string; csrf: string };
const health = ref<'checking' | 'available' | 'unavailable'>('checking');
const stage = ref<'checking' | 'anonymous' | 'signed-in' | 'unavailable'>('checking');
const session = ref<Session | null>(null);
const busy = ref(false);
const message = ref('');
const form = reactive({ username: 'admin', password: '', code: '' });
const rulesPanel = ref<InstanceType<typeof RulesPanel> | null>(null);
const usersPanel = ref<InstanceType<typeof UsersPanel> | null>(null);
const importsPanel = ref<InstanceType<typeof ImportPanel> | null>(null);

type Page = 'overview' | 'users' | 'nodes' | 'imports' | 'webshare' | 'rules' | 'activity' | 'history' | 'events' | 'notifications' | 'security';
type NavigationItem = { id: Page; label: string; description: string; icon: Component };
const navigation: Array<{ title: string; items: NavigationItem[] }> = [
  { title: '管理', items: [
    { id: 'overview', label: '概览', description: '查看服务连接及入口自检。', icon: LayoutDashboard },
    { id: 'users', label: '用户管理', description: '管理用户、配额和客户端连接。', icon: UsersRound },
    { id: 'nodes', label: '独立节点', description: '管理独立节点和用户授权。', icon: Server },
    { id: 'imports', label: '固定代理', description: '检测固定代理与出口。', icon: Cable },
    { id: 'webshare', label: '动态住宅池', description: '管理住宅套餐和地区出口。', icon: House },
    { id: 'rules', label: '规则模板', description: '编辑和发布客户端分流策略。', icon: ListFilter },
  ] },
  { title: '运行与安全', items: [
    { id: 'activity', label: '入口活动', description: '查看用户近期入口流量。', icon: Activity },
    { id: 'history', label: '历史趋势', description: '查看历史流量和入口状态。', icon: ChartNoAxesCombined },
    { id: 'events', label: '操作记录', description: '查看最近的管理操作。', icon: ScrollText },
    { id: 'notifications', label: '故障通知', description: '设置服务故障通知。', icon: BellRing },
    { id: 'security', label: '安全与备份', description: '管理账户安全和数据备份。', icon: ShieldCheck },
  ] },
];
const page = ref<Page>('overview');
const mobileNavigationOpen = ref(false);
const mobileNavigationButton = ref<HTMLButtonElement | null>(null);
const usersVisited = ref(false);
const importsVisited = ref(false);
const rulesVisited = ref(false);
function currentPage(): NavigationItem {
  return navigation.flatMap(group => group.items).find(item => item.id === page.value)!;
}
function closeMobileNavigation() {
  if (!mobileNavigationOpen.value) return;
  mobileNavigationOpen.value = false;
  void nextTick(() => mobileNavigationButton.value?.focus({ preventScroll: true }));
}
function navigate(next: Page) {
  closeMobileNavigation();
  if (page.value === next) return;
  if (page.value === 'users') usersPanel.value?.closeLinks();
  if (page.value === 'imports') importsPanel.value?.leave();
  page.value = next;
  if (next === 'users') {
    if (usersVisited.value) void usersPanel.value?.refresh();
    usersVisited.value = true;
  }
  if (next === 'rules') {
    if (rulesVisited.value) void rulesPanel.value?.refreshUsers();
    rulesVisited.value = true;
  }
  if (next === 'imports') {
    if (importsVisited.value) void importsPanel.value?.refresh();
    importsVisited.value = true;
  }
}
function endSession(reason = '') {
  session.value = null; stage.value = 'anonymous'; page.value = 'overview';
  mobileNavigationOpen.value = false; usersVisited.value = false; importsVisited.value = false; rulesVisited.value = false; message.value = reason;
}

function sessionBody(value: unknown): Session | null {
  if (typeof value !== 'object' || value === null || !('username' in value) || !('csrf' in value)) return null;
  if (typeof value.username !== 'string' || typeof value.csrf !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.csrf)) return null;
  return { username: value.username, csrf: value.csrf };
}
async function checkHealth() {
  health.value = 'checking';
  try {
    const response = await fetch('/healthz', { cache: 'no-store', signal: AbortSignal.timeout(5000) });
    const body: unknown = await response.json();
    health.value = response.ok && typeof body === 'object' && body !== null && 'status' in body && body.status === 'ok'
      ? 'available' : 'unavailable';
  } catch { health.value = 'unavailable'; }
}
async function restoreSession() {
  stage.value = 'checking'; message.value = '';
  try {
    const response = await fetch('/api/session', { cache: 'no-store', credentials: 'same-origin', signal: AbortSignal.timeout(5000) });
    if (response.status === 401) { session.value = null; stage.value = 'anonymous'; return; }
    const value = response.ok ? sessionBody(await response.json()) : null;
    if (!value) throw new Error('invalid session response');
    session.value = value; stage.value = 'signed-in';
  } catch { stage.value = 'unavailable'; }
}
async function login() {
  if (busy.value) return;
  busy.value = true; message.value = '';
  try {
    const response = await fetch('/api/login', { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form), signal: AbortSignal.timeout(15000) });
    if (response.status === 401) { message.value = '账号、密码或二次验证码不正确。'; return; }
    if (response.status === 429) { message.value = '尝试次数过多，请稍后再试。'; return; }
    const value = response.ok ? sessionBody(await response.json()) : null;
    if (!value) throw new Error('invalid login response');
    session.value = value; stage.value = 'signed-in';
  } catch { message.value = '登录暂时不可用，请稍后重试。'; }
  finally { form.password = ''; form.code = ''; busy.value = false; }
}
async function logout() {
  if (busy.value || !session.value) return;
  busy.value = true; message.value = '';
  try {
    const response = await fetch('/api/logout', { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'X-CSRF-Token': session.value.csrf }, signal: AbortSignal.timeout(10000) });
    if (!response.ok && response.status !== 401) throw new Error('logout failed');
    endSession();
  } catch { message.value = '退出暂时不可用，请重试。'; }
  finally { busy.value = false; }
}
onMounted(() => { void checkHealth(); void restoreSession(); });
</script>

<template>
  <div class="shell">
    <a class="skip-link" href="#main-heading">跳到主要内容</a>
    <header class="app-header">
      <div class="brand"><strong>XCLI</strong><span>管理控制台</span><span class="brand-version">测试版</span></div>
      <div v-if="stage === 'signed-in'" class="header-account">
        <span class="header-health" :class="health" title="最近一次管理服务健康检查"><span class="status-dot" aria-hidden="true"></span>{{ health === 'available' ? '最近检查正常' : health === 'checking' ? '正在检查' : '最近检查失败' }}</span>
        <span class="account-name"><span class="account-avatar" aria-hidden="true">{{ session?.username.slice(0, 1).toUpperCase() }}</span>{{ session?.username }}</span>
        <button class="logout-button" type="button" :disabled="busy" @click="logout"><LogOut :size="15" aria-hidden="true" />退出登录</button>
      </div>
    </header>
    <main :class="{ 'signed-in-layout': stage === 'signed-in' }">
      <template v-if="stage !== 'signed-in'">
        <div class="login-layout">
          <div class="login-heading"><p class="eyebrow">XCLI MANAGEMENT</p><h1 id="main-heading" tabindex="-1">管理服务</h1>
            <p class="intro">在一个清晰的工作台中管理用户、节点与订阅。</p>
            <div class="login-features" aria-label="管理功能">
              <span><UsersRound :size="16" aria-hidden="true" />用户与订阅</span>
              <span><Server :size="16" aria-hidden="true" />节点与入口</span>
              <span><ShieldCheck :size="16" aria-hidden="true" />规则与安全</span>
            </div>
          </div>
          <section class="account login-card" aria-labelledby="account-heading">
            <div class="login-card-symbol"><ShieldCheck :size="20" :stroke-width="1.7" aria-hidden="true" /></div>
            <div class="section-heading"><div><h2 id="account-heading">管理员登录</h2><p>使用管理员账号继续。</p></div></div>
            <p v-if="stage === 'checking'" aria-live="polite">正在检查登录状态…</p>
            <div v-else-if="stage === 'unavailable'" class="account-state">
              <p>管理服务暂时不可用。</p><button type="button" @click="restoreSession">重试</button>
            </div>
            <form v-else @submit.prevent="login">
              <label>账号<input v-model="form.username" autocomplete="username" maxlength="64" required></label>
              <label>密码<input v-model="form.password" type="password" autocomplete="current-password" maxlength="256" required></label>
              <label>二次验证码或恢复码<input v-model="form.code" autocomplete="one-time-code" maxlength="128"></label>
              <div><button class="primary login-submit" type="submit" :disabled="busy">{{ busy ? '正在登录…' : '登录管理控制台' }}</button></div>
            </form>
            <p v-if="message" class="message" role="alert">{{ message }}</p>
          </section>
        </div>
      </template>
      <template v-else-if="session">
        <nav class="workspace-navigation" aria-label="管理导航" @keydown.esc.stop="closeMobileNavigation">
          <button ref="mobileNavigationButton" class="mobile-navigation-toggle" type="button"
            :aria-expanded="mobileNavigationOpen" aria-controls="workspace-navigation-items" @click="mobileNavigationOpen = !mobileNavigationOpen">
            <Menu :size="18" aria-hidden="true" /><span>导航</span><span class="mobile-navigation-current">{{ currentPage().label }}</span>
            <ChevronDown :size="16" :class="{ expanded: mobileNavigationOpen }" aria-hidden="true" />
          </button>
          <div id="workspace-navigation-items" class="navigation-items" :class="{ expanded: mobileNavigationOpen }">
            <div v-for="group in navigation" :key="group.title" class="navigation-group">
              <p>{{ group.title }}</p>
              <button v-for="item in group.items" :key="item.id" type="button" :class="{ selected: page === item.id }"
                :aria-current="page === item.id ? 'page' : undefined" @click="navigate(item.id)"><component :is="item.icon" :size="17" :stroke-width="1.8" aria-hidden="true" /><span>{{ item.label }}</span></button>
            </div>
          </div>
        </nav>
        <div class="page-content">
          <div class="page-heading"><p class="eyebrow">{{ page === 'overview' ? 'OVERVIEW' : 'MANAGEMENT' }}</p>
            <h1 id="main-heading" tabindex="-1">{{ currentPage().label }}</h1><p class="intro">{{ currentPage().description }}</p></div>
          <p v-if="message" class="message" role="alert">{{ message }}</p>
          <template v-if="page === 'overview'">
            <HostPanel @expired="endSession()" />
            <CoreStatusPanel @expired="endSession()" />
            <BrutalRatePanel :csrf="session.csrf" @expired="endSession()" />
            <MonitorPanel @expired="endSession()" />
            <section class="health" aria-labelledby="health-heading">
              <div><h2 id="health-heading">后端连接</h2><p>检查管理服务健康接口的响应。</p></div>
              <div class="result"><span class="status-badge" :class="health" aria-live="polite">{{ health === 'checking' ? '正在检查' : health === 'available' ? '接口可用' : '接口不可用' }}</span><button type="button" @click="checkHealth">重新检查</button></div>
            </section>
            <p class="footnote">接口可用不代表节点可用或用户连接正常。</p>
          </template>
          <UsersPanel v-if="usersVisited" v-show="page === 'users'" ref="usersPanel" :csrf="session.csrf" @changed="rulesPanel?.refreshUsers()" @expired="endSession()" />
          <NodesPanel v-if="page === 'nodes'" :csrf="session.csrf" @expired="endSession()" />
          <ImportPanel v-if="importsVisited" v-show="page === 'imports'" ref="importsPanel" :csrf="session.csrf" @expired="endSession()" />
          <WebsharePanel v-if="page === 'webshare'" :csrf="session.csrf" @expired="endSession()" />
          <RulesPanel v-if="rulesVisited" v-show="page === 'rules'" ref="rulesPanel" :csrf="session.csrf" @policy-changed="usersPanel?.refreshLinks()" @expired="endSession()" />
          <ActivityPanel v-if="page === 'activity'" @expired="endSession()" />
          <HistoryPanel v-if="page === 'history'" @expired="endSession()" />
          <EventsPanel v-if="page === 'events'" @expired="endSession()" />
          <NotificationsPanel v-if="page === 'notifications'" :csrf="session.csrf" @expired="endSession()" />
          <template v-if="page === 'security'">
            <SecurityPanel :csrf="session.csrf" @expired="endSession()" @changed="endSession('密码已更新，请重新登录。')" />
            <MfaPanel :csrf="session.csrf" @expired="endSession()" @disabled="endSession('二次验证已关闭，请重新登录。')" />
            <BackupsPanel :csrf="session.csrf" @expired="endSession()" @restored="endSession('备份已恢复，请重新登录。')" />
          </template>
        </div>
      </template>
    </main>
  </div>
</template>
