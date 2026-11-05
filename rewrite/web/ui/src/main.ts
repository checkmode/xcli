import { createApp } from 'vue';
import App from './App.vue';
import ShadowrocketClient from './ShadowrocketClient.vue';
import './style.css';

createApp(window.location.pathname === '/client/shadowrocket' ? ShadowrocketClient : App).mount('#app');
