import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

export default defineConfig({
  root: 'ui',
  plugins: [vue()],
  build: { outDir: '../dist/ui', emptyOutDir: true },
});
