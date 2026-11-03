import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    // Same-origin in dev: the browser only ever talks to :5173.
    proxy: { '/api': { target: 'http://localhost:3000', changeOrigin: false } },
  },
  worker: { format: 'es' },
  build: {
    target: 'es2022',
    sourcemap: false,
    // No inline <script>/<style> so the strict production CSP holds.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
  },
});
