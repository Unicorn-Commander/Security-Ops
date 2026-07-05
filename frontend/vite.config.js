import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Frontend dev server runs on :5173 and proxies /api -> the Security-Ops
// FastAPI backend on :8130 (blueprint: secops-api). In the container build the
// same /api path is fronted by nginx :8131. Keep the path prefix identical so
// the axios/fetch baseURL of '/api/v1' works in dev and prod unchanged.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8130',
        changeOrigin: true,
      },
    },
  },
});
