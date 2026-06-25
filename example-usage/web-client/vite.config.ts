import { defineConfig } from 'vite';
import path from 'path';

export default defineConfig({
  resolve: {
    alias: {
      'mtp-wasm': path.resolve(__dirname, '../../wasm/pkg'),
    },
  },
  server: {
    fs: {
      allow: ['.', path.resolve(__dirname, '../../wasm/pkg')],
    },
  },
});
